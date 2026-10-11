import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";
import { createCanonicalCentralMcpReadHandlers, createCanonicalCentralMcpGateway } from "../cloudflare/src/product_central_mcp.ts";
import { env, owner, otherOwner, client, otherClient, device, secondDevice,
  projectId, withIssuer, token, actionRecord } from "./product_mcp_test_fixtures.mts";

const spaceId="99999999-9999-4999-8999-999999999999";
const thirdDevice="ffffffff-ffff-4fff-8fff-ffffffffffff";
const clientWithPunctuation="OAuth.client:central-3";
const people=[
  {owner,client,device,project:projectId,receipt:randomUUID(),private:"PC1-STRICT"},
  {owner,client:otherClient,device:secondDevice,project:randomUUID(),receipt:randomUUID(),private:"PC2-STRICT"},
  {owner:otherOwner,client:clientWithPunctuation,device:thirdDevice,
    project:randomUUID(),receipt:randomUUID(),private:"PC3-STRICT"},
];
function fixture() {
  let mode="normal";
  const seen=[];
  const member=(input:{ownerUserId:string,clientId:string})=>
    people.find(p=>p.owner===input.ownerUserId&&p.client===input.clientId);
  const handlers=createCanonicalCentralMcpReadHandlers(env,{
    listTargets:async (_,input)=>{
      seen.push({type:"list",...input});
      const p=member(input);
      if(!p||mode==="revoke")return {ok:true,targets:[]};
      const target={device_id:p.device,device_name:"Authorized",online:true,
        private_token:p.private,grant_groups:[{
          space_id:spaceId,project_id:p.project,valid_until:mode==="expire"?"2020-01-01T00:00:00Z":null,
          capabilities:[{capability:"project.text_read",access_mode:"read"}],
        }]};
      if(mode==="multiple-devices")return {ok:true,targets:[target,{
        device_id:p.device===device?secondDevice:device,grant_groups:[],
      }]};
      if(mode==="multiple-projects")target.grant_groups.push({
        space_id:spaceId,project_id:randomUUID(),valid_until:null,
        capabilities:[{capability:"project.text_read",access_mode:"read"}],
      });
      return {ok:true,targets:[target]};
    },
    getAction:async (_,input)=>{
      seen.push({type:"status",...input});
      const p=member(input);
      const row=people.find(item=>item.receipt===input.requestId);
      if(!p||!row||p!==row)return null;
      return actionRecord({
        request_id:p.receipt,device_id:mode==="wrong-result-device"?secondDevice:p.device,
        project_id:p.project,capability:"project.text_read",
        result:{secret:p.private},status:"succeeded",
        finished_at:"2026-10-11T16:00:00Z",
      });
    },
  });
  async function call(jwt:string,name:string,args:Record<string,unknown>={},headers:Record<string,string>={}){
    const res=await handleOrdaxMcp(new Request("https://canary.example/mcp",{
      method:"POST",
      headers:{"content-type":"application/json",authorization:"Bearer "+jwt,...headers},
      body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/call",
        params:{name,arguments:args}}),
    }),handlers);
    const body=await res.json();
    return {status:res.status,body,output:body?.result?.structuredContent??null};
  }
  return {call,seen,setMode:(x:string)=>{mode=x}};
}
test("three signed OAuth clients each discover only one PC and their own receipt",async()=>{
  await withIssuer(async()=>{
    const f=fixture();
    for(const p of people){
      const jwt=await token({sub:p.owner,client_id:p.client});
      const target=await f.call(jwt,"ordax_targets",{},{"x-ordax-client-id":otherClient,
        "x-ordax-device-id":secondDevice,"x-ordax-owner-user-id":otherOwner});
      assert.equal(target.output.ok,true,JSON.stringify(target));
      assert.equal(target.output.targets.length,1);
      assert.equal(target.output.targets[0].device_id,p.device);
      assert.ok(!JSON.stringify(target).includes(p.private));
      for(const other of people.filter(other=>other!==p)){
        assert.ok(!JSON.stringify(target).includes(other.device));
        assert.ok(!JSON.stringify(target).includes(other.private));
      }
      const own=await f.call(jwt,"ordax_action_status",{request_id:p.receipt});
      assert.equal(own.output.ok,true,JSON.stringify(own));
      assert.equal(own.output.action.device_id,p.device);
      assert.equal(own.output.action.project_id,p.project);
      assert.equal(own.output.action.result.secret,p.private);
      const cross=people.find(other=>other!==p);
      const denied=await f.call(jwt,"ordax_action_status",{request_id:cross!.receipt});
      assert.ok(denied.output?.ok===false||denied.status===403);
      assert.ok(!JSON.stringify(denied).includes(cross!.private));
    }
    assert.ok(f.seen.filter(x=>x.type==="list").every(x=>
      people.some(p=>p.owner===x.ownerUserId&&p.client===x.clientId)));
  });
});
test("one signed client with multiple authorized PCs or projects fails closed",async()=>{
  await withIssuer(async()=>{
    const f=fixture(),jwt=await token();
    for(const mode of ["multiple-devices","multiple-projects","expire","revoke"]){
      f.setMode(mode);
      const target=await f.call(jwt,"ordax_targets",{device_id:device});
      assert.ok(target.output?.ok===false||target.status===403,JSON.stringify({mode,target}));
      const status=await f.call(jwt,"ordax_action_status",{request_id:people[0].receipt});
      assert.ok(status.output?.ok===false||status.status===403,JSON.stringify({mode,status}));
    }
  });
});
test("model cannot select a PC by request fields, guessed grant or invented tool",async()=>{
  await withIssuer(async()=>{
    const f=fixture(),jwt=await token();
    const unauthorized=await f.call(jwt,"workspace_text_read",{
      device_id:secondDevice,space_id:spaceId,project:"canonical",
      path:"canonical/example.txt",
    });
    assert.equal(unauthorized.output.ok,false);
    assert.equal(unauthorized.output.error,"relay_scope_denied");
    const action=await f.call(jwt,"terminal_exec",{device_id:device,command:"echo hi"});
    assert.equal(action.output.ok,false);
    assert.equal(action.output.error,"relay_scope_denied");
    const spoof=await f.call(jwt,"ordax_targets",{device_id:secondDevice},{
      "x-ordax-device-id":secondDevice,"x-ordax-client-id":otherClient,
    });
    assert.equal(spoof.output.targets[0].device_id,device);
  });
});
test("wrong canonical device in status response is suppressed, even for same client",async()=>{
  await withIssuer(async()=>{
    const f=fixture(),jwt=await token();
    f.setMode("wrong-result-device");
    const result=await f.call(jwt,"ordax_action_status",{request_id:people[0].receipt});
    assert.ok(result.output?.ok===false||result.status===403);
    assert.ok(!JSON.stringify(result).includes(people[0].private));
  });
});
test("unsigned, wrong audience and missing exact client are rejected before target RPC",async()=>{
  await withIssuer(async()=>{
    const f=fixture();
    for(const jwt of ["bad.token.value",await token({client_id:undefined}),await token({aud:"wrong"})]){
      const res=await f.call(jwt,"ordax_targets");
      assert.ok(res.status===401||res.status===403,JSON.stringify(res));
    }
    assert.equal(f.seen.length,0);
  });
});

test("Central MCP gateway reuses exactly four Product read-only tools and rejects remote actions",async()=>{
  await withIssuer(async()=>{
    const f=fixture();
    // Gateway constructor reuses protocol, issuer metadata, and Product read-only
    // tool allowlist, not another MCP router.
    const gateway=createCanonicalCentralMcpGateway(env,{
      listTargets:async (_env,input)=>({
        ok:true,targets:[{device_id:device,device_name:"PC1",online:true,
          grant_groups:[{space_id:spaceId,project_id:projectId,
            capabilities:[{capability:"project.text_read",access_mode:"read"}]}],
        }],
      }),
      getAction:async()=>null,
    });
    const jwt=await token();
    const make=(name:string,args:Record<string,unknown>={})=>new Request("https://central.example/mcp",{
      method:"POST",headers:{authorization:"Bearer "+jwt,"content-type":"application/json"},
      body:JSON.stringify({jsonrpc:"2.0",id:1,method:name,params:name==="tools/call"
        ?{name:"terminal_exec",arguments:args}:undefined}),
    });
    const list=await gateway(make("tools/list"));
    assert.equal(list.status,200);
    const payload=await list.json();
    assert.deepEqual(payload.result.tools.map((x:{name:string})=>x.name),[
      "ordax_session","ordax_profile","ordax_targets","ordax_action_status"
    ]);
    const unsupported=await gateway(make("tools/call",{device_id:device,command:"whoami"}));
    const nope=await unsupported.json();
    assert.equal(nope.error.code,-32601);
    assert.equal(f.seen.length,0);
  });
});
