import test from "node:test";
import assert from "node:assert/strict";
import { createCanonicalRelayActionSubmitHandler } from "../cloudflare/src/product_relay_submit.ts";
import {
  env, owner, otherOwner, client, otherClient, device, secondDevice, projectId,
  effectId, requestId, token, withIssuer,
} from "./product_mcp_test_fixtures.mts";

const spaceId="99999999-9999-4999-8999-999999999999";
const key="relay-client-00000001";
const base={device_id:device,space_id:spaceId,project_id:projectId,
  action:"workspace.directory_list",arguments:{path:"pasta 1",max_depth:2},
  idempotency_key:key};
const validGrant=(scope={deviceId:device,space:spaceId,project:projectId,expires:null as string|null})=>
  ({ok:true,targets:[{
    device_id:scope.deviceId,
    grant_groups:[{grant_group_id:"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      space_id:scope.space,project_id:scope.project,
      valid_until:scope.expires,capabilities:[
        {capability:"workspace.directory_list",access_mode:"read"},
        {capability:"project.text_read",access_mode:"read"},
      ]}],
  }]});
const req=(jwt:string,payload:Record<string,unknown>)=>new Request("https://ordax.example/v3/product/actions",{
  method:"POST",
  headers:{"content-type":"application/json",authorization:"Bearer "+jwt,
    "x-ordax-owner-user-id":otherOwner,"x-ordax-client-id":otherClient},
  body:JSON.stringify(payload),
});
async function result(handler:ReturnType<typeof createCanonicalRelayActionSubmitHandler>,
  jwt:string,payload:Record<string,unknown>){
  const response=await handler(req(jwt,payload));
  return {status:response.status,body:await response.json(),cache:response.headers.get("cache-control")};
}
test("signed owner and exact client enqueue on ONLY the authorized PC and project",async()=>{
  await withIssuer(async()=>{
    const calls:unknown[]=[];let discovery:unknown;
    const handler=createCanonicalRelayActionSubmitHandler(env,{
      now:()=>Date.parse("2026-10-10T19:00:00Z"),
      listTargets:async (server,input)=>{assert.equal(server,env);discovery=input;return validGrant();},
      enqueue:async (server,input)=>{assert.equal(server,env);calls.push(input);
        return {ok:true,replayed:false,request_id:requestId,effect_id:effectId,status:"queued"};},
    });
    const got=await result(handler,await token(),base);
    assert.equal(got.status,202);
    assert.equal(got.cache,"no-store");
    assert.deepEqual(got.body,{ok:true,request_id:requestId,effect_id:effectId,
      status:"queued",replayed:false,device_id:device,project_id:projectId});
    assert.deepEqual(discovery,{ownerUserId:owner,clientKind:"product-mcp",clientId:client});
    assert.deepEqual(calls,[{
      ownerUserId:owner,clientKind:"product-mcp",clientId:client,
      deviceId:device,spaceId,projectId,
      capability:"workspace.directory_list",accessMode:"read",
      payload:{path:"pasta 1",max_depth:2},
      idempotencyKey:key,expiresAt:"2026-10-10T19:05:00.000Z",
    }]);
  });
});

test("3 clients are independent; never trust forged headers or model-selected target",async()=>{
  await withIssuer(async()=>{
    const identities=[
      {owner,client,device,project:projectId,space:spaceId},
      {owner,client:otherClient,device:secondDevice,
        project:"55555555-5555-4555-8555-555555555555",space:spaceId},
      {owner:otherOwner,client,device:"66666666-6666-4666-8666-666666666666",
        project:"77777777-7777-4777-8777-777777777777",space:spaceId},
    ];
    const trace:unknown[]=[];
    const handler=createCanonicalRelayActionSubmitHandler(env,{
      listTargets:async(_,input)=>{
        const p=identities.find(p=>p.owner===input.ownerUserId&&p.client===input.clientId);
        return p?validGrant({deviceId:p.device,space:p.space,project:p.project,expires:null}):{ok:true,targets:[]};
      },
      enqueue:async(_,input)=>{trace.push(input);
        return {ok:true,request_id:requestId,effect_id:effectId,status:"queued",replayed:false};},
    });
    for(const p of identities){
      const signed=await token({sub:p.owner,client_id:p.client});
      const mine={...base,device_id:p.device,project_id:p.project,space_id:p.space,
        idempotency_key:"request-"+p.client.slice(0,8)};
      assert.equal((await result(handler,signed,mine)).status,202);
      const other=identities.find(q=>q.device!==p.device);
      const wrong=await result(handler,signed,{...mine,device_id:other!.device});
      assert.equal(wrong.status,403);
      assert.equal(wrong.body.error,"relay_action_denied");
      assert.equal((await result(handler,signed,{...mine,project_id:other!.project})).status,403);
    }
    assert.equal(trace.length,3);
    for(let i=0;i<identities.length;i++){
      const received=trace[i] as Record<string,unknown>;
      assert.equal(received.deviceId,identities[i].device);
      assert.equal(received.clientId,identities[i].client);
      assert.equal(received.ownerUserId,identities[i].owner);
    }
  });
});

test("ambiguous, expired or revoked grants and unknown capability are denied BEFORE enqueue",async()=>{
  await withIssuer(async()=>{
    let count=0;
    let mode="normal";
    const handler=createCanonicalRelayActionSubmitHandler(env,{
      listTargets:async()=>{
        const snapshot=validGrant();
        if(mode==="revoked")return {ok:true,targets:[]};
        if(mode==="secondTarget")snapshot.targets.push({device_id:secondDevice,grant_groups:[]});
        if(mode==="expired")snapshot.targets[0].grant_groups[0].valid_until="2020-01-01T00:00:00Z";
        if(mode==="secondProject")snapshot.targets[0].grant_groups.push({
          grant_group_id:"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
          space_id:spaceId,project_id:otherOwner,valid_until:null,
          capabilities:[{capability:"workspace.directory_list",access_mode:"read"}]});
        return snapshot;
      },
      enqueue:async()=>{count++;return {ok:true,request_id:requestId,effect_id:effectId,
        replayed:false,status:"queued"};},
    });
    const jwt=await token();
    for(const denial of ["revoked","secondTarget","expired","secondProject"]){
      mode=denial;
      const r=await result(handler,jwt,base);
      assert.equal(r.status,403,denial);
      assert.equal(r.body.error,"relay_action_denied");
    }
    mode="normal";
    assert.equal((await result(handler,jwt,{...base,action:"terminal.exec"})).status,400);
    assert.equal((await result(handler,jwt,{...base,action:"workspace.text_write"})).status,400);
    assert.equal(count,0);
  });
});

test("malformed prompt arguments, path traversal and extra target fields fail before lookup",async()=>{
  await withIssuer(async()=>{
    let lookups=0,enqueues=0;
    const handler=createCanonicalRelayActionSubmitHandler(env,{
      listTargets:async()=>{lookups++;return validGrant();},
      enqueue:async()=>{enqueues++;throw Error("must not enqueue");},
    });
    const jwt=await token();
    const changes=[
      {path:"pasta 1/../secreto"},{path:"C:/private"},
      {path:"pasta 1/%2e%2e"},{path:"pasta 1/COM1.txt"},
      {path:"pasta 1/secret:stream"},{path:"pasta 1\\segredo"},
      {path:"pasta 1//secret"},{path:"pasta 1/arquivo."},
    ];
    for(const argumentsValue of changes){
      const r=await result(handler,jwt,{...base,arguments:argumentsValue});
      assert.equal(r.status,400,JSON.stringify(argumentsValue));
    }
    for(const body of [
      {...base,extra:"pretend-client"},
      {...base,arguments:{path:"pasta 1",max_depth:55}},
      {...base,arguments:{path:"pasta 1",include_hidden:"true"}},
      {...base,idempotency_key:"x"},
      {...base,idempotency_key:"a".repeat(129)},
      {...base,idempotency_key:"valid-key\nInjected"},
      {...base,device_id:"wrong-target"},
      {...base,project_id:"../private"},
      {...base,arguments:{path:"pasta 1",request_id:"forged"}},
      {...base,action:"workspace.text_read",arguments:{path:"pasta 1",start_line:30,end_line:2}},
    ]){
      const r=await result(handler,jwt,body);
      assert.equal(r.status,400,JSON.stringify(body));
    }
    assert.equal(lookups,0);assert.equal(enqueues,0);
  });
});

test("durable idempotency replays same submission, conflicts on changed payload and keeps key",async()=>{
  await withIssuer(async()=>{
    const records=new Map<string,{input:unknown;request:string}>();
    let created=0;
    const handler=createCanonicalRelayActionSubmitHandler(env,{
      listTargets:async()=>validGrant(),
      enqueue:async(_,input)=>{
        const unique=input.ownerUserId+":"+input.idempotencyKey;
        const found=records.get(unique);
        if(found){
          if(JSON.stringify(found.input)!==JSON.stringify({
            deviceId:input.deviceId,projectId:input.projectId,
            payload:input.payload,clientId:input.clientId})){
            return {ok:false,error:"idempotency_conflict"};
          }
          return {ok:true,replayed:true,request_id:found.request,effect_id:effectId,status:"queued"};
        }
        created++;
        records.set(unique,{request:requestId,input:{
          deviceId:input.deviceId,projectId:input.projectId,
          payload:input.payload,clientId:input.clientId,
        }});
        return {ok:true,replayed:false,request_id:requestId,effect_id:effectId,status:"queued"};
      },
    });
    const jwt=await token();
    const first=await result(handler,jwt,base);
    const again=await result(handler,jwt,base);
    const conflict=await result(handler,jwt,{...base,arguments:{path:"outra pasta"}});
    assert.equal(first.status,202);
    assert.equal(again.status,200);assert.equal(again.body.replayed,true);
    assert.equal(again.body.request_id,first.body.request_id);
    assert.equal(conflict.status,409);assert.equal(conflict.body.error,"idempotency_conflict");
    assert.equal(created,1);
  });
});

test("invalid OAuth, PostgreSQL failure and malformed receipt fail closed without a retry",async()=>{
  await withIssuer(async()=>{
    let calls=0;
    const handler=createCanonicalRelayActionSubmitHandler(env,{
      listTargets:async()=>validGrant(),
      enqueue:async()=>{calls++;throw Error("sensitive-database-connection");},
    });
    const jwt=await token();
    const unauthorized=await result(handler,await token({sub:owner,client_id:undefined}),base);
    assert.equal(unauthorized.status,403);
    assert.equal(calls,0);
    const failure=await result(handler,jwt,base);
    assert.equal(failure.status,503);
    assert.ok(!JSON.stringify(failure).includes("sensitive"));
    assert.equal(calls,1);
    const broken=createCanonicalRelayActionSubmitHandler(env,{
      listTargets:async()=>validGrant(),
      enqueue:async()=>({ok:true,request_id:"not-uuid",effect_id:effectId,
        replayed:false,status:"queued"}),
    });
    assert.equal((await result(broken,jwt,base)).status,503);
  });
});
