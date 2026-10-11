import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";
import { createCanonicalRelayReadOnlyHandlers } from "../labs/relay/canonical-readonly.ts";
import {
  env, owner, otherOwner, client, otherClient, device, secondDevice,
  projectId, requestId, withIssuer, token, actionRecord,
} from "./product_mcp_test_fixtures.mts";

const spaceId="99999999-9999-4999-8999-999999999999";
const people=[
  {owner,client,device,project:projectId,requestId,privateResult:"PC-A-PRIVATE"},
  {owner,client:otherClient,device:secondDevice,project:randomUUID(),requestId:randomUUID(),privateResult:"PC-B-PRIVATE"},
  {owner:otherOwner,client,device:randomUUID(),project:randomUUID(),requestId:randomUUID(),privateResult:"PC-C-PRIVATE"},
];
function readGrant(person:typeof people[number]){
  return {device_id:person.device,device_name:"Privado-"+person.privateResult,online:true,
    grant_groups:[{space_id:spaceId,project_id:person.project,
      capabilities:[{capability:"workspace.text_read",access_mode:"read"}]}]};
}
function fixtures(){
  const trace:{type:string;identity:unknown}[]=[];
  let extraTarget=false,extraGrant=false,maliciousAction=false,revokedClient=null,sameDevice=false;
  const byClient=(input:{ownerUserId:string;clientId:string})=>
    people.find(p=>p.owner===input.ownerUserId&&p.client===input.clientId);
  const handlers=createCanonicalRelayReadOnlyHandlers(env,{
    listTargets:async (_env,input)=>{
      trace.push({type:"targets",identity:input});
      const person=byClient(input);
      if(!person || input.clientId===revokedClient)return {ok:true,targets:[]};
      const target=readGrant(person);
      if(sameDevice && person===people[1])target.device_id=people[0].device;
      if(extraGrant) target.grant_groups.push({space_id:spaceId,project_id:randomUUID(),
        capabilities:[{capability:"workspace.text_read",access_mode:"read"}]});
      return {ok:true,targets:extraTarget?[target,readGrant(people[1])]:[target]};
    },
    getAction:async (_env,input)=>{
      trace.push({type:"receipt",identity:input});
      const person=byClient(input);
      const original=people.find(p=>p.requestId===input.requestId);
      if(!person||person!==original)return null;
      const target=maliciousAction?people[1]:person;
      const boundDevice=sameDevice && person===people[1]?people[0].device:target.device;
      return actionRecord({
        request_id:person.requestId,device_id:boundDevice,project_id:target.project,
        capability:"workspace.text_read",status:"succeeded",
        result:{ok:true,data:{content:person.privateResult}},finished_at:"2026-10-09T12:02:00Z",
      });
    },
  });
  return {handlers,trace,extraTarget:()=>{extraTarget=true},extraGrant:()=>{extraGrant=true},
    corrupt:()=>{maliciousAction=true},revoke:clientId=>{revokedClient=clientId},
    shareDevice:()=>{sameDevice=true}};
}
async function tool(handlers:ReturnType<typeof createCanonicalRelayReadOnlyHandlers>,
  jwt:string,name:string,args:Record<string,unknown>){
  const response=await handleOrdaxMcp(new Request("https://relay.example/mcp",{
    method:"POST",headers:{authorization:"Bearer "+jwt,"content-type":"application/json"},
    body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/call",params:{name,arguments:args}}),
  }),handlers);
  return {status:response.status,body:await response.json()};
}
test("3 signed Product OAuth clients can read only their device's accepted MCP receipt",async()=>{
  await withIssuer(async()=>{
    const lab=fixtures();
    const results=await Promise.all(people.map(async p=>{
      const jwt=await token({sub:p.owner,client_id:p.client});
      const target=await tool(lab.handlers,jwt,"ordax_targets",{});
      assert.equal(target.status,200);
      const listed=target.body.result.structuredContent.targets;
      assert.equal(listed.length,1);
      assert.equal(listed[0].device_id,p.device);
      for(const other of people.filter(x=>x!==p)){
        assert.ok(!JSON.stringify(listed).includes(other.device));
        assert.ok(!JSON.stringify(listed).includes(other.privateResult));
      }
      return tool(lab.handlers,jwt,"ordax_action_status",{request_id:p.requestId});
    }));
    for(let i=0;i<people.length;i++){
      const data=results[i].body.result.structuredContent;
      assert.equal(data.ok,true,JSON.stringify(data));
      assert.equal(data.action.device_id,people[i].device);
      assert.equal(data.action.project_id,people[i].project);
      assert.equal(data.action.result.data.content,people[i].privateResult);
      assert.ok(!JSON.stringify(data).includes(people[(i+1)%3].privateResult));
    }
    assert.equal(lab.trace.filter(x=>x.type==="receipt").length,6);
  });
});

test("cross-client read and model-selected write target both fail before any executor",async()=>{
  await withIssuer(async()=>{
    const lab=fixtures();
    const jwt=await token({sub:people[0].owner,client_id:people[0].client});
    const cross=await tool(lab.handlers,jwt,"ordax_action_status",{request_id:people[1].requestId});
    assert.equal(cross.body.result.structuredContent.ok,false);
    assert.ok(!JSON.stringify(cross.body).includes(people[1].privateResult));
    const unauthorized=await tool(lab.handlers,jwt,"workspace_text_read",{
      device_id:people[1].device,project:"other-project",path:"pasta 1/descricao.txt",
      wait_for_completion_ms:0,
    });
    assert.equal(unauthorized.body.result.structuredContent.ok,false);
    const ownButWrite=await tool(lab.handlers,jwt,"workspace_text_read",{
      device_id:people[0].device,project:"canonical",path:"pasta 1/descricao.txt",
      wait_for_completion_ms:0,
    });
    assert.equal(ownButWrite.body.result.structuredContent.ok,false);
    assert.equal(lab.trace.filter(x=>x.type==="receipt").length,1);
  });
});

test("ambiguous target/project grants and wrong canonical record fail closed",async()=>{
  await withIssuer(async()=>{
    const jwt=await token();
    for(const mode of ["twoTargets","twoProjects","corruptedReceipt"]){
      const lab=fixtures();
      if(mode==="twoTargets")lab.extraTarget();
      if(mode==="twoProjects")lab.extraGrant();
      if(mode==="corruptedReceipt")lab.corrupt();
      const result=await tool(lab.handlers,jwt,"ordax_action_status",{request_id:requestId});
      const data=result.body?.result?.structuredContent;
      assert.ok(result.status === 403
        ? result.body?.error === "relay_scope_denied"
        : data?.ok === false,JSON.stringify({mode,result}));
      assert.ok(!JSON.stringify(result).includes(people[1].privateResult));
    }
  });
});

test("invalid and missing OAuth token cannot read or discover another client",async()=>{
  await withIssuer(async()=>{
    const lab=fixtures();
    const invalid=await tool(lab.handlers,"expired.invalid.token","ordax_targets",{});
    assert.equal(invalid.status,403);
    assert.equal(lab.trace.length,0);
  });
});

test("revogação de grant bloqueia novo status sem reutilizar a sessão anterior",async()=>{
  await withIssuer(async()=>{
    const lab=fixtures();
    const jwt=await token({sub:people[0].owner,client_id:people[0].client});
    const before=await tool(lab.handlers,jwt,"ordax_action_status",{request_id:people[0].requestId});
    assert.equal(before.body.result.structuredContent.ok,true);
    lab.revoke(people[0].client);
    const denied=await tool(lab.handlers,jwt,"ordax_action_status",{request_id:people[0].requestId});
    assert.equal(denied.status,403);
    assert.equal(denied.body.error,"relay_scope_denied");
    assert.ok(!JSON.stringify(denied).includes(people[0].privateResult));
  });
});

test("clientes OAuth distintos no mesmo computador não leem reciprocamente seus recibos",async()=>{
  await withIssuer(async()=>{
    const lab=fixtures();
    lab.shareDevice();
    for(const p of [people[0],people[1]]){
      const jwt=await token({sub:p.owner,client_id:p.client});
      const own=await tool(lab.handlers,jwt,"ordax_action_status",{request_id:p.requestId});
      assert.equal(own.body.result.structuredContent.ok,true);
      assert.equal(own.body.result.structuredContent.action.device_id,people[0].device);
      assert.equal(own.body.result.structuredContent.action.result.data.content,p.privateResult);
      const another=people.find(x=>x!==p && x.owner===p.owner);
      const cross=await tool(lab.handlers,jwt,"ordax_action_status",{request_id:another.requestId});
      assert.equal(cross.body.result.structuredContent.ok,false);
      assert.ok(!JSON.stringify(cross).includes(another.privateResult));
    }
  });
});
