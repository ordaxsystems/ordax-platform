import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createCanonicalRelayActionSubmitHandler } from "../cloudflare/src/product_relay_submit.ts";
import { createCanonicalRelayReadOnlyHandlers } from "../labs/relay/canonical-readonly.ts";
import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";
import {
  env, owner, otherOwner, client, otherClient, device, secondDevice,
  projectId, token, withIssuer,
} from "./product_mcp_test_fixtures.mts";

const spaceId="99999999-9999-4999-8999-999999999999";
const members=[
  {owner,client,device,project:projectId,marker:"PRIVATE-PC-1"},
  {owner,client:otherClient,device:secondDevice,project:randomUUID(),marker:"PRIVATE-PC-2"},
  {owner:otherOwner,client,device:randomUUID(),project:randomUUID(),marker:"PRIVATE-PC-3"},
];
function fixture(){
  const records=new Map<string,Record<string,unknown>>();
  const idempotency=new Map<string,string>();
  let creates=0, revokedClient="";
  const who=(input:{ownerUserId:string;clientId:string})=>
    members.find(p=>p.owner===input.ownerUserId&&p.client===input.clientId);
  const listTargets=async (_env:unknown,input:{ownerUserId:string;clientId:string})=>{
    const p=who(input);
    if(!p||input.clientId===revokedClient)return {ok:true,targets:[]};
    return {ok:true,targets:[{device_id:p.device,online:true,grant_groups:[{
      grant_group_id:randomUUID(),space_id:spaceId,project_id:p.project,
      valid_until:null,capabilities:[{capability:"project.text_read",access_mode:"read"}]
    }]}]};
  };
  const enqueue=async (_env:unknown,input:{
    ownerUserId:string;clientId:string;deviceId:string;spaceId:string;
    projectId:string|null;capability:string;payload:Record<string,unknown>;
    idempotencyKey:string;
  })=>{
    const p=who(input);
    if(!p || p.device!==input.deviceId || p.project!==input.projectId ||
      input.spaceId!==spaceId || input.capability!=="project.text_read")return {ok:false,error:"product_grant_not_resolved"};
    const key=input.ownerUserId+":"+input.idempotencyKey;
    const existing=idempotency.get(key);
    if(existing){
      const row=records.get(existing)!;
      if(row.client_id!==input.clientId || row.device_id!==input.deviceId
        || row.project_id!==input.projectId
        || JSON.stringify(row.payload)!==JSON.stringify(input.payload))return {ok:false,error:"idempotency_conflict"};
      return {ok:true,replayed:true,request_id:existing,effect_id:row.effect_id,status:"succeeded"};
    }
    const requestId=randomUUID();
    const effectId=randomUUID();
    idempotency.set(key,requestId);creates++;
    records.set(requestId,{
      ok:true,request_id:requestId,effect_id:effectId,device_id:p.device,
      project_id:p.project,owner_user_id:p.owner,client_id:p.client,
      capability:input.capability,payload:input.payload,
      status:"succeeded",created_at:"2026-10-10T19:00:00Z",
      started_at:"2026-10-10T19:00:01Z",finished_at:"2026-10-10T19:00:02Z",
      result:{data:{content:p.marker}},error_code:null,
    });
    return {ok:true,replayed:false,request_id:requestId,effect_id:effectId,status:"queued"};
  };
  const getAction=async (_env:unknown,input:{ownerUserId:string;clientId:string;requestId:string})=>{
    const value=records.get(input.requestId);
    return value?.owner_user_id===input.ownerUserId && value.client_id===input.clientId
      ?value:null;
  };
  const submit=createCanonicalRelayActionSubmitHandler(env,{
    listTargets:listTargets as never,enqueue:enqueue as never,
  });
  const status=createCanonicalRelayReadOnlyHandlers(env,{
    listTargets:listTargets as never,getAction:getAction as never,
  });
  async function doSubmit(p:typeof members[number],jwt:string,changes:Record<string,unknown>={}){
    const req=new Request("https://relay.example/v3/product/actions",{
      method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+jwt},
      body:JSON.stringify({
        device_id:p.device,space_id:spaceId,project_id:p.project,
        action:"project.text_read",arguments:{path:"pasta 1/descricao.txt"},
        idempotency_key:"relay-"+p.owner.slice(0,8)+"-"+p.client.slice(0,8),
        ...changes,
      }),
    });
    const response=await submit(req);
    return {status:response.status,body:await response.json()};
  }
  async function doStatus(jwt:string,requestId:string){
    const res=await handleOrdaxMcp(new Request("https://relay.example/mcp",{
      method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+jwt},
      body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/call",
        params:{name:"ordax_action_status",arguments:{request_id:requestId}}}),
    }),status);
    return {status:res.status,body:await res.json()};
  }
  return {doSubmit,doStatus,records,get creates(){return creates},revoke:p=>{revokedClient=p.client}};
}

test("3 signed users submit through Product RPC and read only their MCP receipt",async()=>{
  await withIssuer(async()=>{
    const lab=fixture();
    const tokens=await Promise.all(members.map(m=>token({sub:m.owner,client_id:m.client})));
    const submitted=await Promise.all(members.map((m,i)=>lab.doSubmit(m,tokens[i])));
    assert.equal(lab.creates,3);
    for(let i=0;i<members.length;i++){
      const m=members[i],reply=submitted[i];
      assert.equal(reply.status,202);
      assert.equal(reply.body.device_id,m.device);
      assert.equal(reply.body.project_id,m.project);
      const own=await lab.doStatus(tokens[i],reply.body.request_id);
      assert.equal(own.status,200);
      assert.equal(own.body.result.structuredContent.action.device_id,m.device);
      assert.equal(own.body.result.structuredContent.action.project_id,m.project);
      assert.equal(own.body.result.structuredContent.action.result.data.content,m.marker);
      for(let j=0;j<members.length;j++)if(j!==i){
        const cross=await lab.doStatus(tokens[i],submitted[j].body.request_id);
        assert.ok(cross.body.result?.structuredContent?.ok===false || cross.status===403);
        assert.ok(!JSON.stringify(cross).includes(members[j].marker));
      }
    }
  });
});

test("model-selected wrong PC never enters queue and cannot request an existing result",async()=>{
  await withIssuer(async()=>{
    const lab=fixture(),m=members[0],tokenA=await token({sub:m.owner,client_id:m.client});
    const attempted=await lab.doSubmit(m,tokenA,{device_id:members[1].device});
    assert.equal(attempted.status,403);
    assert.equal(lab.creates,0);
    const accepted=await lab.doSubmit(m,tokenA);
    assert.equal(accepted.status,202);
    lab.revoke(m);
    assert.equal((await lab.doStatus(tokenA,accepted.body.request_id)).status,403);
    assert.equal((await lab.doSubmit(m,tokenA)).status,403);
    assert.equal(lab.creates,1);
  });
});

test("same instruction ID cannot enqueue again or be repurposed for a different file",async()=>{
  await withIssuer(async()=>{
    const lab=fixture(),p=members[0],jwt=await token({sub:p.owner,client_id:p.client});
    const accepted=await lab.doSubmit(p,jwt);
    const replay=await lab.doSubmit(p,jwt);
    assert.equal(accepted.status,202);
    assert.equal(replay.status,200);
    assert.equal(replay.body.replayed,true);
    assert.equal(accepted.body.request_id,replay.body.request_id);
    assert.equal(lab.creates,1);
    const conflict=await lab.doSubmit(p,jwt,{arguments:{path:"pasta 2/segredo.txt"}});
    assert.equal(conflict.status,409);
    assert.equal(lab.creates,1);
  });
});
