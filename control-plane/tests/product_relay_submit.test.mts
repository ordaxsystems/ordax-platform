import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createCanonicalRelayActionSubmitHandler } from "../cloudflare/src/product_relay_submit.ts";
import {
  env, owner, otherOwner, client, otherClient, device, secondDevice, projectId,
  effectId, requestId, token, withIssuer,
} from "./product_mcp_test_fixtures.mts";

const spaceId = "99999999-9999-4999-8999-999999999999";
const body = { action: "workspace.directory_list", arguments: { path: "pasta 1", max_depth: 2 } };
const bound = { subjectId: owner, clientId: client, deviceId: device,
  spaceId, projectId, operationId: randomUUID() };
const grant = (value: { deviceId: string; spaceId: string; projectId: string; expires?: string | null } = bound) => ({
  ok: true, targets: [{
    device_id: value.deviceId, grant_groups: [{
      grant_group_id: randomUUID(), space_id: value.spaceId, project_id: value.projectId,
      valid_until: value.expires ?? null,
      capabilities: [{ capability: "workspace.directory_list", access_mode: "read" }],
    }],
  }],
});
type Binding = Parameters<ReturnType<typeof createCanonicalRelayActionSubmitHandler>>[1];
function request(jwt: string, payload: Record<string,unknown>) {
  return new Request("https://ordax.example/v3/product/actions", {
    method: "POST", headers: {
      "content-type": "application/json", authorization: "Bearer " + jwt,
      // Deliberately spoofed: never used for target or owner authorization.
      "x-ordax-owner-user-id": otherOwner, "x-ordax-client-id": otherClient,
      "x-ordax-device-id": secondDevice,
    },
    body: JSON.stringify(payload),
  });
}
async function submit(
  handler: ReturnType<typeof createCanonicalRelayActionSubmitHandler>,
  jwt: string, binding: Binding, payload: Record<string,unknown> = body,
) {
  const response = await handler(request(jwt,payload),binding);
  return { status: response.status, body: await response.json(),
    cache: response.headers.get("cache-control") };
}

test("trusted UUID and OAuth identity bind the canonical grant and stable idempotency", async () => {
  await withIssuer(async () => {
    const calls: unknown[] = []; let discovery: unknown;
    const handler = createCanonicalRelayActionSubmitHandler(env,{
      now: () => Date.parse("2026-10-10T19:00:00Z"),
      listTargets: async (_env, input) => { discovery=input; return grant(); },
      enqueue: async (_env, input) => { calls.push(input);
        return { ok:true,replayed:false,request_id:requestId,effect_id:effectId,status:"queued" }; },
    });
    const answer = await submit(handler,await token(),bound);
    assert.equal(answer.status,202);
    assert.equal(answer.cache,"no-store");
    assert.deepEqual(answer.body, {
      ok:true,request_id:requestId,effect_id:effectId,
      status:"queued",replayed:false,device_id:device,project_id:projectId,
    });
    assert.deepEqual(discovery,{ownerUserId:owner,clientKind:"product-mcp",clientId:client});
    assert.deepEqual(calls,[{
      ownerUserId:owner,clientKind:"product-mcp",clientId:client,
      deviceId:device,spaceId,projectId,capability:body.action,accessMode:"read",
      payload:body.arguments,idempotencyKey:"relay-"+bound.operationId.toLowerCase(),
      expiresAt:"2026-10-10T19:05:00.000Z",
    }]);
  });
});

test("missing or forged trusted operation never reaches Product or target discovery", async () => {
  await withIssuer(async () => {
    let discoveries=0,enqueues=0;
    const handler = createCanonicalRelayActionSubmitHandler(env,{
      listTargets: async () => { discoveries++; return grant(); },
      enqueue: async () => { enqueues++; return {ok:true,request_id:requestId,effect_id:effectId,replayed:false,status:"queued"}; },
    });
    const jwt=await token();
    for(const binding of [
      null,undefined,
      {...bound,operationId:"not-uuid"},
      {...bound,operationId:""},
      {...bound,deviceId:secondDevice,subjectId:otherOwner},
      {...bound,subjectId:otherOwner},
      {...bound,clientId:otherClient},
      {...bound,extra:"user-supplied-target"},
      {...bound,projectId:"../outside"},
    ]){
      const response=await submit(handler,jwt,binding as Binding);
      assert.equal(response.status,403,JSON.stringify(binding));
      assert.equal(response.body.error,"relay_action_denied");
    }
    assert.equal(discoveries,0);
    assert.equal(enqueues,0);
  });
});

test("3 authorized clients cannot submit to another PC or project with a reused instruction ID", async () => {
  await withIssuer(async () => {
    const members=[
      {owner,client,device,projectId,spaceId,operationId:randomUUID()},
      {owner,client:otherClient,device:secondDevice,projectId:randomUUID(),spaceId,operationId:randomUUID()},
      {owner:otherOwner,client,device:randomUUID(),projectId:randomUUID(),spaceId,operationId:randomUUID()},
    ];
    const events: unknown[]=[];
    const handler=createCanonicalRelayActionSubmitHandler(env,{
      listTargets:async (_,input)=>{
        const m=members.find(p=>p.owner===input.ownerUserId&&p.client===input.clientId);
        return m?grant({deviceId:m.device,projectId:m.projectId,spaceId:m.spaceId}):{ok:true,targets:[]};
      },
      enqueue:async (_,input)=>{events.push(input);
        return {ok:true,request_id:requestId,effect_id:effectId,replayed:false,status:"queued"};},
    });
    for(const m of members){
      const jwt=await token({sub:m.owner,client_id:m.client});
      const own={subjectId:m.owner,clientId:m.client,deviceId:m.device,spaceId:m.spaceId,
        projectId:m.projectId,operationId:m.operationId};
      assert.equal((await submit(handler,jwt,own)).status,202);
      for(const target of members.filter(p=>p.device!==m.device)){
        assert.equal((await submit(handler,jwt,{...own,deviceId:target.device})).status,403);
        assert.equal((await submit(handler,jwt,{...own,projectId:target.projectId})).status,403);
      }
    }
    assert.equal(events.length,3);
    for(const [i,event] of events.entries()){
      assert.equal((event as Record<string,unknown>).deviceId,members[i].device);
      assert.equal((event as Record<string,unknown>).ownerUserId,members[i].owner);
      assert.equal((event as Record<string,unknown>).clientId,members[i].client);
    }
  });
});

test("model cannot supply device, project, operation UUID or idempotency in its tool JSON",async()=>{
  await withIssuer(async()=>{
    let calls=0;
    const handler=createCanonicalRelayActionSubmitHandler(env,{
      listTargets:async()=>{calls++;return grant();},
      enqueue:async()=>{throw Error("unexpected");},
    });
    const jwt=await token();
    for(const payload of [
      {...body,device_id:device},{...body,project_id:projectId},
      {...body,space_id:spaceId},{...body,idempotency_key:"model-created"},
      {...body,operation_id:randomUUID()},{...body,client_id:client},
      {...body,action:"terminal.exec"},{...body,action:"workspace.text_write"},
      {...body,arguments:{path:"pasta 1/../privado"}},
      {...body,arguments:{path:"pasta 1/%2e%2e"}},
      {...body,arguments:{path:"C:/private"}},
      {...body,arguments:{path:"pasta 1/CON"}},
      {...body,arguments:{path:"pasta 1",max_depth:500}},
      {...body,arguments:{path:"pasta 1",request_id:randomUUID()}},
    ]){
      const answer=await submit(handler,jwt,bound,payload);
      assert.equal(answer.status,400,JSON.stringify(payload));
    }
    assert.equal(calls,0);
  });
});

test("revoked, expired, unbound and ambiguous Product grants deny without creating a request",async()=>{
  await withIssuer(async()=>{
    let mode="normal",writes=0;
    const handler=createCanonicalRelayActionSubmitHandler(env,{
      listTargets:async()=>{
        if(mode==="revoked")return {ok:true,targets:[]};
        const current=grant();
        if(mode==="expired")current.targets[0].grant_groups[0].valid_until="2020-01-01T00:00:00Z";
        if(mode==="target-absent")return {ok:true,targets:[{device_id:secondDevice,grant_groups:[]}]};
        if(mode==="duplicate-device")current.targets.push(current.targets[0]);
        if(mode==="multiple-projects")current.targets[0].grant_groups.push({
          grant_group_id:randomUUID(),space_id:spaceId,project_id:randomUUID(),valid_until:null,
          capabilities:[{capability:"workspace.directory_list",access_mode:"read"}],
        });
        return current;
      },
      enqueue:async()=>{writes++;throw Error("unexpected");},
    });
    const jwt=await token();
    for(mode of ["revoked","expired","target-absent","duplicate-device","multiple-projects"]){
      const result=await submit(handler,jwt,bound);
      assert.equal(result.status,403,mode);
    }
    assert.equal(writes,0);
  });
});

test("one host operation key is replayed durably, changing the instruction conflicts",async()=>{
  await withIssuer(async()=>{
    const rows=new Map<string,{signature:string;requestId:string}>();
    let executions=0;
    const handler=createCanonicalRelayActionSubmitHandler(env,{
      listTargets:async()=>grant(),
      enqueue:async(_,input)=>{
        const key=input.ownerUserId+":"+input.idempotencyKey;
        const signature=JSON.stringify([input.deviceId,input.clientId,input.projectId,input.capability,input.payload]);
        const previous=rows.get(key);
        if(previous){
          if(previous.signature!==signature)return {ok:false,error:"idempotency_conflict"};
          return {ok:true,replayed:true,request_id:previous.requestId,effect_id:effectId,status:"queued"};
        }
        executions++;
        rows.set(key,{signature,requestId});
        return {ok:true,replayed:false,request_id:requestId,effect_id:effectId,status:"queued"};
      },
    });
    const jwt=await token();
    const first=await submit(handler,jwt,bound);
    const replay=await submit(handler,jwt,bound);
    const conflict=await submit(handler,jwt,bound,{...body,arguments:{path:"pasta 2"}});
    assert.equal(first.status,202);
    assert.equal(replay.status,200);
    assert.equal(replay.body.replayed,true);
    assert.equal(replay.body.request_id,first.body.request_id);
    assert.equal(conflict.status,409);
    assert.equal(executions,1);
  });
});

test("unknown outcome, invalid receipt and unauthenticated attempts never claim success",async()=>{
  await withIssuer(async()=>{
    let calls=0;
    const bad=createCanonicalRelayActionSubmitHandler(env,{
      listTargets:async()=>grant(),
      enqueue:async()=>{calls++;throw Error("sensitive-database-host");},
    });
    const jwt=await token();
    const invalid=await submit(bad,await token({client_id:undefined}),bound);
    assert.equal(invalid.status,403);
    assert.equal(calls,0);
    const failed=await submit(bad,jwt,bound);
    assert.equal(failed.status,503);
    assert.ok(!JSON.stringify(failed).includes("sensitive"));
    assert.equal(calls,1);
    const broken=createCanonicalRelayActionSubmitHandler(env,{
      listTargets:async()=>grant(),
      enqueue:async()=>({ok:true,replayed:false,request_id:"invalid",effect_id:effectId,status:"queued"}),
    });
    assert.equal((await submit(broken,jwt,bound)).status,503);
  });
});

test("same device with two OAuth clients retains separate operation and grant authority", async () => {
  await withIssuer(async () => {
    const projectA=projectId,projectB=randomUUID();
    const clients=[
      {owner,client,projectId:projectA,operationId:randomUUID()},
      {owner,client:otherClient,projectId:projectB,operationId:randomUUID()},
    ];
    const writes:unknown[]=[];
    const handler=createCanonicalRelayActionSubmitHandler(env,{
      listTargets:async (_,input)=>{
        const member=clients.find(x=>x.owner===input.ownerUserId&&x.client===input.clientId);
        return member?grant({deviceId:device,spaceId,projectId:member.projectId}):{ok:true,targets:[]};
      },
      enqueue:async (_,input)=>{writes.push(input);
        return {ok:true,request_id:randomUUID(),effect_id:randomUUID(),replayed:false,status:"queued"};},
    });
    for(const member of clients){
      const jwt=await token({sub:member.owner,client_id:member.client});
      const binding={subjectId:member.owner,clientId:member.client,deviceId:device,
        spaceId,projectId:member.projectId,operationId:member.operationId};
      assert.equal((await submit(handler,jwt,binding)).status,202);
      // Same physical PC is not authority to switch to another client's grant.
      const other=clients.find(x=>x!==member)!;
      assert.equal((await submit(handler,jwt,{...binding,projectId:other.projectId})).status,403);
      assert.equal((await submit(handler,jwt,{...binding,clientId:other.client})).status,403);
      assert.equal((await submit(handler,jwt,{...binding,operationId:""})).status,403);
    }
    assert.equal(writes.length,2);
    assert.equal((writes[0] as Record<string,unknown>).deviceId,device);
    assert.equal((writes[1] as Record<string,unknown>).deviceId,device);
    assert.equal((writes[0] as Record<string,unknown>).projectId,projectA);
    assert.equal((writes[1] as Record<string,unknown>).projectId,projectB);
    assert.notEqual((writes[0] as Record<string,unknown>).idempotencyKey,
      (writes[1] as Record<string,unknown>).idempotencyKey);
  });
});

test("two PCs under one signed account can dispatch only to the explicitly host-bound PC",async()=>{
  await withIssuer(async()=>{
    const many=[
      grant({deviceId:device,projectId,spaceId}).targets[0],
      grant({deviceId:secondDevice,projectId:"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",spaceId}).targets[0],
    ];
    const calls:unknown[]=[];
    const handler=createCanonicalRelayActionSubmitHandler(env,{
      listTargets:async()=>({ok:true,targets:many}),
      enqueue:async(_,input)=>{calls.push(input);
        return {ok:true,request_id:randomUUID(),effect_id:randomUUID(),status:"queued",replayed:false};}
    });
    const jwt=await token();
    const first=await submit(handler,jwt,bound);
    const secondBinding={...bound,deviceId:secondDevice,
      projectId:"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",operationId:randomUUID()};
    const second=await submit(handler,jwt,secondBinding);
    assert.equal(first.status,202);
    assert.equal(second.status,202);
    assert.equal(first.body.device_id,device);
    assert.equal(second.body.device_id,secondDevice);
    assert.equal(calls.length,2);
    assert.equal((calls[0] as Record<string,unknown>).deviceId,device);
    assert.equal((calls[1] as Record<string,unknown>).deviceId,secondDevice);
    // The LLM cannot pick a destination even when the account owns both PCs.
    const untrusted=await submit(handler,jwt,bound,{...body,device_id:secondDevice});
    assert.equal(untrusted.status,400);
    const swapped=await submit(handler,jwt,{...bound,deviceId:secondDevice});
    assert.equal(swapped.status,403);
    assert.equal(calls.length,2);
  });
});
