import assert from "node:assert/strict";
import test from "node:test";

import {
  createOwnerProjectBindingHandler,
  PRODUCT_OWNER_PROJECT_BINDING_INTENTS_PATH,
} from "../cloudflare/src/product_owner_project_binding.ts";

const OWNER="11111111-1111-4111-8111-111111111111";
const PROJECT="22222222-2222-4222-8222-222222222222";
const SPACE="33333333-3333-4333-8333-333333333333";
const DEVICE="44444444-4444-4444-8444-444444444444";
const INTENT="55555555-5555-4555-8555-555555555555";
const NOW=Date.parse("2026-11-13T23:40:00Z");
const EXPIRES="2026-11-13T23:45:00.000Z";

const authenticated=async()=>({
  ok:true as const,subjectId:OWNER,issuer:"https://auth.example",audience:"ordax",
  expiresAt:2_000_000_000,clientId:null,role:"authenticated",
});

function req(body:Record<string,unknown>){
  return new Request("https://mcp.example"+PRODUCT_OWNER_PROJECT_BINDING_INTENTS_PATH,{
    method:"POST",headers:{authorization:"Bearer test","content-type":"application/json"},
    body:JSON.stringify(body),
  });
}

test("Owner binding intent contains only cloud Project and Device choice",async()=>{
  let observed:any=null,wakes:string[]=[];
  const handler=createOwnerProjectBindingHandler({OWNER_PROJECT_BINDING_ENABLED:"enabled"} as any,{
    authenticate:authenticated,now:()=>NOW,randomUuid:()=>INTENT,
    createIntent:async(_env,input)=>{
      observed=input;
      return {ok:true,intent_id:INTENT,project_id:PROJECT,space_id:SPACE,
        device_id:DEVICE,expires_at:EXPIRES,next_state:"awaiting_device_confirmation"};
    },
    wake:async(_env,deviceId)=>{wakes.push(deviceId)},
  });
  const response=await handler(req({project_id:PROJECT,device_id:DEVICE,confirm:"bind_device"}));
  assert.equal(response.status,201);
  assert.deepEqual(observed,{ownerUserId:OWNER,projectId:PROJECT,deviceId:DEVICE,
    intentId:INTENT,expiresAt:EXPIRES});
  assert.deepEqual(wakes,[DEVICE]);
  assert.deepEqual(await response.json(),{
    ok:true,schema:"ordax.owner-project-binding-intent/1",intent_id:INTENT,
    project_id:PROJECT,space_id:SPACE,device_id:DEVICE,expires_at:EXPIRES,
    next_state:"awaiting_device_confirmation",
  });
});

test("Owner cannot supply local ref, capabilities, path or grants",async()=>{
  let calls=0,wakes=0;
  const handler=createOwnerProjectBindingHandler({OWNER_PROJECT_BINDING_ENABLED:"enabled"} as any,{
    authenticate:authenticated,createIntent:async()=>{calls++;return {} as any},
    wake:async()=>{wakes++},
  });
  const base={project_id:PROJECT,device_id:DEVICE,confirm:"bind_device"};
  for(const extra of [
    {local_project_ref:"project-1"},{path:"/repo"},
    {capabilities:["terminal.exec"]},{grant_profile:"project-native-terminal"},
    {space_id:SPACE},{repository_id:"123"},
  ]){
    const response=await handler(req({...base,...extra}));
    assert.equal(response.status,400);
  }
  assert.equal(calls,0);
  assert.equal(wakes,0);
});

test("disabled binding is hidden only after Owner authentication",async()=>{
  let calls=0;
  const handler=createOwnerProjectBindingHandler({} as any,{
    authenticate:authenticated,createIntent:async()=>{calls++;return {} as any},
  });
  const response=await handler(req({project_id:PROJECT,device_id:DEVICE,confirm:"bind_device"}));
  assert.equal(response.status,404);
  assert.deepEqual(await response.json(),{ok:false,error:"not_found"});
  assert.equal(calls,0);
});

test("delegated OAuth client cannot create Owner binding intent",async()=>{
  let calls=0;
  const handler=createOwnerProjectBindingHandler({
    OWNER_PROJECT_BINDING_ENABLED:"enabled",
    PRODUCT_OWNER_OAUTH_CLIENT_ID:"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  } as any,{
    authenticate:async()=>({...await authenticated(),clientId:"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}),
    createIntent:async()=>{calls++;return {} as any},
  });
  const response=await handler(req({project_id:PROJECT,device_id:DEVICE,confirm:"bind_device"}));
  assert.equal(response.status,403);
  assert.equal(calls,0);
});

test("wake never converts a committed intent into extra authority",async()=>{
  let calls=0;
  const handler=createOwnerProjectBindingHandler({OWNER_PROJECT_BINDING_ENABLED:"enabled"} as any,{
    authenticate:authenticated,now:()=>NOW,randomUuid:()=>INTENT,
    createIntent:async()=>({ok:true,intent_id:INTENT,project_id:PROJECT,space_id:SPACE,
      device_id:DEVICE,expires_at:EXPIRES,next_state:"awaiting_device_confirmation"}),
    wake:async()=>{calls++;throw Error("wake lost")},
  });
  const response=await handler(req({project_id:PROJECT,device_id:DEVICE,confirm:"bind_device"}));
  assert.equal(response.status,503);
  assert.deepEqual(await response.json(),{ok:false,error:"product_postgres_unavailable"});
  assert.equal(calls,1);
  // No second createIntent is attempted; an Owner must read/retry explicitly.
});
