import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  createPostgresCentralSessionVerifier,
  createCanonicalCentralAdmissionVerifier,
} from "../cloudflare/src/product_central_admission.ts";
import {
  bindProductCentralConversation,verifyProductCentralConversation,
  revokeProductCentralConversation,ProductPostgresError,
} from "../cloudflare/src/product_postgres_store.ts";
import { owner,client,otherClient,device,secondDevice,env,token,withIssuer } from "./product_mcp_test_fixtures.mts";

const requestId=randomUUID(),spaceId=randomUUID(),projectId=randomUUID();
const sessionId="openai-test-session-20261011-B";
const conversationId="chatgpt-conversation-20261011-B";
const record={
  subjectId:owner,clientId:client,deviceId:device,spaceId,projectId,
  requestId,sessionId,conversationId,
};
const clientIdentity={ownerUserId:owner,clientId:client,clientKind:"product-mcp" as const};

test("durable verifier accepts only original OAuth subject/client/PC/chat/session and exact scope",async()=>{
  const seen:object[]=[];
  const verify=createPostgresCentralSessionVerifier(env,async(_env,data)=>{
    seen.push(data);
    return data.ownerUserId===owner && data.clientId===client
      && data.deviceId===device && data.spaceId===spaceId
      && data.projectId===projectId && data.requestId===requestId
      && data.conversationId===conversationId && data.sessionId===sessionId;
  });
  assert.equal(await verify(clientIdentity,record),true);
  assert.equal(seen.length,1);
  assert.equal(await verify({...clientIdentity,clientId:otherClient},record),false);
  assert.equal(await verify(clientIdentity,{...record,deviceId:secondDevice}),false);
  assert.equal(await verify(clientIdentity,{...record,conversationId:"another-conversation-555"}),false);
  assert.equal(await verify(clientIdentity,{...record,sessionId:"different-session-555"}),false);
  assert.equal(await verify(clientIdentity,{...record,sessionId:undefined}),false);
  assert.equal(await verify(clientIdentity,{...record,spaceId:null,projectId:null}),false);
  assert.equal(await verify(clientIdentity,{...record,spaceId:null,projectId}),false);
  assert.equal(seen.length,5,"invalid bindings and foreign client never touch database");
});

test("DB failure, missing mapping or revoked mapping denies immediately",async()=>{
  let state:"present"|"gone"|"offline"="present";
  const verify=createPostgresCentralSessionVerifier(env,async()=>{
    if(state==="offline")throw new Error("database unavailable");
    return state==="present";
  });
  assert.equal(await verify(clientIdentity,record),true);
  state="gone";
  assert.equal(await verify(clientIdentity,record),false);
  state="offline";
  assert.equal(await verify(clientIdentity,record),false);
});

test("signed OAuth admission uses durable PostgreSQL verifier BEFORE catalog selection",async()=>{
  await withIssuer(async()=>{
    const observed:string[]=[];
    let linked=false;
    const verify=createPostgresCentralSessionVerifier(env,async(_env,row)=>{
      observed.push("db");
      return linked&&row.requestId===requestId;
    });
    const admit=createCanonicalCentralAdmissionVerifier(env,{
      verifySession:verify,
      listTargets:async()=>{
        observed.push("catalog");
        return {ok:true,targets:[{device_id:device,grant_groups:[{
          space_id:spaceId,project_id:projectId,valid_until:null,
          capabilities:[{capability:"workspace.text_read",access_mode:"read"}],
        }]}]};
      },
    });
    const signed=await token();
    const req=new Request("https://example.invalid/mcp",{headers:{authorization:"Bearer "+signed}});
    assert.equal((await admit(req,record)).ok,false);
    assert.deepEqual(observed,["db"]);
    linked=true;
    const ok=await admit(req,record);
    assert.equal(ok.ok,true,JSON.stringify(ok));
    assert.deepEqual(observed,["db","db","catalog"]);
    assert.equal((await admit(req,{...record,clientId:otherClient})).ok,false);
    assert.equal(observed.length,3);
  });
});

test("unsupported/unconfigured Product DB NEVER creates Central conversation locally",async()=>{
  const invalid={ownerUserId:owner,clientId:client,deviceId:device,
    spaceId,projectId,requestId,conversationId,sessionId};
  const fake={};
  await assert.rejects(bindProductCentralConversation(fake,invalid,new Date(Date.now()+600000).toISOString()),
    e=>e instanceof ProductPostgresError && e.code==="product_postgres_unconfigured");
  await assert.rejects(verifyProductCentralConversation(fake,invalid),
    e=>e instanceof ProductPostgresError && e.code==="product_postgres_unconfigured");
  await assert.rejects(revokeProductCentralConversation(fake,owner,client,requestId),
    e=>e instanceof ProductPostgresError && e.code==="product_postgres_unconfigured");
  await assert.rejects(verifyProductCentralConversation(fake,{...invalid,sessionId:" "}),
    e=>e instanceof ProductPostgresError && e.code==="central_session_invalid");
});
