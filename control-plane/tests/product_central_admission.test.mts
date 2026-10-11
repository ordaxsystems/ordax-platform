import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createCanonicalCentralAdmissionVerifier } from "../cloudflare/src/product_central_admission.ts";
import { createCanonicalCentralSessionMcpGateway } from "../cloudflare/src/product_central_mcp.ts";
import {
  env, owner, otherOwner, client, otherClient, device, secondDevice,
  projectId, withIssuer, token, requestId,
} from "./product_mcp_test_fixtures.mts";

const spaceId="99999999-9999-4999-8999-999999999999";
const chatId="chat-authorized-0001";
const otherChat="chat-elsewhere-0002";
const sessionId="chatgpt-session-A-20261011";
const otherSessionId="chatgpt-session-B-20261011";
const binding=Object.freeze({subjectId:owner,clientId:client,deviceId:device,
  spaceId,projectId,requestId,conversationId:chatId,sessionId});
const otherBinding=Object.freeze({...binding,clientId:otherClient,
  deviceId:secondDevice,projectId:randomUUID(),conversationId:otherChat,requestId:randomUUID(),sessionId:otherSessionId});
type Binding=typeof binding;
const identity=(jwt:string)=>new Request("https://central.example/mcp",{
  method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+jwt,
    "x-ordax-device-id":secondDevice,"x-ordax-client-id":otherClient},
});
function fixture(){
  const rows=new Map<string,Binding>([[client,binding],[otherClient,otherBinding]]);
  const calls:{kind:string,clientId:string}[]=[];
  let mode="normal";
  const grant=(b:Binding)=>({device_id:b.deviceId,device_name:"Authorized",
    grant_groups:[{space_id:b.spaceId,project_id:b.projectId,valid_until:mode==="expired"?"2020-01-01T00:00:00Z":null,
      capabilities:[{capability:"workspace.text_read",access_mode:"read"}]}]});
  const deps={
    listTargets:async(_env:unknown,clientInfo:{clientId:string})=>{
      calls.push({kind:"catalog",clientId:clientInfo.clientId});
      const b=rows.get(clientInfo.clientId);
      if(!b || mode==="revoked")return {ok:true,targets:[]};
      return {ok:true,targets:mode==="ambiguous"
        ?[grant(b),grant({...b,deviceId:b.deviceId===device?secondDevice:device})]
        :[grant(b)]};
    },
    verifySession:async(clientInfo:{ownerUserId:string,clientId:string},value:Binding)=>{
      calls.push({kind:"session",clientId:clientInfo.clientId});
      if(mode==="missing-session")return false;
      const row=rows.get(clientInfo.clientId);
      return Boolean(row && row.subjectId===clientInfo.ownerUserId
        && row.clientId===value.clientId && row.deviceId===value.deviceId
        && row.projectId===value.projectId && row.spaceId===value.spaceId
        && row.requestId===value.requestId && row.conversationId===value.conversationId
        && row.sessionId===value.sessionId);
    },
  };
  return {deps,calls,setMode:(next:string)=>{mode=next},rows};
}
test("no durable Product conversation authority means admission cannot even be constructed",()=>{
  assert.throws(()=>createCanonicalCentralAdmissionVerifier(env,{} as any),
    /central_session_authority_required/);
  assert.throws(()=>createCanonicalCentralSessionMcpGateway(env,binding,{} as any),
    /central_session_authority_required/);
});

test("signed client, one Product PC and durable chat record produce exact immutable admission",async()=>{
  await withIssuer(async()=>{
    const f=fixture();
    const guard=createCanonicalCentralAdmissionVerifier(env,f.deps);
    const result=await guard(identity(await token()),binding);
    assert.equal(result.ok,true,JSON.stringify(result));
    if(!result.ok)return;
    assert.equal(result.subjectId,owner);
    assert.equal(result.clientId,client);
    assert.equal(result.deviceId,device);
    assert.equal(result.projectId,projectId);
    assert.equal(result.conversationId,chatId);
    assert.equal(result.requestId,requestId);
    assert.deepEqual(result.allowedActions,["workspace.text_read"]);
    assert.ok(result.expiresAt>Math.floor(Date.now()/1000));
    assert.ok(Object.isFrozen(result));
    assert.equal(f.calls.filter(x=>x.kind==="session").length,1);
  });
});
test("three signed client/PC/chat combinations are isolated; OAuth cannot borrow another chat",async()=>{
  await withIssuer(async()=>{
    const f=fixture();
    const guard=createCanonicalCentralAdmissionVerifier(env,f.deps);
    const clients=[
      {jwt:await token(),b:binding},
      {jwt:await token({client_id:otherClient}),b:otherBinding},
      {jwt:await token({sub:otherOwner,client_id:otherClient}),b:otherBinding},
    ];
    for(const c of clients.slice(0,2)){
      assert.equal((await guard(identity(c.jwt),c.b)).ok,true);
      const swapped=c.b===binding?otherBinding:binding;
      assert.equal((await guard(identity(c.jwt),swapped)).ok,false);
    }
    assert.equal((await guard(identity(clients[2].jwt),otherBinding)).ok,false);
    assert.equal((await guard(identity(clients[0].jwt),{...binding,conversationId:otherChat})).ok,false);
    assert.equal((await guard(identity(clients[0].jwt),{...binding,requestId:randomUUID()})).ok,false);
    assert.equal((await guard(identity(clients[0].jwt),{...binding,deviceId:secondDevice})).ok,false);
    assert.equal((await guard(identity(clients[0].jwt),{...binding,projectId:otherBinding.projectId})).ok,false);
  });
});
test("missing, forged or malformed binding is denied before target RPC",async()=>{
  await withIssuer(async()=>{
    const f=fixture();
    const guard=createCanonicalCentralAdmissionVerifier(env,f.deps),jwt=await token();
    for(const b of [null,{}, {...binding,extra:"forged"},
      {...binding,conversationId:"/"}, {...binding,requestId:"untrusted"},
      {...binding,clientId:otherClient}, {...binding,spaceId:null}]){
      assert.equal((await guard(identity(jwt),b as any)).ok,false);
    }
    assert.equal(f.calls.filter(x=>x.kind==="catalog").length,0);
  });
});
test("ambiguous Product grants, revoked grants and missing durable chat mapping all fail closed",async()=>{
  await withIssuer(async()=>{
    const f=fixture(),guard=createCanonicalCentralAdmissionVerifier(env,f.deps);
    const req=identity(await token());
    for(const mode of ["ambiguous","revoked","expired","missing-session"]){
      f.setMode(mode);
      const response=await guard(req.clone(),binding);
      assert.equal(response.ok,false,JSON.stringify({mode,response}));
    }
  });
});
test("unsigned, wrong OAuth subject, missing signed client never reach catalog or session",async()=>{
  await withIssuer(async()=>{
    const f=fixture(),guard=createCanonicalCentralAdmissionVerifier(env,f.deps);
    const bad=["not-jwt",await token({aud:"not-authenticated"}),
      await token({client_id:undefined}),await token({sub:otherOwner})];
    for(const jwt of bad)assert.equal((await guard(identity(jwt),binding)).ok,false);
    assert.equal(f.calls.length,0);
  });
});
function call(jwt:string,name:string,args:Record<string,unknown>={},marker:string|null=sessionId){
  return new Request("https://central.example/mcp",{
    method:"POST",
    headers:{"content-type":"application/json",authorization:"Bearer "+jwt,
      "x-ordax-device-id":secondDevice},
    body:JSON.stringify({jsonrpc:"2.0",id:1,method:name,
      params:name==="tools/call"?{name:"ordax_targets",arguments:args,
        ...(marker!==null?{_meta:{"openai/session":marker}}:{})}:undefined}),
  });
}
test("same MCP gateway rechecks session for each call; revoke blocks tool before read",async()=>{
  await withIssuer(async()=>{
    const f=fixture();
    const gateway=createCanonicalCentralSessionMcpGateway(env,binding,f.deps);
    const jwt=await token();
    const good=await gateway(call(jwt,"tools/call",{device_id:secondDevice}));
    assert.equal(good.status,200);
    const payload=await good.json();
    assert.equal(payload.result.structuredContent.targets.length,1);
    assert.equal(payload.result.structuredContent.targets[0].device_id,device);
    const before=f.calls.filter(x=>x.kind==="session").length;
    f.setMode("missing-session");
    const denied=await gateway(call(jwt,"tools/call"));
    assert.ok(denied.status===403|| (await denied.json()).result?.structuredContent?.ok===false);
    assert.equal(f.calls.filter(x=>x.kind==="session").length,before+1);
    // An untrusted different token/header cannot select the bound device.
    const bad=await gateway(call(await token({client_id:otherClient}),"tools/call"));
    assert.notEqual(bad.status,200);
  });
});
test("MCP session gate denies discovery if OAuth chat mapping is absent",async()=>{
  await withIssuer(async()=>{
    const f=fixture();f.setMode("missing-session");
    const gateway=createCanonicalCentralSessionMcpGateway(env,binding,f.deps);
    const response=await gateway(call(await token(),"tools/list"));
    assert.notEqual(response.status,200);
  });
});

test("OpenAI per-conversation MCP marker prevents cross-chat reads under the same OAuth client",async()=>{
  await withIssuer(async()=>{
    const f=fixture();
    const gateway=createCanonicalCentralSessionMcpGateway(env,binding,f.deps);
    const jwt=await token();
    const before=f.calls.length;
    for(const marker of [null,otherSessionId,"bad marker", "", "x".repeat(257)]){
      const response=await gateway(call(jwt,"tools/call",{},marker));
      assert.notEqual(response.status,200,JSON.stringify({marker,status:response.status}));
    }
    assert.equal(f.calls.length,before,"wrong metadata must fail before Product RPC");
    const valid=await gateway(call(jwt,"tools/call",{},sessionId));
    assert.equal(valid.status,200);
    const payload=await valid.json();
    assert.equal(payload.result.structuredContent.targets[0].device_id,device);
    assert.ok(f.calls.some(c=>c.kind==="session"));
  });
});
test("session marker in model tool arguments cannot override OpenAI MCP _meta",async()=>{
  await withIssuer(async()=>{
    const f=fixture(),gateway=createCanonicalCentralSessionMcpGateway(env,binding,f.deps);
    const jwt=await token();
    const bad=await gateway(call(jwt,"tools/call",{
      "_meta":{"openai/session":sessionId},
    },otherSessionId));
    assert.notEqual(bad.status,200);
    assert.equal(f.calls.length,0);
  });
});
test("unbound Central gateway refuses tools even with signed OAuth and supplied MCP marker",async()=>{
  await withIssuer(async()=>{
    const f=fixture();
    const {sessionId:_omit,...unbound}=binding;
    const gateway=createCanonicalCentralSessionMcpGateway(env,unbound,f.deps);
    const response=await gateway(call(await token(),"tools/call",{},sessionId));
    assert.notEqual(response.status,200);
    assert.equal(f.calls.length,0);
  });
});
