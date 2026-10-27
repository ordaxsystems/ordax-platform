import test from "node:test";
import assert from "node:assert/strict";
import {
  handleProductOwnerGrantAdmin,PRODUCT_OWNER_CENTRAL_SESSION_SELECTIONS_PATH,
} from "../cloudflare/src/product_owner_grant_admin.ts";
import {
  openCentralSessionFromMcp,
} from "../cloudflare/src/product_central_device_session.ts";
import { resolveOrBootstrapAttestedSession } from "../cloudflare/src/product_mcp_entry.ts";
import {env,owner,client,token,withIssuer} from "./product_mcp_test_fixtures.mts";

const challenge="22222222-2222-4222-8222-222222222222";
const device="33333333-3333-4333-8333-333333333333";
const OWNER_CLIENT="202fd3e1-b058-4531-8750-82c57e4b6ca0";
const base="https://mcp.ordax.com.br"+PRODUCT_OWNER_CENTRAL_SESSION_SELECTIONS_PATH;
const req=(url:string,jwt?:string,method="GET",body?:unknown)=>
  new Request(url,{method,headers:{
    ...(jwt?{authorization:"Bearer "+jwt}:{}),
    ...(body?{"content-type":"application/json"}:{}),
  },...(body?{body:JSON.stringify(body)}:{})});

test("Owner selection requires independent rollout gate and signed Owner JWT",async()=>{
  await withIssuer(async()=>{
    let calls=0;
    const select=async()=>{calls++;return {ok:true,status:"pending" as const};};
    const jwt=await token();
    assert.equal((await handleProductOwnerGrantAdmin(req(base,jwt,"POST",{
      client_id:client,challenge_id:challenge,device_id:device,
    }),env,{selectDevice:select})).status,404);
    assert.equal(calls,0);
    const enabled={...env,CENTRAL_OWNER_SELECTION_ENABLED:"enabled"};
    const delegated=await handleProductOwnerGrantAdmin(req(base,jwt,"POST",{
      client_id:client,challenge_id:challenge,device_id:device,
    }),enabled,{selectDevice:select});
    assert.equal(delegated.status,403);
    assert.equal((await delegated.json()).error,"owner_primary_session_required");
    const nativeOwner=await token({client_id:OWNER_CLIENT});
    const accepted=await handleProductOwnerGrantAdmin(req(base,nativeOwner,"POST",{
      client_id:client,challenge_id:challenge,device_id:device,
    }),{...enabled,PRODUCT_OWNER_OAUTH_CLIENT_ID:OWNER_CLIENT},{selectDevice:select});
    assert.equal(accepted.status,200,"official first-party Owner OAuth must remain usable");
    assert.equal(calls,1);
    const mismatched=await handleProductOwnerGrantAdmin(req(base,nativeOwner,"POST",{
      client_id:client,challenge_id:challenge,device_id:device,
    }),enabled,{selectDevice:select});
    assert.equal(mismatched.status,403,"unsigned/unconfigured owner client fails closed");
    const denied=await handleProductOwnerGrantAdmin(req(base,undefined,"POST",{
      client_id:client,challenge_id:challenge,device_id:device,
    }),enabled,{selectDevice:select});
    assert.equal(denied.status,401);
    assert.equal(calls,1);
  });
});

test("Owner route only permits exact IDs and one explicit selected challenge",async()=>{
  await withIssuer(async()=>{
    const jwt=await token({client_id:null}),enabled={...env,CENTRAL_OWNER_SELECTION_ENABLED:"enabled"};
    let listCalls=0,selectionCalls=0;
    const list=async(_env:unknown,input:{ownerUserId:string,clientId:string})=>{
      listCalls++;assert.deepEqual(input,{ownerUserId:owner,clientId:client});
      return {ok:true,pending_selections:[{challenge_id:challenge}],count:1};
    };
    const select=async(_env:unknown,input:{
      ownerUserId:string,clientId:string,challengeId:string,deviceId:string})=>{
      selectionCalls++;
      assert.deepEqual(input,{ownerUserId:owner,clientId:client,
        challengeId:challenge,deviceId:device});
      return {ok:true,status:"pending" as const,device_id:device,challenge_id:challenge,
        attested:false,dispatch_authorized:false};
    };
    const deps={listSelections:list,selectDevice:select};
    assert.equal((await handleProductOwnerGrantAdmin(req(base+"?client_id="+client,jwt),enabled,deps)).status,200);
    assert.equal(listCalls,1);
    for(const bad of [base,base+"?client_id="+client+"&device_id="+device,
      base+"?client_id="+client+"&client_id="+client,base+"?client_id=bad"]) {
      assert.equal((await handleProductOwnerGrantAdmin(req(bad,jwt),enabled,deps)).status,400);
    }
    for(const body of [
      {client_id:client,challenge_id:challenge,device_id:device,owner_id:owner},
      {client_id:client,challenge_id:challenge},
      {client_id:client,challenge_id:"bad",device_id:device},
      {client_id:"bad",challenge_id:challenge,device_id:device},
      {client_id:client,challenge_id:challenge,device_id:"bad"},
    ]) assert.equal((await handleProductOwnerGrantAdmin(req(base,jwt,"POST",body),enabled,deps)).status,400);
    assert.equal((await handleProductOwnerGrantAdmin(req(base+"?client_id="+client,jwt,
      "POST",{client_id:client,challenge_id:challenge,device_id:device}),enabled,deps)).status,400);
    assert.equal((await handleProductOwnerGrantAdmin(req(base,jwt,"DELETE"),enabled,deps)).status,405);
    assert.equal(selectionCalls,0);
    const selected=await handleProductOwnerGrantAdmin(req(base,jwt,"POST",{
      client_id:client,challenge_id:challenge,device_id:device,
    }),enabled,deps);
    assert.equal(selected.status,200);
    assert.equal((await selected.json()).attested,false);
    assert.equal(selectionCalls,1);
  });
});

test("MCP opening a waiting challenge cannot acquire Owner selection by model device argument",async()=>{
  await withIssuer(async()=>{
    const jwt=await token();
    const r=new Request("https://mcp.ordax.com.br/mcp",{
      method:"POST",headers:{authorization:"Bearer "+jwt,"content-type":"application/json"},
      body:JSON.stringify({jsonrpc:"2.0",id:3,method:"tools/call",params:{
        name:"computer_access_status",arguments:{device_id:device},
        _meta:{"openai/session":"openai-device-attested-session-20261027-G"},
      }}),
    });
    let called=0;
    const opened=await openCentralSessionFromMcp(r,env,{open:async(_env,input)=>{
      called++;
      assert.equal(input.ownerUserId,owner);
      assert.equal(input.clientId,client);
      assert.equal("deviceId" in input,false);
      return {ok:true,status:"awaiting_owner",challenge_id:challenge};
    }});
    assert.equal(opened.status,202);
    assert.equal((await opened.json()).status,"awaiting_owner");
    assert.equal(called,1);
  });
});

test("awaiting Owner returns a bounded remediation immediately without polling/retrying",async()=>{
  let opened=0,waited=0,resolved=0;
  const req=new Request("https://mcp.ordax.com.br/mcp",{method:"POST"});
  const result=await resolveOrBootstrapAttestedSession(req,env,{
    resolve:async()=>{
      resolved++;
      return {ok:false as const,error:"central_session_unbound"};
    },
    open:async()=>{
      opened++;
      return Response.json({ok:true,status:"awaiting_owner",challenge_id:challenge},{status:202});
    },
    wait:async()=>{waited++;throw Error("must not poll while Owner choice is pending");},
  });
  assert.deepEqual(result,{ok:false,error:"central_session_owner_selection_required"});
  assert.equal(opened,1);
  assert.equal(resolved,1);
  assert.equal(waited,0);
});
