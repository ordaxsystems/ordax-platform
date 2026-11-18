import test from "node:test";
import assert from "node:assert/strict";
import {
  handleProductOwnerGrantAdmin,PRODUCT_OWNER_CENTRAL_SESSION_SELECTIONS_PATH,
} from "../cloudflare/src/product_owner_grant_admin.ts";
import {
  openCentralSessionFromMcp,
} from "../cloudflare/src/product_central_device_session.ts";
import { resolveOrBootstrapAttestedSession } from "../cloudflare/src/product_mcp_entry.ts";
import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";
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

test("Owner central list projection excludes SQL secrets and rejects inconsistent receipts",async()=>{
  await withIssuer(async()=>{
    const jwt=await token({client_id:null});
    const enabled={...env,CENTRAL_OWNER_SELECTION_ENABLED:"enabled"};
    const created_at=new Date(Date.now()-1000).toISOString();
    const expires_at=new Date(Date.now()+60_000).toISOString();
    const normal=await handleProductOwnerGrantAdmin(req(base+"?client_id="+client,jwt),enabled,{
      listSelections:async()=>({
        ok:true,count:1,attested:false,dispatch_authorized:false,
        pending_selections:[{challenge_id:challenge,created_at,expires_at,
          session_sha256:"internal-session-hash",owner_user_id:owner}],
        private_audit:"secret",
      }),
    });
    assert.equal(normal.status,200);
    assert.deepEqual(await normal.json(),{
      ok:true,count:1,attested:false,dispatch_authorized:false,
      pending_selections:[{challenge_id:challenge,created_at,expires_at}],
    });
    for(const value of [
      {ok:true,count:1,pending_selections:[{challenge_id:challenge,created_at,expires_at}],
        attested:true,dispatch_authorized:false},
      {ok:true,count:2,pending_selections:[{challenge_id:challenge,created_at,expires_at}],
        attested:false,dispatch_authorized:false},
      {ok:true,count:1,pending_selections:[{challenge_id:challenge,created_at:"bad",expires_at}],
        attested:false,dispatch_authorized:false},
      {ok:true,count:2,pending_selections:[
        {challenge_id:challenge,created_at,expires_at},
        {challenge_id:challenge,created_at,expires_at}],
        attested:false,dispatch_authorized:false},
      {ok:false,error:"sql_backend_details",session_sha256:"private"},
    ]){
      const response=await handleProductOwnerGrantAdmin(req(base+"?client_id="+client,jwt),enabled,{
        listSelections:async()=>value,
      });
      assert.equal(response.status,value.ok?502:503);
      const projected=await response.json();
      assert.equal(JSON.stringify(projected).includes("private"),false);
      assert.equal(JSON.stringify(projected).includes("session_sha256"),false);
    }
  });
});

test("Owner selection requires independent rollout gate and signed Owner JWT",async()=>{
  await withIssuer(async()=>{
    let calls=0;
    const select=async()=>{calls++;return {ok:true,status:"pending" as const,
      device_id:device,challenge_id:challenge,expires_at:new Date(Date.now()+60_000).toISOString(),
      attested:false,dispatch_authorized:false};};
    const jwt=await token({client_id:null});
    assert.equal((await handleProductOwnerGrantAdmin(req(base,jwt,"POST",{
      client_id:client,challenge_id:challenge,device_id:device,
    }),env,{selectDevice:select})).status,404);
    assert.equal(calls,0);
    const enabled={...env,CENTRAL_OWNER_SELECTION_ENABLED:"enabled"};
    const delegatedJwt=await token();
    const delegated=await handleProductOwnerGrantAdmin(req(base,delegatedJwt,"POST",{
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
      return {ok:true,pending_selections:[{
        challenge_id:challenge,created_at:new Date(Date.now()-1000).toISOString(),
        expires_at:new Date(Date.now()+60_000).toISOString(),
        private_session_sha256:"must-never-leak",
      }],count:1,attested:false,dispatch_authorized:false,owner_user_id:owner};
    };
    const select=async(_env:unknown,input:{
      ownerUserId:string,clientId:string,challengeId:string,deviceId:string})=>{
      selectionCalls++;
      assert.deepEqual(input,{ownerUserId:owner,clientId:client,
        challengeId:challenge,deviceId:device});
      return {ok:true,status:"pending" as const,device_id:device,challenge_id:challenge,
        expires_at:new Date(Date.now()+60_000).toISOString(),
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

test("confirmed Owner choice wakes only the selected Runtime after the SQL receipt",async()=>{
  await withIssuer(async()=>{
    const jwt=await token({client_id:null});
    const enabled={...env,CENTRAL_OWNER_SELECTION_ENABLED:"enabled"};
    const body={client_id:client,challenge_id:challenge,device_id:device};
    const expires_at=new Date(Date.now()+90_000).toISOString();
    const order:string[]=[];
    const tasks:Promise<void>[]=[];
    const accepted=await handleProductOwnerGrantAdmin(req(base,jwt,"POST",body),enabled,{
      selectDevice:async()=>{
        order.push("postgres");
        return {ok:true,status:"pending" as const,device_id:device,challenge_id:challenge,
          expires_at,attested:false,dispatch_authorized:false,
          private_session_sha256:"never-reflect-sql-session-hash"};
      },
      signalWake:async(_env,selected,scheduler)=>{
        order.push("wake");
        assert.equal(selected,device,"only the SQL-confirmed device is signalled");
        assert.equal(typeof scheduler,"function");
        scheduler!(Promise.resolve());
      },
      scheduleWake:promise=>tasks.push(promise),
    });
    assert.equal(accepted.status,200);
    assert.deepEqual(order,["postgres","wake"],"signalling follows the committed Owner choice");
    assert.equal(tasks.length,1,"reuse request-context wake scheduler");
    assert.deepEqual(await accepted.json(),{
      ok:true,status:"pending",device_id:device,challenge_id:challenge,
      expires_at,attested:false,dispatch_authorized:false,
    });
    await Promise.all(tasks);

    // Lost advisory signal cannot undo an already committed pending choice,
    // and it must not retry the selector or claim attestation.
    let writes=0,wakes=0;
    const recovered=await handleProductOwnerGrantAdmin(req(base,jwt,"POST",body),enabled,{
      selectDevice:async()=>{
        writes++;
        return {ok:true,status:"pending" as const,device_id:device,challenge_id:challenge,
          expires_at,attested:false,dispatch_authorized:false};
      },
      signalWake:async()=>{wakes++;throw Error("wake transport unavailable");},
    });
    assert.equal(recovered.status,200);
    assert.equal((await recovered.json()).attested,false);
    assert.equal(writes,1);
    assert.equal(wakes,1);

    // A denied, stale or inconsistent SQL receipt never signals a device.
    for(const raw of [
      {ok:false,error:"owner_central_selection_not_pending"},
      {ok:true,status:"pending",device_id:"44444444-4444-4444-8444-444444444444",
        challenge_id:challenge,expires_at,attested:false,dispatch_authorized:false},
      {ok:true,status:"pending",device_id:device,
        challenge_id:challenge,expires_at,attested:true,dispatch_authorized:true},
      {ok:true,status:"pending",device_id:device,
        challenge_id:challenge,expires_at:"2000-01-01T00:00:00Z",
        attested:false,dispatch_authorized:false},
    ]){
      let notified=0;
      const response=await handleProductOwnerGrantAdmin(req(base,jwt,"POST",body),enabled,{
        selectDevice:async()=>raw,
        signalWake:async()=>{notified++;},
      });
      assert.equal(notified,0,"invalid SQL receipt must never wake Runtime");
      assert.equal(response.status,raw.ok?502:409);
    }
  });
});

test("Owner selection reports missing/stale/ambiguous challenge separately from auth denial",async()=>{
  await withIssuer(async()=>{
    const jwt=await token({client_id:null});
    const enabled={...env,CENTRAL_OWNER_SELECTION_ENABLED:"enabled"};
    const selection={
      client_id:client,challenge_id:challenge,device_id:device,
    };
    const cases=[
      ["owner_central_selection_invalid",400],
      ["owner_central_selection_not_found",404],
      ["owner_central_selection_not_pending",409],
      ["owner_central_selection_ambiguous",409],
      ["central_session_target_mismatch",409],
      ["central_device_runtime_not_ready",409],
      ["owner_central_client_not_consented",403],
      ["central_device_grant_revoked",403],
      ["owner_auth_ineligible",403],
      ["unknown_error",503],
    ] as const;
    let calls=0;
    for(const [error,expectedStatus] of cases){
      const response=await handleProductOwnerGrantAdmin(req(base,jwt,"POST",selection),enabled,{
        selectDevice:async()=>{
          calls++;
          return {ok:false,error};
        },
      });
      assert.equal(response.status,expectedStatus,error);
      assert.deepEqual(await response.json(),{
        ok:false,error:error==="unknown_error"?"owner_central_response_unavailable":error,
      },error);
    }
    assert.equal(calls,cases.length,"no status handling may retry a failed selection");
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

test("a second GPT session sees Owner choice contention without challenge or dispatch",async()=>{
  await withIssuer(async()=>{
    const jwt=await token();
    const request=new Request("https://mcp.ordax.com.br/mcp",{
      method:"POST",headers:{authorization:"Bearer "+jwt,"content-type":"application/json"},
      body:JSON.stringify({jsonrpc:"2.0",id:6,method:"tools/call",params:{
        name:"computer_access_status",arguments:{device_id:device},
        _meta:{"openai/session":"distinct-provider-conversation-marker"},
      }}),
    });
    let opens=0;
    const response=await openCentralSessionFromMcp(request,env,{open:async()=>{
      opens++;
      return {ok:false,error:"central_owner_selection_in_progress"};
    }});
    assert.equal(response.status,409);
    assert.deepEqual(await response.json(),
      {ok:false,error:"central_owner_selection_in_progress"});
    assert.equal(opens,1);
  });
  let resolved=0,opened=0,waited=0;
  const recovery=await resolveOrBootstrapAttestedSession(
    new Request("https://mcp.ordax.com.br/mcp",{method:"POST"}),env,{
      resolve:async()=>{
        resolved++;
        return {ok:false as const,error:"central_session_unbound"};
      },
      open:async()=>{
        opened++;
        return Response.json({ok:false,error:"central_owner_selection_in_progress"},
          {status:409});
      },
      wait:async()=>{waited++;throw Error("do not poll a competing Owner challenge");},
    });
  assert.deepEqual(recovery,{ok:false,error:"central_owner_selection_in_progress"});
  assert.equal(resolved,1);
  assert.equal(opened,1);
  assert.equal(waited,0);
  assert.equal("challenge_id" in recovery,false,"another GPT session's Owner ticket stays private");
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
  assert.deepEqual(result,{ok:false,error:"central_session_owner_selection_required",
    challenge_id:challenge});
  assert.equal(opened,1);
  assert.equal(resolved,1);
  assert.equal(waited,0);
});


test("MCP Owner-choice prompt remains non-dispatched and never leaks session correlation",async()=>{
  let calls=0;
  const gate=(challengeId:unknown)=>handleOrdaxMcp(new Request("https://mcp.ordax.com.br/mcp",{
    method:"POST",headers:{"content-type":"application/json"},
    body:JSON.stringify({jsonrpc:"2.0",id:5,method:"tools/call",params:{
      name:"computer_access_status",arguments:{device_id:device},
      _meta:{"openai/session":"private-provider-correlation-must-not-leak"},
    }}),
  }),{
    session:async()=>Response.json({ok:true,session:{subject_id:owner,client_id:client}}),
    targets:async()=>{throw Error("unexpected targets");},
    getAction:async()=>{throw Error("unexpected action read");},
    createAction:async()=>{
      calls++;
      return Response.json({ok:false,error:"central_session_owner_selection_required",
        challenge_id:challengeId,action_dispatched:false},{status:409});
    },
  },new Set(["computer_access_status"]));
  for(const [id,expected] of [[challenge,challenge],["not-a-challenge",null]] as const){
    const response=await gate(id);
    const payload=await response.json() as any;
    const result=payload.result?.structuredContent;
    assert.equal(result?.error,"central_session_owner_selection_required");
    assert.equal(result?.ok,false);
    assert.equal(result?.action_dispatched,false);
    assert.equal(result?.attested,false);
    assert.equal(result?.challenge_id,expected ?? undefined);
    assert.equal(JSON.stringify(result).includes("private-provider-correlation"),false);
    assert.equal(JSON.stringify(result).includes("session_sha256"),false);
    assert.equal(payload.result?.isError,false,
      "the client should render an Owner action-required reply, not an INVALID_ARGUMENT");
  }
  assert.equal(calls,2);
});
