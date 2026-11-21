import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {
  centralSessionMarker,openCentralSessionFromMcp,resolveCentralSessionFromMcp,
} from "../cloudflare/src/product_central_device_session.ts";
import {env,owner,token,withIssuer} from "./product_mcp_test_fixtures.mts";

const FORGE_CLIENT="6a94ae80-a59c-4f48-a32c-2e15da34374f";
const OTHER_CLIENT="202fd3e1-b058-4531-8750-82c57e4b6ca0";
const DEVICE="22222222-2222-4222-8222-222222222222";
const NONCE="N".repeat(43);
const enabled={...env,FORGE_NATIVE_DELEGATION_ENABLED:"enabled",
  FORGE_NATIVE_OAUTH_CLIENT_ID:FORGE_CLIENT};
const nativeRequest=(jwt:string,nonce=NONCE,both=false)=>
  new Request("https://mcp.ordax.com.br/mcp",{
    method:"POST",headers:{authorization:"Bearer "+jwt,
      "content-type":"application/json"},
    body:JSON.stringify({jsonrpc:"2.0",id:"native-test",method:"tools/call",
      params:{name:"ordax_session",arguments:{device_id:"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
        _meta:{"ordax/native-session":nonce,
          ...(both?{"openai/session":"chatgpt-marker-123456"}:{})}}}),
  });

test("native Forge correlation is disabled by default, including valid OAuth",async()=>{
  await withIssuer(async()=>{
    const jwt=await token({client_id:FORGE_CLIENT});
    let opens=0;
    for(const e of [env,{...enabled,FORGE_NATIVE_DELEGATION_ENABLED:"disabled"},
      {...enabled,FORGE_NATIVE_OAUTH_CLIENT_ID:""}]){
      const make=()=>nativeRequest(jwt);
      assert.equal(await centralSessionMarker(make(),e),null);
      const response=await openCentralSessionFromMcp(make(),e,{
        open:async()=>{opens++;throw Error("disabled must never touch SQL");}
      });
      assert.equal(response.status,409);
      assert.equal((await response.json()).error,"central_session_marker_required");
    }
    assert.equal(opens,0);
  });
});

test("only signed Forge OAuth client and exact native nonce enter the canonical SQL session",async()=>{
  await withIssuer(async()=>{
    const jwt=await token({client_id:FORGE_CLIENT});
    assert.equal(await centralSessionMarker(nativeRequest(jwt),enabled),
      "forge-native-v1:"+NONCE);
    let input:any=null;
    const result=await openCentralSessionFromMcp(nativeRequest(jwt),enabled,{
      open:async(_env,body)=>{input=body;return {
        ok:true,status:"awaiting_owner",device_id:DEVICE,
        challenge_id:"33333333-3333-4333-8333-333333333333",
        expires_at:new Date(Date.now()+60_000).toISOString(),
      };},
    });
    assert.equal(result.status,202);
    assert.deepEqual(input,{ownerUserId:owner,clientId:FORGE_CLIENT,
      sessionSha256:createHash("sha256").update("forge-native-v1:"+NONCE)
        .digest("hex")});
    assert.equal(Object.prototype.hasOwnProperty.call(input,"deviceId"),false);
    assert.equal((await result.json()).status,"awaiting_owner");
  });
});

test("other OAuth client, missing authentication, ambiguous marker or bad nonce cannot open",async()=>{
  await withIssuer(async()=>{
    const foreign=await token({client_id:OTHER_CLIENT});
    const forge=await token({client_id:FORGE_CLIENT});
    let opens=0;
    const cases=[
      nativeRequest(foreign),
      nativeRequest(forge,"short"),
      nativeRequest(forge,NONCE,true),
      nativeRequest(forge,"A".repeat(42)+"!"),
      new Request("https://mcp.ordax.com.br/mcp",{
        method:"POST",headers:{"content-type":"application/json"},
        body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/call",
          params:{name:"ordax_session",arguments:{},
            _meta:{"ordax/native-session":NONCE}}}),
      }),
    ];
    for(const req of cases){
      const response=await openCentralSessionFromMcp(req,enabled,{
        open:async()=>{opens++;throw Error("unauthorized challenge");}
      });
      assert.equal(response.status,409);
    }
    assert.equal(opens,0);
  });
});

test("Forge native marker never converts an unbound session into a device authorization",async()=>{
  await withIssuer(async()=>{
    const jwt=await token({client_id:FORGE_CLIENT});
    let resolved=0;
    const result=await resolveCentralSessionFromMcp(nativeRequest(jwt),enabled,{
      resolve:async(_env,input)=>{
        resolved++;assert.equal(input.clientId,FORGE_CLIENT);
        assert.match(input.sessionSha256,/^[0-9a-f]{64}$/);
        return {ok:false,error:"central_session_unbound"};
      }
    });
    assert.equal(resolved,1);
    assert.deepEqual(result,{ok:false,error:"central_session_unbound"});
  });
});

test("Forge Native verifies the signed OAuth token only once per open/resolve request",async()=>{
  await withIssuer(async()=>{
    const jwt=await token({client_id:FORGE_CLIENT});
    const verifyOriginal=crypto.subtle.verify.bind(crypto.subtle);
    const verifyDescriptor=Object.getOwnPropertyDescriptor(crypto.subtle,"verify");
    let verifies=0;
    Object.defineProperty(crypto.subtle,"verify",{
      configurable:true,
      value:async(...args:Parameters<SubtleCrypto["verify"]>)=>{
        verifies++;
        return verifyOriginal(...args);
      },
    });
    try {
      const opened=await openCentralSessionFromMcp(nativeRequest(jwt),enabled,{
        open:async()=>({ok:true,status:"awaiting_owner"}),
      });
      assert.equal(opened.status,202);
      assert.equal(verifies,1,"native open must not re-verify the token after marker validation");

      const resolved=await resolveCentralSessionFromMcp(nativeRequest(jwt),enabled,{
        resolve:async()=>({ok:true,device_id:DEVICE}),
      });
      assert.equal(resolved.ok,true);
      assert.equal(verifies,2,"native resolve must verify once, not twice");

      assert.equal(await centralSessionMarker(nativeRequest(jwt),enabled),
        "forge-native-v1:"+NONCE);
      assert.equal(verifies,3,"standalone marker still independently verifies OAuth");
    } finally {
      if(verifyDescriptor) Object.defineProperty(crypto.subtle,"verify",verifyDescriptor);
      else Reflect.deleteProperty(crypto.subtle,"verify");
    }
  });
});

test("native correlation keeps signed-client denial even with request-local proof reuse",async()=>{
  await withIssuer(async()=>{
    const clientMismatch=await token({client_id:OTHER_CLIENT});
    let opens=0,resolves=0;
    assert.equal((await openCentralSessionFromMcp(nativeRequest(clientMismatch),enabled,{
      open:async()=>{opens++;return {ok:true,status:"bound"};},
    })).status,409);
    assert.deepEqual(await resolveCentralSessionFromMcp(nativeRequest(clientMismatch),enabled,{
      resolve:async()=>{resolves++;return {ok:true,device_id:DEVICE};},
    }),{ok:false,error:"central_session_marker_required"});
    assert.equal(opens,0);
    assert.equal(resolves,0);
  });
});

test("ChatGPT correlation retains existing behavior without native rollout",async()=>{
  const jwt=await token();
  const req=new Request("https://mcp.ordax.com.br/mcp",{
    method:"POST",headers:{authorization:"Bearer "+jwt,
      "content-type":"application/json"},
    body:JSON.stringify({jsonrpc:"2.0",id:2,method:"tools/call",
      params:{name:"ordax_session",arguments:{},
        _meta:{"openai/session":"original-chatgpt-session-123"}}}),
  });
  assert.equal(await centralSessionMarker(req,env),
    "original-chatgpt-session-123");
});
