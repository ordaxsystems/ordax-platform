import test from "node:test";
import assert from "node:assert/strict";
import {
  centralSessionMarker,
  handleProductDeviceCentralSession,
  openCentralSessionFromMcp,
} from "../cloudflare/src/product_central_device_session.ts";
import { env, owner, client, token, withIssuer } from "./product_mcp_test_fixtures.mts";

const device="22222222-2222-4222-8222-222222222222";
const challenge="33333333-3333-4333-8333-333333333333";
const marker="openai-device-attested-session-20261015-A";
const rawDeviceToken="D".repeat(64);

function mcpRequest(jwt:string,session=marker,name="ordax_session"){
  return new Request("https://mcp.ordax.com.br/mcp",{
    method:"POST",
    headers:{authorization:"Bearer "+jwt,"content-type":"application/json"},
    body:JSON.stringify({jsonrpc:"2.0",id:7,method:"tools/call",params:{
      name,arguments:{device_id:"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
      _meta:{"openai/session":session},
    }}),
  });
}

test("provider marker is correlation only and parsed only from tools/call _meta",async()=>{
  const jwt=await token();
  assert.equal(await centralSessionMarker(mcpRequest(jwt)),marker);
  assert.equal(await centralSessionMarker(new Request("https://mcp.ordax.com.br/mcp",{
    method:"POST",headers:{"content-type":"application/json"},
    body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/list",params:{
      _meta:{"openai/session":marker},
    }}),
  })),null);
  assert.equal(await centralSessionMarker(mcpRequest(jwt,"bad marker with spaces")),null);
});

test("signed OAuth client opens challenge without trusting model device_id",async()=>{
  await withIssuer(async()=>{
    const jwt=await token();
    let observed:any=null;
    const response=await openCentralSessionFromMcp(mcpRequest(jwt),env,{
      open:async(_env,input)=>{
        observed=input;
        return {ok:true,status:"pending",device_id:device,
          challenge_id:challenge,expires_at:"2026-10-15T13:32:00Z"};
      },
    });
    assert.equal(response.status,202);
    assert.equal(observed.ownerUserId,owner);
    assert.equal(observed.clientId,client);
    assert.match(observed.sessionSha256,/^[0-9a-f]{64}$/);
    assert.equal(Object.prototype.hasOwnProperty.call(observed,"deviceId"),false,
      "model device_id must never cross into the challenge-open authority");
    const body:any=await response.json();
    assert.equal(body.device_id,device);
    assert.equal(body.challenge_id,challenge);
  });
});

test("offline session availability is a conflict with canonical device state, not an argument error", async () => {
  await withIssuer(async () => {
    const response = await openCentralSessionFromMcp(mcpRequest(await token()), env, {
      open: async () => ({ ok: false, error: "central_device_offline" }),
    });
    assert.equal(response.status, 409);
    assert.deepEqual(await response.json(), { ok: false, error: "central_device_offline" });
  });
});

test("missing provider marker fails closed before Postgres open",async()=>{
  await withIssuer(async()=>{
    const jwt=await token();
    let calls=0;
    const response=await openCentralSessionFromMcp(mcpRequest(jwt,"bad marker"),env,{
      open:async()=>{calls++;throw new Error("must not run");},
    });
    assert.equal(response.status,409);
    assert.equal(calls,0);
  });
});

test("device poll hashes raw token and never forwards raw credential",async()=>{
  let observed:any=null;
  const response=await handleProductDeviceCentralSession(new Request(
    "https://mcp.ordax.com.br/v3/product/device/central-session",{
      method:"GET",headers:{
        "X-Ordax-Device-Id":device,
        "X-Ordax-Device-Token":rawDeviceToken,
      },
    }),env,{
      poll:async(_env,input)=>{
        observed=input;
        return {ok:true,pending:true,challenge_id:challenge,
          expires_at:"2026-10-15T13:32:00Z"};
      },
    });
  assert.equal(response.status,200);
  assert.equal(observed.deviceId,device);
  assert.match(observed.tokenSha256,/^[0-9a-f]{64}$/);
  assert.notEqual(observed.tokenSha256,rawDeviceToken);
  assert.equal(JSON.stringify(observed).includes(rawDeviceToken),false);
});

test("exact device confirms only one canonical challenge id",async()=>{
  let observed:any=null;
  const response=await handleProductDeviceCentralSession(new Request(
    "https://mcp.ordax.com.br/v3/product/device/central-session",{
      method:"POST",headers:{
        "content-type":"application/json",
        "X-Ordax-Device-Id":device,
        "X-Ordax-Device-Token":rawDeviceToken,
      },
      body:JSON.stringify({challenge_id:challenge}),
    }),env,{
      confirm:async(_env,input)=>{
        observed=input;
        return {ok:true,status:"bound",device_id:device,
          request_id:challenge,expires_at:"2026-10-15T14:00:00Z"};
      },
    });
  assert.equal(response.status,200);
  assert.equal(observed.deviceId,device);
  assert.equal(observed.challengeId,challenge);
  assert.match(observed.tokenSha256,/^[0-9a-f]{64}$/);
});

test("device endpoint rejects malformed identity and extra confirmation fields",async()=>{
  const badAuth=await handleProductDeviceCentralSession(new Request(
    "https://mcp.ordax.com.br/v3/product/device/central-session",{
      method:"GET",headers:{"X-Ordax-Device-Id":device,"X-Ordax-Device-Token":"short"},
    }),env);
  assert.equal(badAuth.status,401);

  const extra=await handleProductDeviceCentralSession(new Request(
    "https://mcp.ordax.com.br/v3/product/device/central-session",{
      method:"POST",headers:{
        "content-type":"application/json",
        "X-Ordax-Device-Id":device,
        "X-Ordax-Device-Token":rawDeviceToken,
      },
      body:JSON.stringify({challenge_id:challenge,device_id:"model-controlled"}),
    }),env,{
      confirm:async()=>{throw new Error("must not run");},
    });
  assert.equal(extra.status,400);
});

