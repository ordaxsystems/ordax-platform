import test from "node:test";
import assert from "node:assert/strict";
import {
  centralSessionMarker,
  handleProductDeviceCentralSession,
  openCentralSessionFromMcp,
  resolveCentralSessionFromMcp,
} from "../cloudflare/src/product_central_device_session.ts";
import { env, owner, client, token, withIssuer } from "./product_mcp_test_fixtures.mts";
import { MAX_MCP_REQUEST_BYTES } from "../cloudflare/src/mcp_http.ts";

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

test("oversized but valid tools/call JSON cannot supply a session marker or open/resolve challenge", async () => {
  const jwt = await token();
  const payload = JSON.stringify({
    jsonrpc: "2.0", id: 7, method: "tools/call",
    params: { name: "ordax_session", _meta: { "openai/session": marker } },
    padding: "x".repeat(MAX_MCP_REQUEST_BYTES),
  });
  assert.ok(new TextEncoder().encode(payload).byteLength > MAX_MCP_REQUEST_BYTES);
  const oversized = () => new Request("https://mcp.ordax.com.br/mcp", {
    method: "POST",
    headers: { authorization: "Bearer " + jwt, "content-type": "application/json" },
    body: payload,
  });
  assert.equal(await centralSessionMarker(oversized()), null);
  let opened = 0, resolved = 0;
  const failedOpen = await openCentralSessionFromMcp(oversized(), env, {
    open: async () => {
      opened++;
      throw new Error("oversized body must not open an Owner challenge");
    },
  });
  assert.equal(failedOpen.status, 409);
  assert.deepEqual(await failedOpen.json(), { ok: false, error: "central_session_marker_required" });
  const failedResolve = await resolveCentralSessionFromMcp(oversized(), env, {
    resolve: async () => {
      resolved++;
      throw new Error("oversized body must not resolve a challenge");
    },
  });
  assert.deepEqual(failedResolve, { ok: false, error: "central_session_marker_required" });
  assert.equal(opened, 0);
  assert.equal(resolved, 0);
});

test("invalid RPC IDs and malformed arguments cannot open a Central session", async () => {
  const jwt = await token();
  const params = { name: "ordax_session", arguments: {},
    _meta: { "openai/session": marker } };
  const invalid = [
    { jsonrpc: "2.0", method: "tools/call", params },
    { jsonrpc: "2.0", id: null, method: "tools/call", params },
    { jsonrpc: "2.0", id: true, method: "tools/call", params },
    { jsonrpc: "2.0", id: [], method: "tools/call", params },
    { jsonrpc: "2.0", id: 1.25, method: "tools/call", params },
    { jsonrpc: "2.0", id: 9, method: "tools/call", params: { ...params, arguments: null } },
    { jsonrpc: "2.0", id: 9, method: "tools/call", params: { ...params, arguments: [] } },
    { jsonrpc: "2.0", id: 9, method: "tools/call", params: { ...params, arguments: "invalid" } },
  ];
  let opened = 0;
  for (const payload of invalid) {
    const makeRequest = () => new Request("https://mcp.ordax.com.br/mcp", {
      method: "POST", headers: { authorization: "Bearer " + jwt, "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    assert.equal(await centralSessionMarker(makeRequest()), null);
    const response = await openCentralSessionFromMcp(makeRequest(), env, {
      open: async () => {
        opened++;
        throw new Error("invalid JSON-RPC envelope must not open a Central challenge");
      },
    });
    assert.equal(response.status, 409);
    assert.equal((await response.json()).error, "central_session_marker_required");
  }
  assert.equal(opened, 0);
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

test("discovery-only online device reports missing action Runtime rather than opening a Central challenge", async () => {
  await withIssuer(async () => {
    const response = await openCentralSessionFromMcp(mcpRequest(await token()), env, {
      open: async () => ({ ok: false, error: "central_device_runtime_not_ready" }),
    });
    assert.equal(response.status, 409);
    assert.deepEqual(await response.json(), {
      ok: false, error: "central_device_runtime_not_ready",
    });
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

