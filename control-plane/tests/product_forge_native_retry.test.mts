import assert from "node:assert/strict";
import test from "node:test";
import {verifiedMcpRetryDigest} from "../cloudflare/src/mcp_http.ts";

const CLIENT="6a94ae80-a59c-4f48-a32c-2e15da34374f";
const DEVICE="22222222-2222-4222-8222-222222222222";
const SESSION="A".repeat(43);
const session={session:{client_id:CLIENT}};
const params=(id=SESSION,args={})=>({
  name:"computer_terminal_exec",
  arguments:{device_id:DEVICE,argv:["git","status"],wait_for_completion_ms:0,...args},
  _meta:{"ordax/native-session":id},
});
const digest=(p:any,id:string|number="forge-task-1",verified?:string)=>
  verifiedMcpRetryDigest(session,id,p,verified);

test("Forge native retry is never derived from an unverified marker",async()=>{
  assert.equal(await digest(params()),null);
  assert.equal(await digest(params(),1,"not-a-uuid"),null);
  assert.equal(await digest(params(),1,
    "202fd3e1-b058-4531-8750-82c57e4b6ca0"),null);
  assert.equal(await verifiedMcpRetryDigest(
    {session:{client_id:"not-a-uuid"}},1,params(),CLIENT),null);
});

test("Runtime-attested native client gets domain-separated stable retry correlation",async()=>{
  const first=await digest(params(),"same-id",CLIENT);
  const stable=await digest({name:"computer_terminal_exec",
    _meta:{"ordax/native-session":SESSION},
    arguments:{argv:["git","status"],device_id:DEVICE,
      wait_for_completion_ms:16000}}, "same-id",CLIENT);
  assert.match(first??"",/^[a-f0-9]{64}$/);
  assert.equal(first,stable,"only the wait budget changed; cannot enqueue twice");
  assert.notEqual(first,await digest(params(SESSION,{argv:["git","diff"]}),"same-id",CLIENT));
  assert.notEqual(first,await digest(params("B".repeat(43)),"same-id",CLIENT));
  assert.notEqual(first,await digest(params(),"different-id",CLIENT));
  assert.notEqual(first,await digest(params(),11,CLIENT));
});

test("Native and ChatGPT retry digest namespaces cannot collide",async()=>{
  const native=await digest(params(),1,CLIENT);
  const chatgpt=await digest({
    name:"computer_terminal_exec",
    arguments:{device_id:DEVICE,argv:["git","status"]},
    _meta:{"openai/session":"chatgpt-attested-session-123"},
  },1);
  assert.match(native??"",/^[a-f0-9]{64}$/);
  assert.match(chatgpt??"",/^[a-f0-9]{64}$/);
  assert.notEqual(native,chatgpt);
});

test("Ambiguous, malformed or spoofed native metadata fails closed",async()=>{
  for(const bad of [
    {...params(),_meta:{"ordax/native-session":SESSION,
      "openai/session":"chatgpt-attested-session-123"}},
    params("too-short"),
    params("X".repeat(42)+"!"),
    params("=".repeat(43)),
  ]){
    assert.equal(await digest(bad,1,CLIENT),null);
  }
  // A valid ChatGPT marker must not bypass a forged native marker.
  assert.equal(await digest({...params(),_meta:{
    "openai/session":"chatgpt-attested-session-123",
    "ordax/native-session":"bad"
  }},1,CLIENT),null);
});

test("Native retry identity includes exact device, RPC id type and effect arguments",async()=>{
  const first=await digest(params(),7,CLIENT);
  const reordered=await digest({name:"computer_terminal_exec",
    arguments:{wait_for_completion_ms:2000,argv:["git","status"],
      device_id:DEVICE},_meta:{"ordax/native-session":SESSION}},7,CLIENT);
  assert.equal(first,reordered);
  assert.notEqual(first,await digest(params(), "7",CLIENT));
  assert.notEqual(first,await digest(params(SESSION,{
    device_id:"33333333-3333-4333-8333-333333333333"
  }),7,CLIENT));
});
