import test from "node:test";
import assert from "node:assert/strict";
import { createCanonicalRelayReceiptVerifier } from "../cloudflare/src/product_relay_receipt.ts";
import {
  env, owner, otherOwner, client, otherClient, device, secondDevice,
  requestId, projectId, token, withIssuer, request, actionRecord,
} from "./product_mcp_test_fixtures.mts";

const allowed = Object.freeze({
  subjectId: owner, clientId: client, deviceId: device, projectId,
  allowedActions: ["project.text_read"],
});

test("canonical receipt: signed user + exact OAuth client + original device and project", async () => {
  await withIssuer(async () => {
    let calls = 0;
    const verify = createCanonicalRelayReceiptVerifier(env, {
      getAction: async (_, input) => {
        calls++;
        assert.deepEqual(input, {
          ownerUserId: owner, clientKind: "product-mcp", clientId: client, requestId,
        });
        return actionRecord();
      },
    });
    const req = request(await token(), `/v3/product/actions/${requestId}?device_id=${secondDevice}`);
    assert.equal(await verify(req, requestId, allowed), true);
    assert.equal(calls, 1);
  });
});

test("signed owner/client substitution and forged headers cannot reach the canonical RPC", async () => {
  await withIssuer(async () => {
    let reads = 0;
    const verify = createCanonicalRelayReceiptVerifier(env, {
      getAction: async () => { reads++; return actionRecord(); },
    });
    for (const [signedOwner, signedClient] of [
      [otherOwner, client], [owner, otherClient], [otherOwner, otherClient],
    ] as const) {
      const jwt = await token({sub:signedOwner,client_id:signedClient});
      assert.equal(await verify(request(jwt), requestId, allowed), false);
    }
    for (const claims of [
      {role:"anon"}, {client_id:undefined},
      {exp:Math.floor(Date.now()/1000)-3600},
    ]) {
      assert.equal(await verify(request(await token(claims)), requestId, allowed), false);
    }
    assert.equal(await verify(request("not-a-token"), requestId, allowed), false);
    assert.equal(reads, 0);
  });
});

test("cross-PC, wrong project, wrong capability and missing metadata fail closed", async () => {
  await withIssuer(async () => {
    const req = request(await token());
    let record = actionRecord();
    const verify = createCanonicalRelayReceiptVerifier(env, {
      getAction: async () => record,
    });
    for (const mutation of [
      {device_id: secondDevice},
      {project_id: null},
      {project_id: otherOwner},
      {capability:"terminal.exec"},
      {capability:"workspace.directory_list"},
      {request_id:secondDevice},
      {ok:false},
      {device_id:undefined},
      {project_id:undefined},
      {capability:undefined},
    ]) {
      record = actionRecord(mutation);
      assert.equal(await verify(req, requestId, allowed), false, JSON.stringify(mutation));
    }
    record = actionRecord();
    assert.equal(await verify(req, requestId, {...allowed,deviceId:secondDevice}), false);
    assert.equal(await verify(req, requestId, {...allowed,projectId:otherOwner}), false);
    assert.equal(await verify(req, requestId, {...allowed,allowedActions:["git.diff"]}), false);
    assert.equal(await verify(req, requestId, allowed), true);
  });
});

test("malformed request IDs and untrusted destination scopes never query authority", async () => {
  await withIssuer(async () => {
    let calls=0;
    const verify=createCanonicalRelayReceiptVerifier(env,{
      getAction: async()=>{calls++; return actionRecord();},
    });
    const req=request(await token());
    for(const badId of ["","x","../../private",requestId+"?owner=other"]){
      assert.equal(await verify(req,badId,allowed),false);
    }
    for(const scope of [
      {...allowed,clientId:""},
      {...allowed,subjectId:"untrusted"},
      {...allowed,deviceId:"other-device"},
      {...allowed,projectId:"not-canonical"},
      {...allowed,allowedActions:[]},
      {...allowed,allowedActions:["project.text_read","project.text_read"]},
      {...allowed,allowedActions:["computer.type\n"]},
    ]) {
      assert.equal(await verify(req,requestId,scope),false);
    }
    assert.equal(calls,0);
  });
});

test("no action for other owner or exact client and database outages deny without disclosure",async()=>{
  await withIssuer(async()=>{
    const jwt=await token();
    const req=request(jwt);
    const notFound=createCanonicalRelayReceiptVerifier(env,{getAction:async()=>null});
    assert.equal(await notFound(req,requestId,allowed),false);
    const denied=createCanonicalRelayReceiptVerifier(env,{
      getAction:async()=>({ok:false,error:"product_owner_auth_ineligible"}),
    });
    assert.equal(await denied(req,requestId,allowed),false);
    const down=createCanonicalRelayReceiptVerifier(env,{
      getAction:async()=>{throw Error("private database password host");},
    });
    assert.equal(await down(req,requestId,allowed),false);
  });
});
