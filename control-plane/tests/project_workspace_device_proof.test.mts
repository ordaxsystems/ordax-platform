import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { randomUUID } from "node:crypto";
import {
  canonicalDeviceWorkspaceProofQuery,
  projectWorkspaceVerifierResponse,
  handleProductDeviceTransport,
} from "../cloudflare/src/product_device_transport.ts";

const device = randomUUID();
const owner = randomUUID();
const actor = randomUUID();
const client = randomUUID();
const space = randomUUID();
const project = randomUUID();
const resource = "resource_" + randomUUID().replaceAll("-", "");
const required = {
  owner_user_id: owner, actor_id: actor, client_id: client,
  lab_project_id: "lab_one", workspace_session_id: "session_one",
  resource_id: resource,
};
const scope = canonicalDeviceWorkspaceProofQuery(required, device);
assert.ok(scope);
const issued = new Date(Date.now() - 5 * 60 * 1000).toISOString();
const expires = new Date(Date.now() + 55 * 60 * 1000).toISOString();
const row = {
  grant_id: randomUUID(), owner_user_id: owner, space_id: space,
  project_id: project, lab_project_id: "lab_one", actor_id: actor,
  client_id: client, workspace_session_id: "session_one",
  device_id: device, resource_id: resource,
  allowed_actions: ["read"], issued_by: "trusted-runtime-picker",
  issued_at: issued, valid_until: expires, revoked_at: null, active: true,
};
const wrap = (grant: unknown) => ({
  ok: true, schema: "ordax.project-workspace-resource/1", grant,
});

test("device workspace proof uses only authenticated device identity", () => {
  assert.deepEqual(scope, {
    ownerUserId: owner, actorId: actor, clientId: client, labProjectId: "lab_one",
    workspaceSessionId: "session_one", deviceId: device, resourceId: resource,
  });
  assert.equal(Object.isFrozen(scope), true);
  assert.equal(canonicalDeviceWorkspaceProofQuery(required, randomUUID())?.deviceId === device, false);
  for (const [field, bad] of [
    ["owner_user_id", "not_owner"], ["actor_id", "actor"], ["client_id", "client"],
    ["resource_id", "C:\\Users\\private"], ["lab_project_id", "../lab"],
    ["workspace_session_id", "session with space"],
  ] as const) {
    assert.equal(canonicalDeviceWorkspaceProofQuery({...required, [field]: bad},device),null,field);
  }
  for(const forbidden of [
    { device_id: device }, { space_id: space }, { project_id: project },
    { path: "C:\\Users\\Private" }, { token: "secret" }, { grant: { active: true } },
    { action: "read" }, { allowed_actions: ["read"] },
  ]) assert.equal(canonicalDeviceWorkspaceProofQuery({...required,...forbidden},device),null,
    JSON.stringify(forbidden));
  for(const key of Object.keys(required)) {
    const fewer = {...required};
    delete (fewer as Record<string,unknown>)[key];
    assert.equal(canonicalDeviceWorkspaceProofQuery(fewer,device),null,key);
  }
  assert.equal(canonicalDeviceWorkspaceProofQuery(required,"invalid"),null);
  assert.equal(canonicalDeviceWorkspaceProofQuery([required],device),null);
  assert.equal(canonicalDeviceWorkspaceProofQuery(null,device),null);
});

test("only exact canonical PostgreSQL row is projected to device reply", () => {
  const accepted = projectWorkspaceVerifierResponse(wrap(row),scope);
  assert.ok(accepted);
  assert.deepEqual(accepted,wrap(row));
  assert.deepEqual(Object.keys(accepted),["ok","schema","grant"]);

  for(const [field,bad] of [
    ["owner_user_id", randomUUID()], ["space_id", "invalid"],
    ["project_id", "invalid"], ["lab_project_id", "other_lab"],
    ["actor_id", randomUUID()], ["client_id", randomUUID()],
    ["workspace_session_id", "other_session"],
    ["device_id", randomUUID()], ["resource_id","resource_"+randomUUID().replaceAll("-","")],
    ["grant_id", "not_uuid"], ["active", false], ["active", 1],
    ["revoked_at", new Date().toISOString()],
    ["issued_by", "model"], ["allowed_actions", ["read","write"]],
    ["allowed_actions", ["write"]], ["allowed_actions", "read"],
  ] as const) {
    const modified={...row,[field]:bad};
    assert.equal(projectWorkspaceVerifierResponse(wrap(modified),scope),null,field);
  }
  const additional = {...row,path:"C:\\Users\\Private"};
  assert.equal(projectWorkspaceVerifierResponse(wrap(additional),scope),null);
  for(const field of Object.keys(row)) {
    const missing={...row} as Record<string,unknown>;
    delete missing[field];
    assert.equal(projectWorkspaceVerifierResponse(wrap(missing),scope),null,"missing "+field);
  }
  assert.equal(projectWorkspaceVerifierResponse(null,scope),null);
  assert.equal(projectWorkspaceVerifierResponse({...wrap(row),extra:"bearer"},scope),null);
  assert.equal(projectWorkspaceVerifierResponse({...wrap(row),schema:"different"},scope),null);
  assert.equal(projectWorkspaceVerifierResponse({...wrap(row),ok:false},scope),null);
  assert.equal(projectWorkspaceVerifierResponse({...wrap(row),grant:[row]},scope),null);
});

test("workspace proof checks original TTL and current status, not remaining TTL alone", () => {
  const now=Date.now();
  assert.equal(projectWorkspaceVerifierResponse(wrap({
    ...row,issued_at:new Date(now-26*60*60*1000).toISOString(),
    valid_until:new Date(now+30*60*1000).toISOString(),
  }),scope),null,"expired original lifetime");
  assert.equal(projectWorkspaceVerifierResponse(wrap({
    ...row,valid_until:new Date(now-1000).toISOString(),
  }),scope),null,"revoked by expiry");
  assert.equal(projectWorkspaceVerifierResponse(wrap({
    ...row,issued_at:new Date(now+60*1000).toISOString(),
  }),scope),null,"not yet issued");
});

test("workspace endpoint is default-off, uses the existing device transport and never trusts model fields", async () => {
  const path="/v3/device/transport/workspace-proof";
  const env={} as any;
  const unauth = await handleProductDeviceTransport(new Request(
    "https://mcp.example"+path, {method:"POST",
      headers:{"content-type":"application/json"},body:JSON.stringify(required)},
  ),env);
  assert.equal(unauth.status,401);
  assert.equal((await unauth.json() as any).error,"device_auth_required");
  const get=await handleProductDeviceTransport(new Request("https://mcp.example"+path),env);
  assert.equal(get.status,405);
  const transport=fs.readFileSync(new URL("../cloudflare/src/product_device_transport.ts",import.meta.url),"utf8");
  const store=fs.readFileSync(new URL("../cloudflare/src/product_postgres_store.ts",import.meta.url),"utf8");
  assert.match(transport,/WORKSPACE_RESOURCE_VERIFIER_ENABLED !== "enabled"/);
  assert.match(transport,/authenticateProductDeviceRequest\(request, env\)/);
  assert.match(transport,/path === PRODUCT_DEVICE_TRANSPORT_PREFIX \+ "\/workspace-proof"/);
  assert.match(store,/ordax_verify_project_workspace_resource_v1/);
  assert.match(store,/p_device_id: input\.deviceId/);
  for(const forbidden of ["D1Database","R2Bucket","ORDAX_OPERATOR_TOKEN","env.DB"]) {
    assert.equal(transport.includes(forbidden),false,forbidden);
  }
});
