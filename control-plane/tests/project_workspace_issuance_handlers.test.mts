import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { randomUUID } from "node:crypto";
import {
  canonicalOwnerWorkspaceApproval,
  canonicalDeviceWorkspaceConfirmation,
} from "../cloudflare/src/project_workspace_issue_contract.ts";
import { handleProductOwnerGrantAdmin } from "../cloudflare/src/product_owner_grant_admin.ts";
import { handleProductDeviceTransport } from "../cloudflare/src/product_device_transport.ts";

const id = () => randomUUID();
const owner = {
  client_id: id(), lab_project_id: "lab_one", space_id: id(), project_id: id(),
  device_id: id(), actor_id: id(), workspace_session_id: "session_one",
  resource_id: "resource_" + id().replaceAll("-", ""), intent_id: id(),
};
const device = {
  intent_id: owner.intent_id, actor_id: owner.actor_id, client_id: owner.client_id,
  workspace_session_id: owner.workspace_session_id, resource_id: owner.resource_id,
};
test("Owner approval shape must contain all exact IDs; no injected Owner or path", () => {
  const parsed = canonicalOwnerWorkspaceApproval(owner);
  assert.deepEqual(parsed, {
    clientId: owner.client_id, labProjectId: "lab_one", spaceId: owner.space_id,
    projectId: owner.project_id, deviceId: owner.device_id,
    actorId: owner.actor_id, workspaceSessionId: owner.workspace_session_id,
    resourceId: owner.resource_id, intentId: owner.intent_id,
  });
  assert.equal(Object.isFrozen(parsed),true);
  for(const value of [null,[],{}, {...owner,owner_user_id:id()},
    {...owner,path:"C:\\Private"}, {...owner,token:"secret"}, {...owner,grant:true},
    {...owner,allowed_actions:["read"]}, {...owner,profile_key:"full-computer-control"}])
    assert.equal(canonicalOwnerWorkspaceApproval(value),null);
  for(const [field,value] of [
    ["client_id","not-uuid"],["lab_project_id","../private"],
    ["space_id",id().slice(0,8)],["project_id","other"],
    ["device_id","not-device"],["actor_id","not-actor"],
    ["workspace_session_id","session with spaces"],
    ["resource_id","C:/private"],["intent_id","guess"],
  ] as const)
    assert.equal(canonicalOwnerWorkspaceApproval({...owner,[field]:value}),null,field);
  for(const field of Object.keys(owner)){
    const dropped={...owner} as Record<string,unknown>;
    delete dropped[field];
    assert.equal(canonicalOwnerWorkspaceApproval(dropped),null,field);
  }
});
test("Device confirmation request cannot pick Owner, device, Space, project or filesystem path", () => {
  const parsed=canonicalDeviceWorkspaceConfirmation(device);
  assert.deepEqual(parsed,{
    intentId:device.intent_id,actorId:device.actor_id,clientId:device.client_id,
    workspaceSessionId:device.workspace_session_id,resourceId:device.resource_id,
  });
  assert.equal(Object.isFrozen(parsed),true);
  for(const bad of [null,[],{}, {...device,owner_user_id:id()},
    {...device,device_id:id()}, {...device,space_id:id()},
    {...device,project_id:id()}, {...device,lab_project_id:"lab_one"},
    {...device,path:"/Users/private"}, {...device,token:"secret"},
    {...device,grant_id:id()}, {...device,write:true}])
    assert.equal(canonicalDeviceWorkspaceConfirmation(bad),null);
  for(const field of Object.keys(device)){
    const dropped={...device} as Record<string,unknown>;
    delete dropped[field];
    assert.equal(canonicalDeviceWorkspaceConfirmation(dropped),null,field);
  }
  for(const [field,value] of [
    ["intent_id","not-uuid"],["actor_id","not-uuid"],["client_id","not-uuid"],
    ["resource_id","../private"],["workspace_session_id","contains space"],
  ] as const)
    assert.equal(canonicalDeviceWorkspaceConfirmation({...device,[field]:value}),null,field);
});
test("both staged handlers fail closed without signed Owner or enrolled Device", async () => {
  const env={ PRODUCT_AUTH_ISSUER:"https://issuer.example/auth/v1",
    PRODUCT_AUTH_AUDIENCE:"authenticated",
    PRODUCT_AUTH_JWKS_URL:"https://issuer.example/auth/v1/.well-known/jwks.json",
  } as any;
  const signedOwnerOnly="/v3/owner/workspace-resources/approvals";
  const response=await handleProductOwnerGrantAdmin(new Request(
    "https://mcp.example"+signedOwnerOnly,{
      method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(owner),
    }),env);
  assert.equal(response.status,401);
  assert.equal((await response.json() as any).ok,false);
  const devicePath="/v3/device/transport/workspace-confirm";
  const unauth=await handleProductDeviceTransport(new Request(
    "https://mcp.example"+devicePath,{
      method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(device),
    }),env);
  assert.equal(unauth.status,401);
  assert.equal((await unauth.json() as any).error,"device_auth_required");
  const get=await handleProductDeviceTransport(new Request(
    "https://mcp.example"+devicePath),env);
  assert.equal(get.status,405);
});
test("issuance stays separately disabled, reuses only the canonical Postgres grant ledger", () => {
  const src=(path:string)=>fs.readFileSync(new URL(path,import.meta.url),"utf8");
  const ownerSource=src("../cloudflare/src/product_owner_grant_admin.ts");
  const deviceSource=src("../cloudflare/src/product_device_transport.ts");
  const store=src("../cloudflare/src/product_postgres_store.ts");
  for(const source of [ownerSource,deviceSource]){
    assert.match(source,/WORKSPACE_RESOURCE_VERIFIER_ENABLED !== "enabled"/);
    assert.match(source,/WORKSPACE_RESOURCE_ISSUANCE_ENABLED !== "enabled"/);
    for(const forbidden of ["D1Database","ORDAX_OPERATOR_TOKEN","env.DB"])
      assert.equal(source.includes(forbidden),false,forbidden);
  }
  assert.equal(ownerSource.includes("owner(request, env)"),true);
  assert.match(ownerSource,/canonicalOwnerWorkspaceApproval\(body\)/);
  assert.match(ownerSource,/ownerUserId: ownerId/);
  assert.match(deviceSource,/authenticateDeviceRequest\(request, env\)/);
  assert.match(deviceSource,/canonicalDeviceWorkspaceConfirmation\(body\)/);
  assert.match(deviceSource,/deviceId, \.\.\.input/);
  for(const spec of ["ordax_approve_project_workspace_resource_v1",
                     "ordax_commit_project_workspace_resource_v1"])
    assert.match(store,new RegExp(spec));
  assert.match(store,/callRpc<boolean>\(env/);
  assert.equal(store.includes("insert into private.ordax_workspace"),false);
});
