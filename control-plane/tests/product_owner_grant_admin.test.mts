import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  handleProductOwnerGrantAdmin, parseOwnerWorkspaceResourceRevocation,
} from "../cloudflare/src/product_owner_grant_admin.ts";
import {
  OWNER_MCP_GRANT_PROFILES,
  productCapabilityAccessMode,
} from "../cloudflare/src/product_owner_grant_profiles.ts";
import {
  COMPUTER_DEVICE_ACTIONS,
  OBSERVE_COMPUTER_CONTROL_MODE,
  TEXT_EDIT_COMPUTER_CONTROL_MODE,
  PROJECT_BROWSER_ACTIONS,
} from "../cloudflare/src/product_action_scope.ts";

const HERE=path.dirname(fileURLToPath(import.meta.url));

test("owner grant profiles are explicit and observation remains least privilege", () => {
  const full=OWNER_MCP_GRANT_PROFILES["full-computer-control"];
  assert.equal(full.scope,"device");
  assert.deepEqual(full.capabilities.map((item)=>item.capability), [...COMPUTER_DEVICE_ACTIONS].sort());
  assert.equal(productCapabilityAccessMode("computer.screenshot"),"read");
  assert.equal(productCapabilityAccessMode("computer.click"),"write");

  const observe=OWNER_MCP_GRANT_PROFILES[OBSERVE_COMPUTER_CONTROL_MODE];
  assert.equal(observe.scope,"device");
  assert.deepEqual(observe.capabilities, [
    {capability:"computer.access_status",accessMode:"read"},
    {capability:"computer.active_window",accessMode:"read"},
    {capability:"computer.processes",accessMode:"read"},
    {capability:"computer.screen_info",accessMode:"read"},
    {capability:"computer.windows",accessMode:"read"},
  ]);
  assert.equal(observe.capabilities.some((item)=>[
    "computer.click","computer.screenshot","computer.terminate_process","computer.type",
  ].includes(item.capability)),false);

  const textEdit=OWNER_MCP_GRANT_PROFILES[TEXT_EDIT_COMPUTER_CONTROL_MODE];
  assert.equal(textEdit.scope,"device");
  assert.deepEqual(textEdit.capabilities, [
    {capability:"computer.directory_list",accessMode:"read"},
    {capability:"computer.file_stat",accessMode:"read"},
    {capability:"computer.text_patch",accessMode:"write"},
    {capability:"computer.text_read",accessMode:"read"},
    {capability:"computer.text_write",accessMode:"write"},
  ]);
  for (const excluded of [
    "computer.path_remove", "computer.path_move", "computer.terminate_process",
    "computer.clipboard_read", "computer.click", "computer.screenshot",
  ]) {
    assert.equal(textEdit.capabilities.some(item => item.capability===excluded), false);
  }

  const browser=OWNER_MCP_GRANT_PROFILES["project-browser-automation"];
  assert.equal(browser.scope,"project");
  assert.deepEqual(browser.capabilities.map((item)=>item.capability), [...PROJECT_BROWSER_ACTIONS].sort());
  assert.equal(productCapabilityAccessMode("browser.snapshot"),"read");
  assert.equal(productCapabilityAccessMode("browser.navigate"),"write");
  const workspace=OWNER_MCP_GRANT_PROFILES["project-workspace-read"];
  assert.equal(workspace.scope,"project");
  assert.deepEqual(workspace.capabilities,[{
    capability:"workspace.project_snapshot",accessMode:"read",
  }]);
  assert.equal(productCapabilityAccessMode("workspace.project_snapshot"),"read");
  assert.equal(workspace.capabilities.some(item=>item.accessMode==="write"),false);
  assert.equal(workspace.capabilities.some(item=>item.capability.startsWith("computer.")),false);
});

test("owner grant admin fails closed before database access without signed owner session", async () => {
  const env={PRODUCT_AUTH_ISSUER:"https://issuer.example/auth/v1",PRODUCT_AUTH_AUDIENCE:"authenticated",PRODUCT_AUTH_JWKS_URL:"https://issuer.example/auth/v1/.well-known/jwks.json"} as any;
  const get=await handleProductOwnerGrantAdmin(new Request(
    "https://mcp.example/v3/owner/remote-authority?device_id=11111111-1111-4111-8111-111111111111",
  ),env);
  assert.equal(get.status,401);
  const post=await handleProductOwnerGrantAdmin(new Request(
    "https://mcp.example/v3/owner/remote-grant-groups",
    {method:"POST",headers:{"content-type":"application/json"},body:"{}"},
  ),env);
  assert.equal(post.status,401);
});

test("owner grant source contains no device-link or pairing authority", () => {
  const source=fs.readFileSync(path.resolve(HERE,"../cloudflare/src/product_owner_grant_admin.ts"),"utf8")
    +fs.readFileSync(path.resolve(HERE,"../cloudflare/src/product_owner_grant_profiles.ts"),"utf8");
  for (const forbidden of ["device-link","pairing_secret","claim_device_pairing","ORDAX_OPERATOR_TOKEN","D1Database"])
    assert.equal(source.includes(forbidden),false,forbidden);
  for (const required of ["replaceOwnerMcpGrantGroup","revokeOwnerMcpGrantGroup","ownerMcpGrantProfile"])
    assert.equal(source.includes(required),true,required);
});

test("Owner workspace revocation only accepts exact opaque resource and consented client identifiers", async () => {
  const resource="resource_"+"a".repeat(32);
  const client="11111111-1111-4111-8111-111111111111";
  const root="https://mcp.example/v3/owner/workspace-resources/";
  const parse=(suffix: string) => parseOwnerWorkspaceResourceRevocation(new URL(root+suffix));
  assert.deepEqual(parse(resource+"?client_id="+client),{clientId:client,resourceId:resource});
  for(const query of [
    resource,
    resource+"?client_id=invalid",
    resource+"?client_id="+client+"&client_id="+client,
    resource+"?client_id="+client+"&owner_user_id="+client,
    resource+"?client_id="+client+"&path=private",
    "resource_"+ "a".repeat(7)+"?client_id="+client,
    "resource_"+ "a".repeat(161)+"?client_id="+client,
    "path%2Fprivate?client_id="+client,
    "../private?client_id="+client,
    resource+"/extra?client_id="+client,
  ]) assert.equal(parse(query),null,query);
  assert.equal(parseOwnerWorkspaceResourceRevocation(new URL(
    "https://mcp.example/v3/owner/remote-authority?client_id="+client
  )),null);

  const env={
    PRODUCT_AUTH_ISSUER:"https://issuer.example/auth/v1",
    PRODUCT_AUTH_AUDIENCE:"authenticated",
    PRODUCT_AUTH_JWKS_URL:"https://issuer.example/auth/v1/.well-known/jwks.json",
  } as any;
  const unauth=await handleProductOwnerGrantAdmin(new Request(
    root+resource+"?client_id="+client,{method:"DELETE"},
  ),env);
  assert.equal(unauth.status,401);
  assert.deepEqual(await unauth.json(),{ok:false,error:"product_auth_required"});

  const source=fs.readFileSync(path.resolve(HERE,"../cloudflare/src/product_owner_grant_admin.ts"),"utf8");
  const store=fs.readFileSync(path.resolve(HERE,"../cloudflare/src/product_postgres_store.ts"),"utf8");
  assert.match(source,/WORKSPACE_RESOURCE_VERIFIER_ENABLED !== "enabled"/);
  assert.match(source,/revokeProjectWorkspaceResource\(env/);
  assert.match(store,/ordax_revoke_project_workspace_resource_v1/);
  assert.ok(!source.includes("issueProjectWorkspaceResource"));
});
