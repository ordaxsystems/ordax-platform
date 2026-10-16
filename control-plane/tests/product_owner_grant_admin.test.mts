import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { handleProductOwnerGrantAdmin } from "../cloudflare/src/product_owner_grant_admin.ts";
import {
  OWNER_MCP_GRANT_PROFILES,
  productCapabilityAccessMode,
} from "../cloudflare/src/product_owner_grant_profiles.ts";
import { COMPUTER_DEVICE_ACTIONS, PROJECT_BROWSER_ACTIONS } from "../cloudflare/src/product_action_scope.ts";

const HERE=path.dirname(fileURLToPath(import.meta.url));

test("owner grant profiles are explicit and full-computer-control covers canonical device actions", () => {
  const full=OWNER_MCP_GRANT_PROFILES["full-computer-control"];
  assert.equal(full.scope,"device");
  assert.deepEqual(full.capabilities.map((item)=>item.capability), [...COMPUTER_DEVICE_ACTIONS].sort());
  assert.equal(productCapabilityAccessMode("computer.screenshot"),"read");
  assert.equal(productCapabilityAccessMode("computer.click"),"write");
  const browser=OWNER_MCP_GRANT_PROFILES["project-browser-automation"];
  assert.equal(browser.scope,"project");
  assert.deepEqual(browser.capabilities.map((item)=>item.capability), [...PROJECT_BROWSER_ACTIONS].sort());
  assert.equal(productCapabilityAccessMode("browser.snapshot"),"read");
  assert.equal(productCapabilityAccessMode("browser.navigate"),"write");
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

