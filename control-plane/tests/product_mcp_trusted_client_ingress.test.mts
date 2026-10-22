import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

import {
  createCanonicalProductMcpGateway,
  PRODUCT_MCP_DIRECT_TOOLS,
  PRODUCT_OWNER_SESSION_PATH,
  PRODUCT_TRUSTED_CLIENT_HOSTNAME,
} from "../cloudflare/src/product_mcp_entry.ts";
import { PRODUCT_DEVICE_CENTRAL_SESSION_PATH } from "../cloudflare/src/product_central_device_session.ts";
import { PRODUCT_DEVICE_SETUP_PATH } from "../cloudflare/src/product_device_setup.ts";
import { PRODUCT_DEVICE_TRANSPORT_PREFIX } from "../cloudflare/src/product_device_transport.ts";
import {
  PRODUCT_OWNER_REMOTE_AUTHORITY_PATH,
  PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH,
} from "../cloudflare/src/product_owner_grant_admin.ts";
import { PRODUCT_OWNER_PROJECT_SCOPE_PATH } from "../cloudflare/src/product_owner_project_scope.ts";
import { PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH } from "../cloudflare/src/product_workspace_resource_api.ts";

const ENV = Object.freeze({
  PRODUCT_AUTH_ISSUER: "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1",
  PRODUCT_AUTH_AUDIENCE: "authenticated",
  PRODUCT_AUTH_JWKS_URL: "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1/.well-known/jwks.json",
  POSTGRES: { connectionString: "postgresql://localhost:6543/example" },
});

const DEVICE_ID = "22222222-2222-4222-8222-222222222222";
const trusted = (path: string, init?: RequestInit) =>
  new Request(`https://${PRODUCT_TRUSTED_CLIENT_HOSTNAME}${path}`, init);

const fakeReads = {
  session: async () => Response.json({ ok: true, authenticated: true }),
  targets: async () => Response.json({ ok: true, targets: [] }),
  getAction: async () => Response.json({ ok: false, error: "not_found" }, { status: 404 }),
};

test("workers.dev is a restricted trusted Product client ingress, not a second MCP", async () => {
  const config = await readFile(new URL("../cloudflare/wrangler.mcp.toml", import.meta.url), "utf8");
  assert.match(config, /workers_dev\s*=\s*true/);
  assert.match(config, /preview_urls\s*=\s*false/);
  assert.equal(PRODUCT_TRUSTED_CLIENT_HOSTNAME, "ordax-mcp.ordaxsystems.workers.dev");
});

test("trusted ingress hides every public or unrelated surface", async () => {
  const gateway = createCanonicalProductMcpGateway(ENV, fakeReads);
  const forbidden: Array<[string, RequestInit | undefined]> = [
    ["/health", undefined],
    ["/ready", undefined],
    ["/.well-known/oauth-protected-resource", undefined],
    ["/v3/product/targets", undefined],
    // Project scope is an authenticated Owner read used by Windows Studio,
    // not a public route. Only its exact path is admitted.
    [`${PRODUCT_OWNER_PROJECT_SCOPE_PATH}/unknown`, undefined],
    ["/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    }],
  ];
  for (const [path, init] of forbidden) {
    const response = await gateway(trusted(path, init));
    assert.equal(response.status, 404, path);
    assert.deepEqual(await response.json(), { ok: false, error: "not_found" }, path);
  }
});

test("trusted ingress reaches only authenticated Runtime and owner-grant handlers", async () => {
  const gateway = createCanonicalProductMcpGateway(ENV, fakeReads);
  const requests: Array<[string, RequestInit | undefined]> = [
    [PRODUCT_OWNER_SESSION_PATH, undefined],
    [`${PRODUCT_OWNER_PROJECT_SCOPE_PATH}?device_id=${DEVICE_ID}&repository_full_name=ordaxsystems%2Fordax-os`, undefined],
    [PRODUCT_DEVICE_SETUP_PATH, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    }],
    [PRODUCT_DEVICE_CENTRAL_SESSION_PATH, undefined],
    [`${PRODUCT_DEVICE_TRANSPORT_PREFIX}/heartbeat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ status: "online", agent_version: "test", capabilities: [] }),
    }],
    [`${PRODUCT_OWNER_REMOTE_AUTHORITY_PATH}?device_id=${DEVICE_ID}`, undefined],
    [PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    }],
    [`${PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH}/33333333-3333-4333-8333-333333333333?client_id=44444444-4444-4444-8444-444444444444`, {
      method: "DELETE",
    }],
    [PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    }],
    [`${PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH}/resource_abcdefgh12345678?client_id=33333333-3333-4333-8333-333333333333`, {
      method: "DELETE",
    }],
  ];

  for (const [path, init] of requests) {
    const response = await gateway(trusted(path, init));
    assert.notEqual(response.status, 404, path);
    assert.ok([400, 401, 403].includes(response.status), `${path}: ${response.status}`);
  }
});

test("canonical custom domain retains the full public MCP surface", async () => {
  const gateway = createCanonicalProductMcpGateway(ENV, fakeReads);
  const health = await gateway(new Request("https://mcp.ordax.com.br/health"));
  assert.equal(health.status, 200);

  const tools = await gateway(new Request("https://mcp.ordax.com.br/mcp", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  }));
  assert.equal(tools.status, 200);
  const json = await tools.json();
  assert.equal(json.result.tools.length, PRODUCT_MCP_DIRECT_TOOLS.size);
});
