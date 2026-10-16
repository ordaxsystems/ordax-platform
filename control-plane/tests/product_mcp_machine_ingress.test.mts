import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

import {
  createCanonicalProductMcpGateway,
  PRODUCT_DEVICE_MACHINE_HOSTNAME,
} from "../cloudflare/src/product_mcp_entry.ts";
import { PRODUCT_DEVICE_CENTRAL_SESSION_PATH } from "../cloudflare/src/product_central_device_session.ts";
import { PRODUCT_DEVICE_SETUP_PATH } from "../cloudflare/src/product_device_setup.ts";
import { PRODUCT_DEVICE_TRANSPORT_PREFIX } from "../cloudflare/src/product_device_transport.ts";

const ENV = Object.freeze({
  PRODUCT_AUTH_ISSUER: "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1",
  PRODUCT_AUTH_AUDIENCE: "authenticated",
  PRODUCT_AUTH_JWKS_URL: "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1/.well-known/jwks.json",
  POSTGRES: { connectionString: "postgresql://localhost:6543/example" },
});

const machine = (path: string, init?: RequestInit) =>
  new Request(`https://${PRODUCT_DEVICE_MACHINE_HOSTNAME}${path}`, init);

const fakeReads = {
  session: async () => Response.json({ ok: true, authenticated: true }),
  targets: async () => Response.json({ ok: true, targets: [] }),
  getAction: async () => Response.json({ ok: false, error: "not_found" }, { status: 404 }),
};

test("workers.dev is enabled only for the Runtime machine ingress", async () => {
  const config = await readFile(new URL("../cloudflare/wrangler.mcp.toml", import.meta.url), "utf8");
  assert.match(config, /workers_dev\s*=\s*true/);
  assert.match(config, /preview_urls\s*=\s*false/);
  assert.equal(PRODUCT_DEVICE_MACHINE_HOSTNAME, "ordax-mcp.ordaxsystems.workers.dev");
});

test("machine ingress never exposes MCP, OAuth metadata, owner APIs, health or device setup", async () => {
  const gateway = createCanonicalProductMcpGateway(ENV, fakeReads);
  const forbidden: Array<[string, RequestInit | undefined]> = [
    ["/health", undefined],
    ["/ready", undefined],
    ["/.well-known/oauth-protected-resource", undefined],
    ["/v3/product/session", undefined],
    [PRODUCT_DEVICE_SETUP_PATH, { method: "POST" }],
    ["/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    }],
  ];
  for (const [path, init] of forbidden) {
    const response = await gateway(machine(path, init));
    assert.equal(response.status, 404, path);
    assert.deepEqual(await response.json(), { ok: false, error: "not_found" }, path);
  }
});

test("machine ingress reaches only credential-protected central-session and device transport handlers", async () => {
  const gateway = createCanonicalProductMcpGateway(ENV, fakeReads);

  const central = await gateway(machine(PRODUCT_DEVICE_CENTRAL_SESSION_PATH));
  assert.notEqual(central.status, 404);
  assert.ok([401, 403].includes(central.status), `central session status ${central.status}`);

  const heartbeat = await gateway(machine(`${PRODUCT_DEVICE_TRANSPORT_PREFIX}/heartbeat`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ status: "online", agent_version: "test", capabilities: [] }),
  }));
  assert.notEqual(heartbeat.status, 404);
  assert.ok([400, 401, 403].includes(heartbeat.status), `transport status ${heartbeat.status}`);
});

test("canonical custom domain keeps the normal public MCP surface", async () => {
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
  assert.equal(json.result.tools.length, 18);
});
