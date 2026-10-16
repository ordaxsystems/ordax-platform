import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { handleProductDeviceTransport } from "../cloudflare/src/product_device_transport.ts";
import { createCanonicalProductMcpGateway } from "../cloudflare/src/product_mcp_entry.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(HERE, "../cloudflare/src/product_device_transport.ts");
const fakeEnv = {} as any;

test("device transport is POST-only and rejects unauthenticated device before PostgreSQL", async () => {
  const get = await handleProductDeviceTransport(
    new Request("https://mcp.example/v3/device/transport/heartbeat"), fakeEnv,
  );
  assert.equal(get.status, 405);
  assert.deepEqual(await get.json(), { ok: false, error: "method_not_allowed" });

  const post = await handleProductDeviceTransport(
    new Request("https://mcp.example/v3/device/transport/heartbeat", { method: "POST" }), fakeEnv,
  );
  assert.equal(post.status, 401);
  assert.deepEqual(await post.json(), { ok: false, error: "device_auth_required" });
});

test("canonical MCP gateway mounts device transport without exposing another MCP tool", async () => {
  const gateway = createCanonicalProductMcpGateway(fakeEnv, {
    session: async () => Response.json({ ok: false }, { status: 401 }),
    targets: async () => Response.json({ ok: false }, { status: 401 }),
    getAction: async () => Response.json({ ok: false }, { status: 401 }),
  } as any, async () => new Response("{}", { status: 503 }));
  const response = await gateway(new Request(
    "https://mcp.example/v3/device/transport/claim", { method: "POST" },
  ));
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { ok: false, error: "device_auth_required" });
});

test("device transport source has no D1, operator bearer, websocket queue, pairing or remote artifact authority", () => {
  const source = fs.readFileSync(SRC, "utf8");
  for (const forbidden of [
    "D1Database", "env.DB", "ORDAX_OPERATOR_TOKEN", "operatorAuthorized",
    "WebSocket", "pairing_secret", "/v3/artifacts/", "R2Bucket",
  ]) assert.equal(source.includes(forbidden), false, forbidden);
  for (const required of [
    "authenticateProductDevice", "recordProductPresence", "claimProductAction",
    "startProductAction", "renewProductActionLease", "progressProductAction",
    "reportProductAction", "result_canonical_b64",
  ]) assert.equal(source.includes(required), true, required);
});
