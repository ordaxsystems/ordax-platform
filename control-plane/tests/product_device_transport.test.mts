import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalDeviceHeartbeatDigest,
  handleProductDeviceTransport,
} from "../cloudflare/src/product_device_transport.ts";
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

test("device heartbeat persists one canonical digest, never a capability array", () => {
  const source = fs.readFileSync(SRC, "utf8");
  assert.equal(source.includes('body.capabilities_digest'), true);
  assert.equal(source.includes('readBoundedJsonObject(request, LEGACY_HEARTBEAT_MAX_BODY_BYTES)'), true);
  assert.equal(source.includes('48 * 1024'), true);
  assert.equal(source.includes('LEGACY_HEARTBEAT_MAX_CAPABILITIES = 1024'), true);
  assert.equal(source.includes('LEGACY_HEARTBEAT_MAX_NAME_CODEPOINTS = 160'), true);
  assert.equal(source.includes('capabilityDigest,'), true);
  assert.equal(source.includes('capabilities: values'), false);
  assert.equal(source.includes('env.DB'), false);
});

test("legacy installed Runtime heartbeat hashes sorted unique action names exactly like connector SSOT", async () => {
  const input = { status: "online", agent_version: "1.30.3", capabilities: ["b", "a", "a"] };
  const expected = createHash("sha256").update('["a","b"]', "utf8").digest("hex");
  assert.equal(await canonicalDeviceHeartbeatDigest(input), expected);
  assert.equal(
    await canonicalDeviceHeartbeatDigest({ capabilities_digest: expected.toUpperCase() }),
    expected,
  );
  const unicode = ["🐈", "é", "z", "é"];
  const canonicalUnicode = JSON.stringify(["z", "é", "🐈"]);
  assert.equal(await canonicalDeviceHeartbeatDigest({ capabilities: unicode }),
    createHash("sha256").update(canonicalUnicode, "utf8").digest("hex"));
  assert.equal(await canonicalDeviceHeartbeatDigest({ capabilities: [] }),
    createHash("sha256").update("[]", "utf8").digest("hex"));
});

test("heartbeat bridge rejects mixed schemas, untrusted authority metadata and oversized legacy inputs", async () => {
  const valid = "a".repeat(64);
  const variants = [
    {},
    { capabilities_digest: valid, capabilities: ["x"] },
    { capabilities_digest: "x" },
    { capabilities_digest: 5 },
    { capabilities_digest: [] },
    { capabilities: "computer.text_read" },
    { capabilities: [null] },
    { capabilities: [{}] },
    { capabilities: [""] },
    { capabilities: ["x".repeat(161)] },
    { capabilities: Array.from({ length: 1025 }, () => "x") },
    { status: "online", agent_version: "1.30.3", capabilities: ["x"], device_id: "spoof" },
    { status: "online", agent_version: "1.30.3", capabilities: ["x"], owner_user_id: "spoof" },
    { status: "online", agent_version: "1.30.3", capabilities: ["x"], grant: { allow: true } },
  ];
  for (const body of variants) {
    assert.equal(await canonicalDeviceHeartbeatDigest(body), null, JSON.stringify(body).slice(0, 150));
  }
});
