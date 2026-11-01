import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalDeviceHeartbeatDigest,
  canonicalDeviceLeaseSeconds,
  canonicalDeviceActionProgress,
  isProductReportJsonbSafe,
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

test("unknown device routes do not consume SQL token-verification queries", async () => {
  const authenticatedShape = {
    "x-ordax-device-id": "22222222-2222-4222-8222-222222222222",
    "x-ordax-device-token": "a".repeat(64),
  };
  const unknown = [
    "/v3/device/transport/unknown",
    "/v3/device/transport/heartbeat/unexpected",
    "/v3/device/transport/report/extra",
    "/v3/device/transport/wake/subscribe",
  ];
  for (const urlPath of unknown) {
    const request = new Request("https://mcp.example" + urlPath, {
      method: "POST", headers: authenticatedShape,
    });
    // No POSTGRES binding exists in this env. An attempted SQL verification
    // would return 503; nonexistent routes must return 404 without DB access.
    const result = await handleProductDeviceTransport(request, fakeEnv);
    assert.equal(result.status, 404, urlPath);
    assert.deepEqual(await result.json(), { ok: false, error: "not_found" });
  }
});

test("staged workspace routes preserve auth-first secrecy even while disabled", async () => {
  const variants = [
    {},
    { WORKSPACE_RESOURCE_VERIFIER_ENABLED: "enabled" },
    { WORKSPACE_RESOURCE_ISSUANCE_ENABLED: "enabled" },
  ];
  for (const urlPath of ["/workspace-confirm", "/workspace-proof"]) {
    for (const flags of variants) {
      const response = await handleProductDeviceTransport(
        new Request("https://mcp.example/v3/device/transport" + urlPath, { method: "POST" }),
        { ...fakeEnv, ...flags },
      );
      assert.equal(response.status, 401, urlPath + JSON.stringify(flags));
      assert.deepEqual(await response.json(), { ok: false, error: "device_auth_required" });
    }
  }
});

test("enabled and recognized device paths always retain PostgreSQL authentication", async () => {
  const recognized = [
    "/heartbeat", "/claim", "/start", "/lease",
    "/orchestrator-read-authorization", "/progress",
    "/report", "/recover-report",
  ];
  const flags = {
    WORKSPACE_RESOURCE_VERIFIER_ENABLED: "enabled",
    WORKSPACE_RESOURCE_ISSUANCE_ENABLED: "enabled",
  };
  for (const urlPath of [...recognized, "/workspace-proof", "/workspace-confirm"]) {
    const response = await handleProductDeviceTransport(
      new Request("https://mcp.example/v3/device/transport" + urlPath, { method: "POST" }),
      { ...fakeEnv, ...flags },
    );
    assert.equal(response.status, 401, urlPath);
    assert.deepEqual(await response.json(), { ok: false, error: "device_auth_required" });
  }
  const wake = await handleProductDeviceTransport(
    new Request("https://mcp.example/v3/device/transport/wake"), fakeEnv,
  );
  assert.equal(wake.status, 401, "WebSocket subscriptions still require SQL device authentication");
  const wrongMethod = await handleProductDeviceTransport(
    new Request("https://mcp.example/v3/device/transport/wake", { method: "POST" }), fakeEnv,
  );
  assert.equal(wrongMethod.status, 405);
  const otherGet = await handleProductDeviceTransport(
    new Request("https://mcp.example/v3/device/transport/unknown"), fakeEnv,
  );
  assert.equal(otherGet.status, 405, "preserve existing method precedence");
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

test("PostgreSQL report JSONB rejects NUL recursively without rejecting text escaped for display", () => {
  const nul = String.fromCharCode(0);
  assert.equal(isProductReportJsonbSafe({ ok: true, data: { stdout: "line" + nul + "tail" } }), false);
  assert.equal(isProductReportJsonbSafe({ nested: [{ [nul]: "value" }] }), false);
  assert.equal(isProductReportJsonbSafe({ nested: [null, "safe", "\\u0000"] }), true);
  assert.equal(isProductReportJsonbSafe({ stdout: "C:\\\\Users\\\\Work" }), true);
});

test("device claim and lease use one strict numeric duration contract without JSON coercion", () => {
  assert.equal(canonicalDeviceLeaseSeconds(undefined), 120, "omitted duration retains canonical default");
  for (const [input, expected] of [[30, 30], [120, 120], [300, 300]] as const) {
    assert.equal(canonicalDeviceLeaseSeconds(input), expected);
  }
  for (const input of [null, "", "120", "300", "0", false, true, {}, [], [120],
    0, 29, 301, -1, 30.5, Infinity, -Infinity, NaN, Number.MAX_SAFE_INTEGER + 1]) {
    assert.equal(canonicalDeviceLeaseSeconds(input), null,
      "malformed claim/lease value must fail before PostgreSQL: " + JSON.stringify(input));
  }
  const source = fs.readFileSync(SRC, "utf8");
  assert.equal((source.match(/canonicalDeviceLeaseSeconds\(body!?\.lease_seconds\)/g) ?? []).length, 2,
    "claim and renew must share one numeric parser instead of copy/pasted coercions");
  assert.doesNotMatch(source, /Number\(body!?\.lease_seconds\)/);
});

test("device progress rejects malformed percentages and messages instead of recording forged telemetry", () => {
  assert.deepEqual(canonicalDeviceActionProgress({
    stage: " building ", message: "Compiling", progress_percent: 0,
  }), { stage: "building", message: "Compiling", percent: 0 });
  assert.deepEqual(canonicalDeviceActionProgress({
    stage: "running", message: null, progress_percent: 100,
  }), { stage: "running", message: null, percent: 100 });
  assert.deepEqual(canonicalDeviceActionProgress({ stage: "running" }),
    { stage: "running", message: null, percent: null },
    "omitted optional telemetry remains absent, never silently zero");
  for (const malformed of [
    null, {}, { stage: "" }, { stage: " " }, { stage: "x".repeat(97) },
    ...[true, false, "1", "", {}, [], [12], 101, -1, 0.5, Infinity, NaN].map(value =>
      ({ stage: "running", progress_percent: value })),
    ...[true, false, 123, 0, {}, [], ["message"], "x".repeat(513)].map(value =>
      ({ stage: "running", message: value })),
  ]) {
    assert.equal(canonicalDeviceActionProgress(malformed as any), null,
      "malformed progress must not be written: " + JSON.stringify(malformed).slice(0, 180));
  }
  const source = fs.readFileSync(SRC, "utf8");
  assert.match(source, /const progress = canonicalDeviceActionProgress\(body\)/);
  assert.doesNotMatch(source, /Number\(body\.progress_percent\)|String\(body\.message\)/);
});
