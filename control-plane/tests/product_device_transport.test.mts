import test from "node:test";
import assert from "node:assert/strict";

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalDeviceHeartbeatDigest,
  canonicalDeviceLeaseSeconds,
  canonicalDeviceActionProgress,
  isProductReportJsonbSafe,
  deviceProjectBindingIntentsResponse,
  deviceProjectBindingConfirmationResponse,
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
  for (const urlPath of [
    "/workspace-confirm", "/workspace-proof",
    "/project-binding-intents", "/project-binding-confirm",
  ]) {
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
    OWNER_PROJECT_DEVICE_BINDING_ENABLED: "enabled",
  };
  for (const urlPath of [
    ...recognized, "/workspace-proof", "/workspace-confirm",
    "/project-binding-intents", "/project-binding-confirm",
  ]) {
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
  assert.equal(source.includes('readBoundedJsonObject(request, 1024)'), true);
  assert.equal(source.includes('48 * 1024'), false);
  assert.equal(source.includes('LEGACY_HEARTBEAT_MAX_CAPABILITIES'), false);
  assert.equal(source.includes('LEGACY_HEARTBEAT_MAX_NAME_CODEPOINTS'), false);
  assert.equal(source.includes('capabilityDigest,'), true);
  assert.equal(source.includes('capabilities: values'), false);
  assert.equal(source.includes('env.DB'), false);
});

test("canonical heartbeat accepts only digest-based Native and desktop payloads", () => {
  const digest = "ab".repeat(32);
  assert.equal(canonicalDeviceHeartbeatDigest({
    status: "online", agent_version: "1.31.0", capabilities_digest: digest,
  }), digest);
  assert.equal(canonicalDeviceHeartbeatDigest({
    status: "busy", agent_version: "1.31.0", runtime_kind: "ordax-os",
    capabilities_digest: digest.toUpperCase(),
  }), digest);
});

test("retired capability arrays, mixed schemas and forged authority fields fail closed", () => {
  const digest = "a".repeat(64);
  const variants = [
    {},
    { status: "online", agent_version: "1.30.3", capabilities: ["a", "b"] },
    { capabilities: [] },
    { capabilities_digest: digest, capabilities: ["x"] },
    { capabilities_digest: "x" },
    { capabilities_digest: 5 },
    { capabilities_digest: [] },
    { capabilities_digest: digest, device_id: "spoof" },
    { capabilities_digest: digest, owner_user_id: "spoof" },
    { capabilities_digest: digest, grant: { allow: true } },
    { capabilities_digest: digest, runtime_kind: "desktop-agent", extra: true },
  ];
  for (const body of variants) {
    assert.equal(canonicalDeviceHeartbeatDigest(body), null, JSON.stringify(body).slice(0, 150));
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


test("Project binding intent projection exposes only bounded Device-local coordination state", () => {
  const device = "22222222-2222-4222-8222-222222222222";
  const intent = "55555555-5555-4555-8555-555555555555";
  const project = "44444444-4444-4444-8444-444444444444";
  const space = "33333333-3333-4333-8333-333333333333";
  const raw = {
    ok: true,
    device_id: device,
    intents: [{
      intent_id: intent,
      project_id: project,
      space_id: space,
      repository_full_name: "OrdaXSystems/OrdaX-Platform",
      expires_at: "2026-11-14T00:00:00.000Z",
      owner_user_id: "drop",
      installation_id: "drop",
      repository_id: "drop",
      allowed_capabilities: ["drop"],
    }],
  };
  assert.deepEqual(deviceProjectBindingIntentsResponse(raw, device), {
    ok: true,
    schema: "ordax.device-project-binding-intents/1",
    device_id: device,
    intents: [{
      intent_id: intent,
      project_id: project,
      space_id: space,
      repository_full_name: "ordaxsystems/ordax-platform",
      expires_at: "2026-11-14T00:00:00.000Z",
    }],
  });
  for (const invalid of [
    { ...raw, device_id: space },
    { ...raw, intents: [{ ...raw.intents[0], intent_id: "bad" }] },
    { ...raw, intents: [{ ...raw.intents[0], repository_full_name: "bad path/repo/x" }] },
    { ...raw, intents: Array.from({ length: 17 }, () => raw.intents[0]) },
    { ...raw, intents: [raw.intents[0], raw.intents[0]] },
  ]) {
    assert.throws(() => deviceProjectBindingIntentsResponse(invalid as any, device),
      /product_postgres_invalid_response/);
  }
});

test("Project binding confirmation projection cannot manufacture grants or local paths", () => {
  const device = "22222222-2222-4222-8222-222222222222";
  const intent = "55555555-5555-4555-8555-555555555555";
  const raw = {
    ok: true,
    binding_id: "66666666-6666-4666-8666-666666666666",
    project_id: "44444444-4444-4444-8444-444444444444",
    space_id: "33333333-3333-4333-8333-333333333333",
    device_id: device,
    state: "active",
    next_state: "ready_without_grants",
    local_project_ref: "drop",
    allowed_capabilities: ["drop"],
    grant_id: "drop",
  };
  const result = deviceProjectBindingConfirmationResponse(raw, device, intent);
  assert.deepEqual(result, {
    ok: true,
    schema: "ordax.device-project-binding-confirmed/1",
    intent_id: intent,
    binding_id: raw.binding_id,
    project_id: raw.project_id,
    space_id: raw.space_id,
    device_id: device,
    state: "active",
    next_state: "ready_without_grants",
  });
  assert.equal("local_project_ref" in result, false);
  assert.equal("allowed_capabilities" in result, false);
  assert.equal("grant_id" in result, false);
  assert.equal("grant_profile" in result, false);

  for (const error of [
    "project_device_binding_confirmation_invalid",
    "project_device_binding_intent_not_active",
    "project_device_binding_authority_changed",
    "github_repository_changed",
    "project_device_binding_conflict",
  ]) {
    assert.deepEqual(deviceProjectBindingConfirmationResponse(
      { ok: false, error }, device, intent,
    ), { ok: false, error });
  }
});

test("Project binding transport is independently gated and accepts only opaque project-N refs", () => {
  const source = fs.readFileSync(SRC, "utf8");
  assert.match(source, /OWNER_PROJECT_DEVICE_BINDING_ENABLED/);
  assert.match(source, /LOCAL_PROJECT_REF_RE = \/\^project-\[1-9\]\[0-9\]\*\$\//);
  assert.match(source, /project-binding-intents/);
  assert.match(source, /project-binding-confirm/);
  assert.match(source, /exactKeys\(body, \["intent_id", "local_project_ref", "confirm"\]\)/);
  assert.match(source, /body\.confirm !== "bind_local_project"/);
  assert.doesNotMatch(source, /local_project_path|workspace_path|repository_id.*project-binding-confirm/);
});
