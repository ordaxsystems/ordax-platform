import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { createCanonicalProductMcpGateway } from "../cloudflare/src/product_mcp_entry.ts";

const ENV = Object.freeze({
  PRODUCT_AUTH_ISSUER: "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1",
  PRODUCT_AUTH_AUDIENCE: "authenticated",
  PRODUCT_AUTH_JWKS_URL: "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1/.well-known/jwks.json",
  POSTGRES: { connectionString: "postgresql://localhost:6543/example" },
});
const SETUP_URL = "https://mcp.example/v3/device/setup";
const HEX64 = "a".repeat(64);

function post(body: Record<string, unknown>, headers: Record<string, string> = {}) {
  return new Request(SETUP_URL, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

test("canonical MCP entry mounts device bootstrap without importing legacy Worker or D1", async () => {
  const entry = await readFile(new URL("../cloudflare/src/product_mcp_entry.ts", import.meta.url), "utf8");
  const setup = await readFile(new URL("../cloudflare/src/product_device_setup.ts", import.meta.url), "utf8");
  assert.match(entry, /PRODUCT_DEVICE_SETUP_PATH/);
  assert.match(entry, /handleProductDeviceSetup/);
  assert.doesNotMatch(entry + setup, /from ["']\.\/index(?:\.ts)?["']|env\.DB\b|ORDAX_OPERATOR_TOKEN/);
  assert.match(setup, /enrollProductDevice/);
  assert.match(setup, /identifyProductDevice/);
  assert.match(setup, /authenticateProductRequest/);
});

test("device bootstrap accepts only POST and fails closed before authority calls", async () => {
  const gateway = createCanonicalProductMcpGateway(ENV);
  const get = await gateway(new Request(SETUP_URL));
  assert.equal(get.status, 405);
  assert.equal((await get.json()).error, "method_not_allowed");

  const malformed = await gateway(post({ operation: "enroll" }));
  assert.equal(malformed.status, 400);
  assert.equal((await malformed.json()).error, "request_invalid");

  const unknown = await gateway(post({ operation: "delete", machine_binding_sha256: HEX64 }));
  assert.equal(unknown.status, 400);
  assert.equal((await unknown.json()).error, "operation_not_allowed");
});

test("enrollment contract requires canonical kind/channel and product authentication", async () => {
  const gateway = createCanonicalProductMcpGateway(ENV);
  const base = {
    operation: "enroll",
    machine_binding_sha256: HEX64,
    token_sha256: "b".repeat(64),
    device_name: "ORDAX-TEST",
  };

  for (const body of [
    { ...base, device_kind: "toaster", channel: "development" },
    { ...base, device_kind: "desktop", channel: "nightly" },
  ]) {
    const response = await gateway(post(body));
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, "request_invalid");
  }

  const unauthenticated = await gateway(post({
    ...base,
    device_kind: "desktop",
    channel: "development",
  }));
  assert.equal(unauthenticated.status, 401);
  assert.equal((await unauthenticated.json()).error, "product_auth_required");
});

test("identify contract requires a locally-held device token and never accepts owner bearer as substitute", async () => {
  const gateway = createCanonicalProductMcpGateway(ENV);
  const missing = await gateway(post({
    operation: "identify",
    machine_binding_sha256: HEX64,
  }, { authorization: "Bearer owner-session-is-not-a-device-token" }));
  assert.equal(missing.status, 401);
  assert.equal((await missing.json()).error, "device_auth_required");
});
