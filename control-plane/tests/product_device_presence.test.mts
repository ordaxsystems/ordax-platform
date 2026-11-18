import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { handleProductDevicePresence, PRODUCT_DEVICE_PRESENCE_PATH } from "../cloudflare/src/product_device_presence.ts";
import { ProductPostgresError } from "../cloudflare/src/product_postgres_store.ts";

const DEVICE = "ba014375-8c25-4aa1-a9d0-d6be994e3c15";
const TOKEN = "fixture-device-token-never-a-real-credential";
const SNAPSHOT = {
  online: true, runtime_kind: "desktop-agent", agent_version: "1.30.1",
  capability_digest: "a".repeat(64),
};
type Dependencies = NonNullable<Parameters<typeof handleProductDevicePresence>[2]>;

function request(body: unknown = SNAPSHOT, headers: Record<string, string> = {}, url = PRODUCT_DEVICE_PRESENCE_PATH): Request {
  return new Request(`https://fixture.invalid${url}`, {
    method: "POST",
    headers: { "content-type": "application/json", "X-Ordax-Device-Id": DEVICE, "X-Ordax-Device-Token": TOKEN, ...headers },
    body: JSON.stringify(body),
  });
}

function fixture(...receipts: unknown[]) {
  const authenticated = receipts.length > 0 ? receipts[0] : true;
  const changed = receipts.length > 1 ? receipts[1] : true;
  const calls: { operation: string; input: unknown }[] = [];
  const dependencies: Dependencies = {
    authenticate: async (_env, input) => { calls.push({ operation: "authenticate", input }); return authenticated as boolean; },
    record: async (_env, input) => { calls.push({ operation: "record", input }); return changed as boolean; },
  };
  return { calls, dependencies };
}

test("canonical device presence hashes the credential, then writes exactly the authenticated device", async () => {
  const { calls, dependencies } = fixture();
  const response = await handleProductDevicePresence(request(), {}, dependencies);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), { ok: true, device_id: DEVICE, changed: true });
  assert.deepEqual(calls, [
    { operation: "authenticate", input: { deviceId: DEVICE, tokenSha256: createHash("sha256").update(TOKEN).digest("hex") } },
    { operation: "record", input: { deviceId: DEVICE, online: true, runtimeKind: "desktop-agent", agentVersion: "1.30.1", capabilityDigest: "a".repeat(64), force: false } },
  ]);
  assert.equal(JSON.stringify(calls).includes(TOKEN), false);
});

test("coalesced unchanged heartbeat is accepted without claiming a timestamp update", async () => {
  const { calls, dependencies } = fixture(true, false);
  const response = await handleProductDevicePresence(request(), {}, dependencies);
  assert.deepEqual(await response.json(), { ok: true, device_id: DEVICE, changed: false });
  assert.equal(calls.length, 2);
});

test("all canonical runtime kinds and explicit offline/null metadata snapshots are supported", async () => {
  for (const runtimeKind of ["ordax-os", "desktop-agent", "mobile-client", "other", null]) {
    const { calls, dependencies } = fixture();
    const response = await handleProductDevicePresence(request({ online: false, runtime_kind: runtimeKind, agent_version: null, capability_digest: null }), {}, dependencies);
    assert.equal(response.status, 200);
    assert.deepEqual(calls[1].input, { deviceId: DEVICE, online: false, runtimeKind, agentVersion: null, capabilityDigest: null, force: false });
  }
});

test("another, unknown or revoked credential never updates presence", async () => {
  const { calls, dependencies } = fixture(false);
  const response = await handleProductDevicePresence(request(), {}, dependencies);
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { ok: false, error: "product_device_unauthorized" });
  assert.deepEqual(calls.map(call => call.operation), ["authenticate"]);
});

test("account bearer and caller query metadata cannot select or authenticate the device writer", async () => {
  const { calls, dependencies } = fixture();
  const response = await handleProductDevicePresence(request(SNAPSHOT, { Authorization: "Bearer fixture-account-token" }, `${PRODUCT_DEVICE_PRESENCE_PATH}?device_id=another&token=spoof&force=true&owner_user_id=spoof`), {}, dependencies);
  assert.equal(response.status, 200);
  assert.equal((calls[0].input as Record<string, unknown>).deviceId, DEVICE);
  assert.equal((calls[1].input as Record<string, unknown>).force, false);
  const missing = request(SNAPSHOT, { Authorization: "Bearer fixture-account-token" });
  missing.headers.delete("X-Ordax-Device-Token");
  const denied = await handleProductDevicePresence(missing, {}, dependencies);
  assert.equal(denied.status, 401);
  assert.equal(calls.length, 2);
});

test("invalid or missing device credential headers are rejected before RPCs", async () => {
  for (const headers of [
    { "X-Ordax-Device-Id": "" }, { "X-Ordax-Device-Id": "legacy-slug" },
    { "X-Ordax-Device-Token": "" }, { "X-Ordax-Device-Token": "short" },
    { "X-Ordax-Device-Token": "a".repeat(513) }, { "X-Ordax-Device-Token": `a${" ".repeat(32)}b` },
  ]) {
    const { calls, dependencies } = fixture();
    const response = await handleProductDevicePresence(request(SNAPSHOT, headers), {}, dependencies);
    assert.equal(response.status, 401);
    assert.deepEqual(calls, []);
    assert.equal(response.headers.get("cache-control"), "no-store");
  }
});

test("only POST and JSON are accepted, with no authority calls", async () => {
  const { calls, dependencies } = fixture();
  for (const method of ["GET", "PUT", "DELETE", "OPTIONS"]) {
    const response = await handleProductDevicePresence(new Request(`https://fixture.invalid${PRODUCT_DEVICE_PRESENCE_PATH}`, { method }), {}, dependencies);
    assert.equal(response.status, 405);
    assert.equal(response.headers.get("allow"), "POST");
  }
  for (const mime of ["text/plain", "text/html", "application/octet-stream", ""]) {
    assert.equal((await handleProductDevicePresence(request(SNAPSHOT, { "content-type": mime }), {}, dependencies)).status, 415);
  }
  assert.deepEqual(calls, []);
  assert.equal((await handleProductDevicePresence(request(SNAPSHOT, { "content-type": "Application/JSON; charset=utf-8" }), {}, dependencies)).status, 200);
});

test("malformed snapshots and caller authority fields are rejected without database writes", async () => {
  const invalid = [null, [], "not-a-snapshot", {},
    { ...SNAPSHOT, online: "true" }, { ...SNAPSHOT, online: 1 },
    { ...SNAPSHOT, runtime_kind: "cloud-executor" }, { ...SNAPSHOT, runtime_kind: {} },
    { ...SNAPSHOT, agent_version: "" }, { ...SNAPSHOT, agent_version: "x".repeat(81) },
    { ...SNAPSHOT, agent_version: " 1.0" }, { ...SNAPSHOT, agent_version: "1.0\u0000" },
    { ...SNAPSHOT, agent_version: "1.0\u007f" }, { ...SNAPSHOT, agent_version: false },
    { ...SNAPSHOT, capability_digest: "A".repeat(64) }, { ...SNAPSHOT, capability_digest: [] },
    { ...SNAPSHOT, capability_digest: "a".repeat(63) },
    ...["device_id", "owner_user_id", "client_id", "grant", "force", "last_seen_at", "capabilities", "token"].map(key => ({ ...SNAPSHOT, [key]: "spoof" })),
  ];
  for (const key of Object.keys(SNAPSHOT)) {
    const partial: Record<string, unknown> = { ...SNAPSHOT }; delete partial[key]; invalid.push(partial as typeof SNAPSHOT);
  }
  for (const body of invalid) {
    const { calls, dependencies } = fixture();
    assert.equal((await handleProductDevicePresence(request(body), {}, dependencies)).status, 400);
    assert.deepEqual(calls, []);
  }
});

test("invalid UTF-8, JSON and oversized streamed requests are bounded and cancelled", async () => {
  for (const bytes of [new Uint8Array([0xff]), new TextEncoder().encode("{bad"), new TextEncoder().encode(JSON.stringify({ ...SNAPSHOT, agent_version: "x".repeat(17 * 1024) }))]) {
    let cancelled = false;
    const oversized = bytes.length > 16 * 1024;
    const stream = new ReadableStream({ start(controller) {
      controller.enqueue(bytes);
      if (!oversized) controller.close();
    }, cancel() { cancelled = true; } });
    const incoming = new Request(`https://fixture.invalid${PRODUCT_DEVICE_PRESENCE_PATH}`, {
      method: "POST", headers: request().headers, body: stream, duplex: "half",
    } as RequestInit);
    const { calls, dependencies } = fixture();
    assert.equal((await handleProductDevicePresence(incoming, {}, dependencies)).status, 400);
    assert.deepEqual(calls, []);
    assert.equal(cancelled, oversized);
    assert.equal(stream.locked, false);
  }
});

test("invalid authentication RPC receipts fail closed and do not write", async () => {
  for (const result of [null, undefined, 1, "true", { ok: true }]) {
    const { calls, dependencies } = fixture(result);
    const response = await handleProductDevicePresence(request(), {}, dependencies);
    assert.equal(response.status, 502);
    assert.deepEqual(await response.json(), { ok: false, error: "product_postgres_invalid_response" });
    assert.equal(calls.length, 1);
  }
});

test("invalid presence RPC receipts never announce success or retry", async () => {
  for (const result of [null, undefined, 0, "false", { ok: true }]) {
    const { calls, dependencies } = fixture(true, result);
    const response = await handleProductDevicePresence(request(), {}, dependencies);
    assert.equal(response.status, 502);
    assert.deepEqual(await response.json(), { ok: false, error: "product_postgres_invalid_response" });
    assert.equal(calls.length, 2);
  }
});

test("authority errors are private and never cause fallback or replay", async () => {
  for (const operation of ["authenticate", "record"] as const) {
    for (const error of [new Error(`private SQL host password ${TOKEN}`), new ProductPostgresError("private_error", 403)]) {
      const { calls, dependencies } = fixture();
      dependencies[operation] = async () => { throw error; };
      const response = await handleProductDevicePresence(request(), {}, dependencies);
      assert.equal(response.status, 503);
      assert.deepEqual(await response.json(), { ok: false, error: "product_presence_unavailable" });
      assert.equal(response.headers.get("cache-control"), "no-store");
      assert.equal(calls.length, operation === "record" ? 1 : 0);
    }
  }
});

test("default production adapter fails closed when PostgreSQL is absent", async () => {
  const response = await handleProductDevicePresence(request(), {});
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { ok: false, error: "product_postgres_unconfigured" });
});

test("Worker dispatches the canonical presence path without adding D1 or another session transport", () => {
  const entry = readFileSync(new URL("../cloudflare/src/product_mcp_entry.ts", import.meta.url), "utf8");
  assert.match(entry, /if \(url\.pathname === PRODUCT_DEVICE_PRESENCE_PATH\) \{[\s\S]*?handleProductDevicePresence\(request, env\);/);
  const source = readFileSync(new URL("../cloudflare/src/product_device_presence.ts", import.meta.url), "utf8");
  assert.doesNotMatch(source, /\bDB\b|\.prepare\(|DEVICE_SESSIONS|setInterval|setTimeout|console\./);
  assert.match(source, /dependencies\.authenticate \?\? authenticateProductDevice/);
  assert.match(source, /dependencies\.record \?\? recordProductPresence/);
});
