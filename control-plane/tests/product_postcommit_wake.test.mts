import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { enqueueProductAction } from "../cloudflare/src/product_postgres_store.ts";

const DEVICE = "22222222-2222-4222-8222-222222222222";
const REQUEST = "33333333-3333-4333-8333-333333333333";
const RECEIPT = Object.freeze({
  ok: true, replayed: false, request_id: REQUEST,
  effect_id: "44444444-4444-4444-8444-444444444444", status: "queued",
});
const INPUT = Object.freeze({
  ownerUserId: "11111111-1111-4111-8111-111111111111",
  spaceId: null, projectId: null, deviceId: DEVICE,
  clientKind: "product-mcp" as const, clientId: "chatgpt-client-test",
  capability: "computer.screen_info", accessMode: "read" as const,
  payload: {}, idempotencyKey: "product-wake-test-001",
  expiresAt: "2027-01-01T00:00:00Z",
});

function client(result: unknown = RECEIPT) {
  return () => ({
    async connect() {},
    async query(sql: string) {
      assert.match(sql, /^select public\.ordax_enqueue_product_action_v1\(/);
      return { rows: [{ result }] };
    },
    async end() {},
  }) as any;
}
function wakeFixture() {
  let release!: () => void;
  let wakeStarted!: () => void;
  const started = new Promise<void>(resolve => { wakeStarted = resolve; });
  const pendingWake = new Promise<Response>(resolve => {
    release = () => resolve(Response.json({ ok: true }));
  });
  let calls = 0;
  const env = {
    POSTGRES: { connectionString: "postgresql://localhost:5432/test-only" },
    PRODUCT_DEVICE_WAKE_ENABLED: "enabled",
    DEVICE_WAKE: {
      idFromName(device: string) { assert.equal(device, DEVICE); return "wake-stub"; },
      get(id: string) {
        assert.equal(id, "wake-stub");
        return {
          fetch(url: string, options: RequestInit) {
            assert.equal(url, "https://ordax-device-wake.internal/wake");
            assert.equal(options.method, "POST");
            calls++;
            wakeStarted();
            return pendingWake;
          },
        };
      },
    },
  } as any;
  return { env, started, release, get calls() { return calls; } };
}

test("request-owned Worker waitUntil lets committed SQL ACK return before a stalled wake", async () => {
  const fixture = wakeFixture();
  const scheduled: Promise<void>[] = [];
  const result = await enqueueProductAction(fixture.env, {
    ...INPUT, scheduleWake: (wake: Promise<void>) => { scheduled.push(wake); },
  }, client());
  assert.deepEqual(result, RECEIPT);
  assert.equal(fixture.calls, 1);
  assert.equal(scheduled.length, 1);
  // Signalling still runs to completion in the explicitly retained Worker
  // lifetime; the device must always claim and authorize in PostgreSQL.
  fixture.release();
  await Promise.all(scheduled);
});

test("non-Worker callers still await the same advisory wake", async () => {
  const fixture = wakeFixture();
  let finished = false;
  const pending = enqueueProductAction(fixture.env, INPUT, client()).then(result => {
    finished = true;
    return result;
  });
  await fixture.started;
  await Promise.resolve();
  assert.equal(finished, false, "without an execution context, enqueue still waits for wake");
  fixture.release();
  assert.deepEqual(await pending, RECEIPT);
  assert.equal(finished, true);
  assert.equal(fixture.calls, 1);
});

test("a denied SQL enqueue never schedules a wake or invents a persisted receipt", async () => {
  let touched = 0, scheduled = 0;
  const env = {
    POSTGRES: { connectionString: "postgresql://localhost:5432/test-only" },
    PRODUCT_DEVICE_WAKE_ENABLED: "enabled",
    DEVICE_WAKE: { idFromName() { touched++; throw new Error("must not wake"); } },
  } as any;
  const denied = { ok: false, error: "product_grant_not_resolved" };
  const result = await enqueueProductAction(env, {
    ...INPUT, scheduleWake: () => { scheduled++; },
  }, client(denied));
  assert.deepEqual(result, denied);
  assert.equal(touched, 0);
  assert.equal(scheduled, 0);
});

test("if a supplied scheduler throws, the original wake path is preserved", async () => {
  const fixture = wakeFixture();
  let finished = false;
  const pending = enqueueProductAction(fixture.env, {
    ...INPUT, scheduleWake: () => { throw new Error("invalid execution context"); },
  }, client()).then(result => { finished = true; return result; });
  await fixture.started;
  await Promise.resolve();
  assert.equal(finished, false);
  fixture.release();
  assert.deepEqual(await pending, RECEIPT);
  assert.equal(fixture.calls, 1);
});

test("one Worker request owns the wake scheduler across every attested MCP enqueue route", () => {
  const gatewaySource = readFileSync(fileURLToPath(new URL(
    "../cloudflare/src/product_mcp_entry.ts", import.meta.url,
  )), "utf8");
  const expected = [
    "createAttestedDeviceActionHandler(env, trusted, wakeDependencies)",
    "createAttestedProjectActionHandler(env, trusted, wakeDependencies)",
    "createAttestedProjectContinuityHandler(env, trusted, wakeDependencies)",
    "createAttestedRepositoryCatalogHandler(env, trusted, wakeDependencies)",
  ];
  assert.equal(
    gatewaySource.includes("scheduleWake: (wake: Promise<void>) => context.waitUntil(wake)"),
    true,
  );
  for (const route of expected) assert.equal(gatewaySource.includes(route), true, route);
});
