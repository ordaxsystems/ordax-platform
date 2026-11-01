import assert from "node:assert/strict";
import test from "node:test";
import { enqueueProductAction, ProductPostgresError } from "../cloudflare/src/product_postgres_store.ts";

const INPUT = Object.freeze({
  ownerUserId: "11111111-1111-4111-8111-111111111111",
  spaceId: null, projectId: null,
  deviceId: "22222222-2222-4222-8222-222222222222",
  clientKind: "product-mcp" as const,
  clientId: "product-test-client-001",
  capability: "computer.screen_info",
  accessMode: "read" as const,
  payload: { max_items: 4 },
  idempotencyKey: "mcp-read-retry-concurrent-001",
  expiresAt: "2027-01-01T00:00:00.000Z",
});
const ENV = { POSTGRES: { connectionString: "postgresql://localhost:6543/test-only" } } as any;
const RECEIPT = Object.freeze({
  ok: true, replayed: true,
  request_id: "33333333-3333-4333-8333-333333333333",
  effect_id: "44444444-4444-4444-8444-444444444444", status: "queued",
});
function failure(code: string, nested = false) {
  const error = new Error("private credentials must never escape");
  return nested ? Object.assign(error, { cause: { code } }) : Object.assign(error, { code });
}
function mockClient(run: (call: number) => unknown) {
  let calls = 0, connected = 0, ended = 0;
  const values: string[] = [];
  const createClient = (_connectionString: string) => ({
    async connect() { connected++; },
    async query(sql: string, params: readonly unknown[]) {
      calls++;
      assert.match(sql, /^select public\.ordax_enqueue_product_action_v1\(/);
      assert.equal(params[0], INPUT.ownerUserId);
      assert.equal(params[5], INPUT.clientId);
      assert.equal(params[9], INPUT.idempotencyKey);
      values.push(JSON.stringify(params));
      const result = run(calls);
      if (result instanceof Error) throw result;
      return { rows: [{ result }] };
    },
    async end() { ended++; },
  }) as any;
  return { createClient, get calls() { return calls; },
    get connected() { return connected; }, get ended() { return ended; }, values };
}

test("same Owner/key retries one SQL unique race and returns the durable receipt", async () => {
  const c = mockClient((n) => n === 1 ? failure("23505") : RECEIPT);
  const previous = console.error;
  const logs: string[] = [];
  console.error = (...v: unknown[]) => logs.push(v.map(String).join(" "));
  try {
    const result = await enqueueProductAction(ENV, INPUT, c.createClient);
    assert.deepEqual(result, RECEIPT);
    assert.equal(c.calls, 2);
    assert.equal(c.connected, 2);
    assert.equal(c.ended, 2);
    assert.equal(c.values[0], c.values[1], "retry must reuse exact SQL inputs");
    assert.equal(logs.length, 1);
    assert.equal(logs[0].includes("private credentials"), false);
    assert.equal(JSON.parse(logs[0]).code, "23505");
  } finally { console.error = previous; }
});

test("nested SQLSTATE collision is retried but differing payload cannot replay", async () => {
  const conflict = { ok: false, error: "idempotency_conflict" };
  const c = mockClient((n) => n === 1 ? failure("23505", true) : conflict);
  const original = console.error; console.error = () => {};
  try {
    assert.deepEqual(await enqueueProductAction(ENV, INPUT, c.createClient), conflict);
  } finally { console.error = original; }
  assert.equal(c.calls, 2);
  assert.equal(c.ended, 2);
  assert.equal(c.values[0], c.values[1]);
});

test("a second SQL unique collision is terminal and never loops or invents a key", async () => {
  const c = mockClient(() => failure("23505"));
  const original = console.error; console.error = () => {};
  try {
    await assert.rejects(
      enqueueProductAction(ENV, INPUT, c.createClient),
      (error: unknown) => error instanceof ProductPostgresError
        && error.code === "product_postgres_unavailable" && error.status === 503,
    );
  } finally { console.error = original; }
  assert.equal(c.calls, 2);
  assert.equal(c.ended, 2);
  assert.equal(c.values[0], c.values[1]);
});

test("unrelated PostgreSQL transport errors do not cause blind action retries", async () => {
  const c = mockClient(() => failure("08006"));
  const original = console.error; console.error = () => {};
  try {
    await assert.rejects(
      enqueueProductAction(ENV, INPUT, c.createClient),
      (error: unknown) => error instanceof ProductPostgresError
        && error.code === "product_postgres_unavailable" && error.status === 503,
    );
  } finally { console.error = original; }
  assert.equal(c.calls, 1);
  assert.equal(c.ended, 1);
});
