import assert from "node:assert/strict";
import test from "node:test";
import { ensureProductMcpTargetDiscovery } from "../cloudflare/src/product_mcp_discovery_store.ts";
import { ProductPostgresError } from "../cloudflare/src/product_postgres_store.ts";

const OWNER_ID = "11111111-1111-4111-8111-111111111111";
const CLIENT_ID = "22222222-2222-4222-8222-222222222222";
const CONNECTION_SECRET = "postgres://private-user:secret-never-logged@internal.local/postgres";
const ENV = { POSTGRES: { connectionString: CONNECTION_SECRET } };
const RPC = "select public.ordax_ensure_product_mcp_target_discovery_v1($1::uuid, $2::uuid) as result";

type Stage = "connect" | "query" | "decode";
function fault(stage: Stage) {
  let closed = 0;
  let queried = 0;
  const secret = CONNECTION_SECRET + " owner=" + OWNER_ID + " client=" + CLIENT_ID;
  const failure = Object.assign(new Error("connection terminated unexpectedly: " + secret), {
    code: "58000", address: secret, cause: { message: secret },
  });
  const client = {
    async connect() {
      if (stage === "connect") throw failure;
    },
    async query(_sql: string, _params: string[]) {
      queried++;
      if (stage === "query") throw failure;
      // Property throws while decoding a successful RPC response.
      return Object.defineProperty({}, "rows", { get() { throw failure; } }) as any;
    },
    async end() { closed++; },
  };
  return { client, queried: () => queried, closed: () => closed };
}

test("target-discovery PostgreSQL errors report sanitized phase without disclosing credentials or owner IDs", async () => {
  for (const stage of ["connect", "query", "decode"] as const) {
    const fixture = fault(stage);
    const observed: string[] = [];
    const previous = console.error;
    console.error = (...messages: unknown[]) => observed.push(messages.map(String).join(" "));
    try {
      await assert.rejects(
        ensureProductMcpTargetDiscovery(ENV, OWNER_ID, CLIENT_ID, {
          createClient: connectionString => {
            assert.equal(connectionString, CONNECTION_SECRET);
            return fixture.client;
          },
        }),
        (error: unknown) => error instanceof ProductPostgresError
          && error.code === "product_postgres_unavailable" && error.status === 503,
      );
    } finally {
      console.error = previous;
    }
    assert.equal(fixture.closed(), 1, stage);
    assert.equal(fixture.queried(), stage === "connect" ? 0 : 1, stage);
    assert.equal(observed.length, 1, stage);
    const diagnostic = JSON.parse(observed[0]);
    assert.deepEqual(
      { event: diagnostic.event, rpc: diagnostic.rpc, phase: diagnostic.phase,
        classification: diagnostic.classification, code: diagnostic.code },
      { event: "product_postgres_failure",
        rpc: "ordax_ensure_product_mcp_target_discovery_v1",
        phase: stage, classification: "pg_connection_terminated_unexpectedly", code: "58000" },
    );
    for (const secret of [CONNECTION_SECRET, OWNER_ID, CLIENT_ID, "secret-never-logged", "internal.local"]) {
      assert.equal(observed[0].includes(secret), false, "private data leaked in " + stage);
    }
    assert.equal(Object.hasOwn(diagnostic, "message"), false);
    assert.equal(Object.hasOwn(diagnostic, "stack"), false);
    assert.equal(Object.hasOwn(diagnostic, "address"), false);
  }
});

test("canonical discovery retains exact RPC and owner/client arguments and closes the connection", async () => {
  const calls: { sql: string; params: string[] }[] = [];
  let closed = 0;
  const result = await ensureProductMcpTargetDiscovery(ENV, OWNER_ID, CLIENT_ID, {
    createClient: () => ({
      async connect() {},
      async query(sql: string, params: string[]) {
        calls.push({ sql, params });
        return { rows: [{ result: { ok: true, devices_granted: 1 } }] };
      },
      async end() { closed++; },
    }),
  });
  assert.deepEqual(result, { ok: true, devices_granted: 1 });
  assert.deepEqual(calls, [{ sql: RPC, params: [OWNER_ID, CLIENT_ID] }]);
  assert.equal(closed, 1);
});

test("invalid OAuth identity and malformed database response fail closed before target enumeration", async () => {
  let created = 0;
  const dependency = {
    createClient: () => {
      created++;
      return {
        async connect() {},
        async query() { return { rows: [{ result: { targets: ["private"] } }] }; },
        async end() {},
      };
    },
  };
  await assert.rejects(
    ensureProductMcpTargetDiscovery(ENV, OWNER_ID, "not-a-uuid", dependency),
    (error: unknown) => error instanceof ProductPostgresError
      && error.code === "product_mcp_client_identity_invalid",
  );
  assert.equal(created, 0, "invalid client cannot open a database connection");
  await assert.rejects(
    ensureProductMcpTargetDiscovery(ENV, OWNER_ID, CLIENT_ID, dependency),
    (error: unknown) => error instanceof ProductPostgresError
      && error.code === "product_postgres_invalid_response",
  );
  assert.equal(created, 1);
});
