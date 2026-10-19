import assert from "node:assert/strict";
import test from "node:test";
import { checkCanonicalProductPostgresReadiness } from "../cloudflare/src/product_postgres_store.ts";
import { createCanonicalProductMcpGateway } from "../cloudflare/src/product_mcp_entry.ts";

const SECRET = "postgres://private-user:private-password@private-db.invalid/private-db";
const ENV = {
  PRODUCT_AUTH_ISSUER: "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1",
  PRODUCT_AUTH_AUDIENCE: "authenticated",
  PRODUCT_AUTH_JWKS_URL: "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1/.well-known/jwks.json",
  POSTGRES: { connectionString: SECRET },
};
const response = (body: unknown) => Response.json(body);
const metadata = () => ({
  issuer: ENV.PRODUCT_AUTH_ISSUER,
  authorization_endpoint: ENV.PRODUCT_AUTH_ISSUER + "/oauth/authorize",
  token_endpoint: ENV.PRODUCT_AUTH_ISSUER + "/oauth/token",
  registration_endpoint: ENV.PRODUCT_AUTH_ISSUER + "/oauth/clients",
  code_challenge_methods_supported: ["S256"],
  grant_types_supported: ["authorization_code"],
  response_types_supported: ["code"],
  token_endpoint_auth_methods_supported: ["none"],
});
const oauthOk = (async () => response(metadata())) as typeof fetch;
const noActions = {
  session: async () => response({ ok: true }),
  targets: async () => response({ ok: true, targets: [] }),
  getAction: async () => response({ ok: false }),
};

test("a real SQL round trip, not a configured URL, is required for readiness", async () => {
  let connectCount = 0;
  let queryCount = 0;
  let endCount = 0;
  const result = await checkCanonicalProductPostgresReadiness(ENV, value => {
    assert.equal(value, SECRET);
    return {
      async connect() { connectCount++; },
      async query(sql) {
        queryCount++;
        assert.equal(sql, "select 1::int as alive");
        return { rows: [{ alive: 1 }] };
      },
      async end() { endCount++; },
    };
  });
  assert.deepEqual(result, { ok: true, error: null });
  assert.equal(connectCount, 1);
  assert.equal(queryCount, 1);
  assert.equal(endCount, 1);
});

test("a configured but disconnected Hyperdrive reports not ready, even with healthy OAuth", async () => {
  let endCount = 0;
  const failure = Object.assign(new Error("private credentials " + SECRET), { code: "58000" });
  const check = () => checkCanonicalProductPostgresReadiness(ENV, () => ({
    async connect() { throw failure; },
    async query() { throw new Error("SQL must never run without a connection"); },
    async end() { endCount++; },
  }));
  assert.deepEqual(await check(), {
    ok: false, error: "product_postgres_unavailable", failure_stage: "connect",
  });
  assert.equal(endCount, 1);
  const handler = createCanonicalProductMcpGateway(ENV, noActions, oauthOk, undefined, {}, check);
  const answer = await handler(new Request("https://mcp.ordax.com.br/ready"));
  assert.equal(answer.status, 503);
  const body = await answer.json();
  assert.deepEqual(body, {
    ok: false, service: "ordax-platform-mcp",
    oauth_discovery_ready: true, postgres_ready: false,
    conversation_topology: "user_chatgpt_direct", model_relay: false,
    supports_attested_remote_reads: false, supports_remote_actions: false,
    error: "product_postgres_unavailable", postgres_failure_stage: "connect",
  });
  assert.equal(answer.headers.get("cache-control"), "no-store");
  assert.equal(endCount, 2);
  assert.equal(JSON.stringify(body).includes(SECRET), false);
});

test("readiness classifies failed connect, query and malformed result without disclosing secrets", async () => {
  for (const stage of ["connect", "query", "decode"] as const) {
    let closed = 0;
    let queried = false;
    const probe = await checkCanonicalProductPostgresReadiness(ENV, () => ({
      async connect() {
        if (stage === "connect") throw new Error(SECRET);
      },
      async query() {
        queried = true;
        if (stage === "query") throw new Error(SECRET);
        return { rows: [{ alive: "not-number" }] };
      },
      async end() { closed++; },
    }));
    assert.deepEqual(probe, {
      ok: false, error: "product_postgres_unavailable", failure_stage: stage,
    });
    assert.equal(closed, 1);
    assert.equal(queried, stage !== "connect");
    assert.equal(JSON.stringify(probe).includes(SECRET), false);
  }
});

test("invalid DB config fails without opening a connection", async () => {
  let opened = false;
  const res = await checkCanonicalProductPostgresReadiness({}, () => {
    opened = true;
    throw new Error("must not open");
  });
  assert.deepEqual(res, { ok: false, error: "product_postgres_unconfigured" });
  assert.equal(opened, false);
});

test("OAuth failure does not connect to PostgreSQL; readiness does not claim actions", async () => {
  let connected = false;
  const badOauth = (async () => new Response(null, { status: 503 })) as typeof fetch;
  const handler = createCanonicalProductMcpGateway(ENV, noActions, badOauth, undefined, {},
    async () => { connected = true; return { ok: true, error: null }; });
  const res = await handler(new Request("https://mcp.ordax.com.br/ready"));
  const body = await res.json() as Record<string,unknown>;
  assert.equal(res.status, 503);
  assert.equal(body.oauth_discovery_ready, false);
  assert.equal(body.postgres_ready, null);
  assert.equal(body.supports_remote_actions, false);
  assert.equal(connected, false);
});
