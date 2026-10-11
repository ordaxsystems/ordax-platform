import assert from "node:assert/strict";
import test from "node:test";
import { checkCanonicalProductOAuthDiscovery } from "../cloudflare/src/product_oauth_readiness.ts";
import { createCanonicalProductMcpGateway } from "../cloudflare/src/product_mcp_entry.ts";

const ISSUER = "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1";
const DISCOVERY_URL = "https://jhfphsjptrpmtnzkpwud.supabase.co/.well-known/oauth-authorization-server/auth/v1";
const metadata = () => ({
  issuer: ISSUER,
  authorization_endpoint: ISSUER + "/oauth/authorize",
  token_endpoint: ISSUER + "/oauth/token",
  registration_endpoint: ISSUER + "/oauth/clients",
  code_challenge_methods_supported: ["S256"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  response_types_supported: ["code"],
  token_endpoint_auth_methods_supported: ["none", "client_secret_basic"],
});
const response = (object: unknown, status = 200) => Response.json(object, { status });
const env = {
  PRODUCT_AUTH_ISSUER: ISSUER,
  PRODUCT_AUTH_AUDIENCE: "authenticated",
  PRODUCT_AUTH_JWKS_URL: ISSUER + "/.well-known/jwks.json",
  POSTGRES: { connectionString: "postgresql://localhost:6543/example" },
};
const handlers = {
  session: async () => response({ ok: true, session: { subject_id: "server-subject" } }),
  targets: async () => response({ ok: true, targets: [] }),
  getAction: async () => response({ ok: false, error: "not_found" }, 404),
};

test("ready uses canonical discovery URL with 5s deadline and rejects redirects", async () => {
  let calls = 0;
  const fake = (async (url: RequestInfo | URL, options?: RequestInit) => {
    calls++;
    assert.equal(url, DISCOVERY_URL);
    assert.equal(options?.redirect, "error");
    assert.equal(options?.method, "GET");
    assert.equal(options?.headers && (options.headers as Record<string,string>).accept, "application/json");
    assert.ok(options?.signal instanceof AbortSignal);
    return response(metadata());
  }) as typeof fetch;
  assert.deepEqual(await checkCanonicalProductOAuthDiscovery(ISSUER, fake), { ok: true, error: null });
  const run = createCanonicalProductMcpGateway(env, handlers, fake);
  const result = await run(new Request("https://platform.example/ready"));
  assert.equal(result.status, 200);
  assert.deepEqual(await result.json(), {
    ok: true, service: "ordax-platform-mcp", oauth_discovery_ready: true, supports_remote_actions: false,
  });
  assert.equal(calls, 2);
});

test("disabled Supabase OAuth 2.1 server does not turn configured variables into working OAuth", async () => {
  const unavailable = (async () => response({ code: 404, error_code: "feature_disabled" }, 404)) as typeof fetch;
  assert.deepEqual(await checkCanonicalProductOAuthDiscovery(ISSUER, unavailable), {
    ok: false, error: "oauth_discovery_unavailable", upstream_http_status: 404,
  });
  const run = createCanonicalProductMcpGateway(env, handlers, unavailable);
  const status = await run(new Request("https://platform.example/ready"));
  assert.equal(status.status, 503);
  assert.deepEqual(await status.json(), {
    ok: false, service: "ordax-platform-mcp", oauth_discovery_ready: false,
    supports_remote_actions: false, error: "oauth_discovery_unavailable", upstream_http_status: 404,
  });
  assert.equal(status.headers.get("cache-control"), "no-store");
  const health = await run(new Request("https://platform.example/health"));
  assert.equal(health.status, 200);
  assert.equal((await health.json()).auth_configured, true);
});

test("disabled/unconfigured and malformed issuer never initiate external fetch", async () => {
  let calls = 0;
  const fake = (async () => { calls++; throw new Error("unexpected external call"); }) as typeof fetch;
  const noConfig = createCanonicalProductMcpGateway({}, handlers, fake);
  const result = await noConfig(new Request("https://platform.example/ready"));
  assert.equal(result.status, 503);
  assert.equal((await result.json()).error, "platform_mcp_unconfigured");
  assert.deepEqual(await checkCanonicalProductOAuthDiscovery("https://attacker.invalid/auth/v1", fake), {
    ok: false, error: "oauth_issuer_invalid",
  });
  assert.equal(calls, 0);
});

test("issuer, DCR, public PKCE and endpoint origins must match the canonical OAuth Server", async () => {
  for (const change of [
    { issuer: "https://another.supabase.co/auth/v1" },
    { registration_endpoint: "https://evil.example/auth/v1/oauth/clients" },
    { registration_endpoint: ISSUER + "/oauth/clients?secret=1" },
    { authorization_endpoint: "http://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1/oauth/authorize" },
    { token_endpoint: ISSUER + "//oauth/token" },
    { code_challenge_methods_supported: ["plain"] },
    { grant_types_supported: ["refresh_token"] },
    { response_types_supported: ["token"] },
    { token_endpoint_auth_methods_supported: ["client_secret_basic"] },
    { registration_endpoint: undefined },
  ]) {
    const fake = (async () => response({ ...metadata(), ...change })) as typeof fetch;
    const res = await checkCanonicalProductOAuthDiscovery(ISSUER, fake);
    assert.equal(res.ok, false, JSON.stringify(change));
    assert.equal(res.error, "oauth_discovery_invalid");
  }
});

test("network errors, 302 responses, JSON parse errors and oversized bodies fail without credentials", async () => {
  for (const fake of [
    (async () => { throw new Error("private network diagnostics"); }) as typeof fetch,
    (async () => response({ redirect: true }, 302)) as typeof fetch,
    (async () => new Response("not json", { status: 200 })) as typeof fetch,
    (async () => new Response("x".repeat(65537), { status: 200 })) as typeof fetch,
    (async () => new Response("{}", { status: 200, headers: { "content-length": "999999" } })) as typeof fetch,
  ]) {
    const res = await checkCanonicalProductOAuthDiscovery(ISSUER, fake);
    assert.equal(res.ok, false);
    assert.ok(["oauth_discovery_unavailable","oauth_discovery_invalid"].includes(String(res.error)));
  }
});
