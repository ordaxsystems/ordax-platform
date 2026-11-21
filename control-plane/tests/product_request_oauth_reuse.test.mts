import test from "node:test";
import assert from "node:assert/strict";
import {
  requestScopedProductMcpAuthenticator,
} from "../cloudflare/src/product_auth.ts";
import {
  createCanonicalProductMcpGateway,
} from "../cloudflare/src/product_mcp_entry.ts";
import {
  env, owner, otherClient, client, requestId, token, withIssuer,
} from "./product_mcp_test_fixtures.mts";

function trackSignatureVerifications() {
  const native = crypto.subtle.verify.bind(crypto.subtle);
  const prior = Object.getOwnPropertyDescriptor(crypto.subtle, "verify");
  let count = 0;
  Object.defineProperty(crypto.subtle, "verify", {
    configurable: true,
    value: async (...args: Parameters<SubtleCrypto["verify"]>) => {
      count++;
      return native(...args);
    },
  });
  return {
    count: () => count,
    restore() {
      if (prior) Object.defineProperty(crypto.subtle, "verify", prior);
      else Reflect.deleteProperty(crypto.subtle, "verify");
    },
  };
}

function statusRequest(jwt: string) {
  return new Request("https://mcp.ordax.com.br/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer " + jwt },
    body: JSON.stringify({ jsonrpc: "2.0", id: 17, method: "tools/call", params: {
      name: "ordax_action_status", arguments: { request_id: requestId },
    } }),
  });
}

test("status MCP verifies OAuth once for session probe and current SQL-status adapter", async () => {
  await withIssuer(async () => {
    const jwt = await token();
    const counter = trackSignatureVerifications();
    try {
      const gateway = createCanonicalProductMcpGateway(env);
      const response = await gateway(statusRequest(jwt));
      assert.equal(response.status, 200);
      const payload = await response.json() as any;
      assert.equal(payload.result.structuredContent.ok, false,
        "PostgreSQL is intentionally not configured in this fixture");
      assert.equal(counter.count(), 1,
        "the request's status read must reuse the signed session identity, not reverify it");
    } finally { counter.restore(); }
  });
});

test("two MCP requests never share a verified bearer even through the same gateway instance", async () => {
  await withIssuer(async () => {
    const jwt = await token();
    const gateway = createCanonicalProductMcpGateway(env);
    const counter = trackSignatureVerifications();
    try {
      await gateway(statusRequest(jwt));
      assert.equal(counter.count(), 1);
      await gateway(statusRequest(jwt));
      assert.equal(counter.count(), 2,
        "request-local proof must not survive into the next HTTP request");
    } finally { counter.restore(); }
  });
});

test("request proof rejects a different bearer or environment and never trusts a spoofed client header", async () => {
  await withIssuer(async () => {
    const first = await token();
    const second = await token({ client_id: otherClient });
    const source = new Request("https://mcp.ordax.com.br/mcp", {
      headers: { authorization: "Bearer " + first },
    });
    const authenticate = requestScopedProductMcpAuthenticator(source, env);
    const counter = trackSignatureVerifications();
    try {
      const a = await authenticate(source, env);
      assert.equal(a.ok, true);
      assert.equal(a.ok && a.ownerUserId, owner);
      assert.equal(a.ok && a.clientId, client);
      assert.equal(counter.count(), 1);

      const clone = new Request("https://mcp.ordax.com.br/v3/product/actions", {
        method: "GET", headers: { authorization: "Bearer " + first,
          "x-ordax-client-id": otherClient },
      });
      const b = await authenticate(clone, env);
      assert.deepEqual(b, a);
      assert.equal(counter.count(), 1);

      const changed = await authenticate(new Request("https://mcp.ordax.com.br/mcp", {
        headers: { authorization: "Bearer " + second },
      }), env);
      assert.equal(changed.ok && changed.clientId, otherClient);
      assert.equal(counter.count(), 2, "changed bearer must be reverified");
      const otherEnvironment = await authenticate(clone, { ...env });
      assert.equal(otherEnvironment.ok, true);
      assert.equal(counter.count(), 3, "another verification environment cannot reuse proof");
    } finally { counter.restore(); }
  });
});

test("request-local proof rechecks OAuth expiration before every reuse", async () => {
  await withIssuer(async () => {
    const now = Math.floor(Date.now() / 1000);
    const expiry = now + 5;
    const jwt = await token({ exp: expiry });
    const source = new Request("https://mcp.ordax.com.br/mcp", {
      headers: { authorization: "Bearer " + jwt },
    });
    const authenticate = requestScopedProductMcpAuthenticator(source, env);
    const initial = await authenticate(source, env);
    assert.equal(initial.ok, true);
    const originalNow = Date.now;
    try {
      Date.now = () => (expiry + 61) * 1000;
      const stale = await authenticate(source, env);
      assert.deepEqual(stale, { ok: false, error: "product_token_claims_invalid", status: 401 });
    } finally { Date.now = originalNow; }
  });
});
