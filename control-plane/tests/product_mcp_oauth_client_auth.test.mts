import assert from "node:assert/strict";
import { test } from "node:test";
import { webcrypto } from "node:crypto";
import {
  authenticateProductMcpClientRequest,
  authenticateProductRequest,
  productOwnerAccountSession,
} from "../cloudflare/src/product_auth.ts";

const issuer = "https://canonical-project.supabase.co/auth/v1";
const config = {
  PRODUCT_AUTH_ISSUER: issuer,
  PRODUCT_AUTH_AUDIENCE: "authenticated",
  PRODUCT_AUTH_JWKS_URL: issuer + "/.well-known/jwks.json",
};
const subjectId = "11111111-1111-4111-8111-111111111111";
const firstClient = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const secondClient = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const encoder = new TextEncoder();
const b64 = (value: string | Uint8Array): string =>
  Buffer.from(typeof value === "string" ? encoder.encode(value) : value).toString("base64url");

async function keyPair() {
  const keys = await webcrypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const publicJwk = await webcrypto.subtle.exportKey("jwk", keys.publicKey);
  return { keys, publicJwk: { ...publicJwk, kid: "auth-key-1", alg: "RS256" } };
}

const baseClaims = () => ({
  iss: issuer, aud: "authenticated", sub: subjectId, role: "authenticated",
  exp: Math.floor(Date.now() / 1000) + 900, client_id: firstClient,
});

async function signedJwt(privateKey: CryptoKey, claims: Record<string, unknown>, header?: Record<string, unknown>): Promise<string> {
  const signingInput = b64(JSON.stringify({ alg: "RS256", kid: "auth-key-1", typ: "JWT", ...header }))
    + "." + b64(JSON.stringify(claims));
  const sig = await webcrypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, encoder.encode(signingInput));
  return signingInput + "." + b64(new Uint8Array(sig));
}

function request(jwt: string, extras?: { clientIdHeader?: string; clientIdBody?: string }): Request {
  return new Request("https://ordax.invalid/mcp", {
    method: "POST",
    headers: {
      authorization: "Bearer " + jwt,
      "content-type": "application/json",
      ...(extras?.clientIdHeader ? { "x-ordax-client-id": extras.clientIdHeader } : {}),
    },
    body: JSON.stringify({ client_id: extras?.clientIdBody ?? secondClient }),
  });
}

async function verifyWithMockIssuer(
  callback: (privateKey: CryptoKey) => Promise<void>,
): Promise<void> {
  const pair = await keyPair();
  const oldFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ keys: [pair.publicJwk] });
  try {
    await callback(pair.keys.privateKey);
  } finally {
    globalThis.fetch = oldFetch;
  }
}

test("verified OAuth JWT binds exact client and owner, never forwarded header/body", async () => {
  await verifyWithMockIssuer(async (key) => {
    const token = await signedJwt(key, baseClaims());
    const result = await authenticateProductMcpClientRequest(
      request(token, { clientIdHeader: secondClient, clientIdBody: secondClient }), config,
    );
    assert.equal(result.ok, true);
    if (!result.ok) return;
    assert.equal(result.ownerUserId, subjectId);
    assert.equal(result.clientId, firstClient);
    assert.equal(result.clientKind, "product-mcp");
  });
});

test("different signed OAuth clients of the same kind remain distinct", async () => {
  await verifyWithMockIssuer(async (key) => {
    const tokenA = await signedJwt(key, baseClaims());
    const tokenB = await signedJwt(key, { ...baseClaims(), client_id: secondClient });
    const a = await authenticateProductMcpClientRequest(request(tokenA), config);
    const b = await authenticateProductMcpClientRequest(request(tokenB), config);
    assert.equal(a.ok, true);
    assert.equal(b.ok, true);
    if (a.ok && b.ok) {
      assert.equal(a.clientKind, b.clientKind);
      assert.notEqual(a.clientId, b.clientId);
    }
  });
});

test("plain user token and user_metadata/header spoofing cannot mint MCP client authority", async () => {
  await verifyWithMockIssuer(async (key) => {
    const token = await signedJwt(key, {
      ...baseClaims(), client_id: undefined,
      user_metadata: { client_id: firstClient },
      app_metadata: { client_id: firstClient },
    });
    const normal = await authenticateProductRequest(request(token), config);
    assert.equal(normal.ok, true);
    const mcp = await authenticateProductMcpClientRequest(
      request(token, { clientIdHeader: firstClient, clientIdBody: firstClient }), config,
    );
    assert.deepEqual(mcp, { ok: false, error: "product_mcp_oauth_client_required", status: 403 });
  });
});

test("unsigned/malformed OAuth client_id, non-authenticated role and legacy subject fail closed", async () => {
  await verifyWithMockIssuer(async (key) => {
    const variants: Array<Record<string, unknown>> = [
      { ...baseClaims(), client_id: "bad" },
      { ...baseClaims(), client_id: null },
      { ...baseClaims(), role: "anon" },
      { ...baseClaims(), sub: "legacy:user-name" },
      { ...baseClaims(), client_id: { client_id: firstClient } },
    ];
    for (const claims of variants) {
      const token = await signedJwt(key, claims);
      const result = await authenticateProductMcpClientRequest(request(token), config);
      assert.equal(result.ok, false, JSON.stringify(claims));
      if (!result.ok) assert.equal(result.status, 403);
    }
  });
});

test("tampering a signed client_id claim invalidates the token signature", async () => {
  await verifyWithMockIssuer(async (key) => {
    const signed = await signedJwt(key, baseClaims());
    const chunks = signed.split(".");
    const altered = chunks[0] + "." + b64(JSON.stringify({ ...baseClaims(), client_id: secondClient })) + "." + chunks[2];
    const result = await authenticateProductMcpClientRequest(request(altered), config);
    assert.deepEqual(result, { ok: false, error: "product_signature_invalid", status: 401 });
  });
});

test("invalid issuer/audience and unauthenticated token still fail at JWT boundary", async () => {
  await verifyWithMockIssuer(async (key) => {
    for (const claims of [
      { ...baseClaims(), iss: "https://evil.invalid/auth/v1" },
      { ...baseClaims(), aud: "another-api" },
      { ...baseClaims(), exp: Math.floor(Date.now() / 1000) - 3600 },
    ]) {
      const result = await authenticateProductMcpClientRequest(request(await signedJwt(key, claims)), config);
      assert.equal(result.ok, false);
      if (!result.ok) assert.equal(result.status, 401);
    }
  });
});

test("owner account JWT without OAuth client authenticates session but cannot access MCP", async () => {
  await verifyWithMockIssuer(async key => {
    const token = await signedJwt(key, { ...baseClaims(), client_id: undefined });
    const owner = await productOwnerAccountSession(request(token), config);
    const body = await owner.json();
    assert.equal(owner.status, 200);
    assert.equal(body.session.subject_id, subjectId);
    assert.equal(body.session.client_id, undefined);
    assert.equal(owner.headers.get("cache-control"), "no-store");
    const mcp = await authenticateProductMcpClientRequest(request(token), config);
    assert.deepEqual(mcp, { ok: false, error: "product_mcp_oauth_client_required", status: 403 });
  });
});

test("owner session refuses non-owner role and unverifiable subject", async () => {
  await verifyWithMockIssuer(async key => {
    for (const claims of [
      { ...baseClaims(), role: "anon", client_id: undefined },
      { ...baseClaims(), sub: "legacy-identifier", client_id: undefined },
    ]) {
      const res = await productOwnerAccountSession(request(await signedJwt(key, claims)), config);
      assert.equal(res.status, 403);
      assert.equal((await res.json()).error, "product_owner_identity_invalid");
    }
  });
});
