import assert from "node:assert/strict";
import { before, test } from "node:test";
import { authenticateProductRequest } from "../cloudflare/src/product_auth.ts";

const env = {
  PRODUCT_AUTH_ISSUER: "https://identity.example",
  PRODUCT_AUTH_AUDIENCE: "authenticated",
  PRODUCT_AUTH_JWKS_URL: "https://identity.example/auth/v1/.well-known/jwks.json",
};

let publicJwk: JsonWebKey;
let token: string;
before(async () => {
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, ["sign", "verify"],
  );
  publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const input = [
    encode({ alg: "RS256", kid: "test-key" }),
    encode({
      iss: env.PRODUCT_AUTH_ISSUER,
      aud: env.PRODUCT_AUTH_AUDIENCE,
      sub: "22222222-2222-4222-8222-222222222222",
      exp: Math.floor(Date.now() / 1000) + 600,
    }),
  ].join(".");
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5", keyPair.privateKey,
    new TextEncoder().encode(input),
  );
  token = input + "." + Buffer.from(signature).toString("base64url");
});

const signedRequest = () => new Request("https://ordax.example/v3/product/session", {
  headers: { authorization: "Bearer " + token },
});

test("signed Supabase-style JWT remains valid with the shared bounded JWKS reader", async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    return Response.json({ keys: [{ ...publicJwk, kid: "test-key", alg: "RS256" }] });
  }) as typeof fetch;
  try {
    const result = await authenticateProductRequest(signedRequest(), env);
    assert.equal(result.ok, true);
    if (result.ok) assert.equal(result.subjectId, "22222222-2222-4222-8222-222222222222");
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("JWKS public-key imports are shared across concurrent verification, not token outcomes", async () => {
  const originalFetch = globalThis.fetch;
  const originalImport = crypto.subtle.importKey;
  const originalDescriptor = Object.getOwnPropertyDescriptor(crypto.subtle, "importKey");
  let fetches = 0;
  let imports = 0;
  const isolatedEnv = {
    ...env,
    PRODUCT_AUTH_JWKS_URL: env.PRODUCT_AUTH_JWKS_URL + "?fixture=shared-crypto-key",
  };
  globalThis.fetch = (async () => {
    fetches++;
    return Response.json({ keys: [{ ...publicJwk, kid: "test-key", alg: "RS256" }] });
  }) as typeof fetch;
  Object.defineProperty(crypto.subtle, "importKey", {
    configurable: true,
    value: (...args: unknown[]) => {
      imports++;
      return Reflect.apply(originalImport, crypto.subtle, args);
    },
  });
  try {
    const verified = await Promise.all(Array.from(
      { length: 8 }, () => authenticateProductRequest(signedRequest(), isolatedEnv),
    ));
    assert.ok(verified.every((result) => result.ok === true));
    assert.equal(fetches, 1, "concurrent JWKS reads should already coalesce");
    assert.equal(imports, 1, "verified public key should import once per JWKS object");
    const rejected = await authenticateProductRequest(
      new Request("https://ordax.example/v3/product/session", {
        headers: { authorization: "Bearer invalid" },
      }),
      isolatedEnv,
    );
    assert.equal(rejected.ok, false, "a cached public key cannot cache authorization");
    assert.equal(imports, 1);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalDescriptor) Object.defineProperty(crypto.subtle, "importKey", originalDescriptor);
    else Reflect.deleteProperty(crypto.subtle, "importKey");
  }
});

test("oversized/infinite JWKS response is cancelled and does not authorize a JWT", async () => {
  const originalFetch = globalThis.fetch;
  let chunksRead = 0;
  let cancelled = false;
  globalThis.fetch = (async () => new Response(new ReadableStream({
    pull(controller) {
      chunksRead++;
      controller.enqueue(new Uint8Array(8192));
    },
    cancel() { cancelled = true; },
  }), { status: 200, headers: { "content-type": "application/json" } })) as typeof fetch;
  try {
    const result = await authenticateProductRequest(signedRequest(), { ...env, PRODUCT_AUTH_JWKS_URL: env.PRODUCT_AUTH_JWKS_URL + "?fixture=oversized" });
    assert.deepEqual(result, { ok: false, error: "product_signing_key_not_found", status: 401 });
    assert.equal(cancelled, true);
    assert.ok(chunksRead >= 17 && chunksRead <= 19, "JWKS size cap failed: " + chunksRead);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("unexpectedly large JWKS key collections fail closed", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => Response.json({
    keys: Array.from({ length: 65 }, () => ({ ...publicJwk, kid: "test-key", alg: "RS256" })),
  })) as typeof fetch;
  try {
    const result = await authenticateProductRequest(signedRequest(), { ...env, PRODUCT_AUTH_JWKS_URL: env.PRODUCT_AUTH_JWKS_URL + "?fixture=too-many-keys" });
    assert.deepEqual(result, { ok: false, error: "product_signing_key_not_found", status: 401 });
  } finally {
    globalThis.fetch = originalFetch;
  }
});
