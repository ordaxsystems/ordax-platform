import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

const issuer = "https://discovery-project.supabase.co/auth/v1";
export const env = {
  PRODUCT_AUTH_ISSUER: issuer,
  PRODUCT_AUTH_AUDIENCE: "authenticated",
  PRODUCT_AUTH_JWKS_URL: issuer + "/.well-known/jwks.json",
};
export const owner = "11111111-1111-4111-8111-111111111111";
export const otherOwner = "22222222-2222-4222-8222-222222222222";
export const client = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const otherClient = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
export const device = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
export const secondDevice = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
export const requestId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
export const projectId = "33333333-3333-4333-8333-333333333333";
export const effectId = "44444444-4444-4444-8444-444444444444";
const encoder = new TextEncoder();
const b64 = (value: string | Uint8Array) => Buffer.from(value).toString("base64url");
const keys = webcrypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true, ["sign", "verify"],
);

export async function token(overrides: Record<string, unknown> = {}) {
  const pair = await keys;
  const unsigned = b64(JSON.stringify({ alg: "RS256", kid: "discovery-1" })) + "." + b64(JSON.stringify({
    iss: issuer, aud: "authenticated", role: "authenticated", sub: owner,
    client_id: client, exp: Math.floor(Date.now() / 1000) + 900, ...overrides,
  }));
  const signature = await webcrypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, encoder.encode(unsigned));
  return unsigned + "." + b64(new Uint8Array(signature));
}

export async function withIssuer(run: () => Promise<void>) {
  const pair = await keys;
  const jwk = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
  const previous = globalThis.fetch;
  globalThis.fetch = async (url) => {
    assert.equal(String(url), env.PRODUCT_AUTH_JWKS_URL);
    return Response.json({ keys: [{ ...jwk, kid: "discovery-1", alg: "RS256" }] });
  };
  try { await run(); } finally { globalThis.fetch = previous; }
}

export function request(jwt: string, path = "/v3/product/targets") {
  return new Request("https://ordax.example" + path, {
    headers: { authorization: "Bearer " + jwt, "x-ordax-client-id": otherClient, "x-ordax-owner-user-id": otherOwner },
  });
}

export function catalog() {
  return { ok: true, targets: [
    { device_id: device, device_name: "Meu desktop", online: true, private_token: "private-device-token",
      grant_groups: [{ grant_group_id: "internal-group", profile_key: "project-read", space_id: null, project_id: null,
        valid_until: null, capabilities: [{ capability: "computer.windows", access_mode: "read" }] }] },
    { device_id: secondDevice, device_name: "Notebook", online: false, last_seen_at: "2026-10-09T12:00:00Z" },
  ] };
}

export function actionRecord(overrides: Record<string, unknown> = {}) {
  return {
    ok: true, request_id: requestId, device_id: device, project_id: projectId,
    capability: "project.text_read", status: "running", effect_id: effectId,
    result: null, error_code: null,
    execution_runtime_kind: null, execution_agent_version: null,
    created_at: "2026-10-09T12:00:00Z",
    started_at: "2026-10-09T12:01:00Z", finished_at: null,
    ...overrides,
  };
}