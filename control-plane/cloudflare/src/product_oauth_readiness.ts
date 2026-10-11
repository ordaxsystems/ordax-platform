/**
 * OAuth 2.1 discovery readiness for the canonical Supabase issuer.
 *
 * Verifies public metadata only. Never creates users, registers clients,
 * grants device access, reads secrets or authorizes a model/Runtime.
 * Used by the canonical Product MCP readiness probe, not a second auth owner.
 */
const MAX_METADATA_BYTES = 64 * 1024;
const CANONICAL_ISSUER = /^https:\/\/[a-z0-9]{20}\.supabase\.co\/auth\/v1$/;

export type ProductOAuthDiscovery = Readonly<{
  ok: boolean;
  error: "oauth_issuer_invalid" | "oauth_discovery_unavailable" | "oauth_discovery_invalid" | null;
  upstream_http_status?: number;
  /** Diagnostic phase only; never return exception messages or upstream bodies. */
  failure_stage?: "fetch" | "read_metadata";
}>;

function validEndpoint(value: unknown, issuer: string): boolean {
  if (typeof value !== "string") return false;
  try {
    const endpoint = new URL(value);
    const base = new URL(issuer);
    return endpoint.protocol === "https:"
      && endpoint.origin === base.origin
      && endpoint.username === "" && endpoint.password === ""
      && endpoint.search === "" && endpoint.hash === ""
      && endpoint.pathname.startsWith("/auth/v1/")
      && !endpoint.pathname.startsWith("/auth/v1//");
  } catch {
    return false;
  }
}

function validMetadata(value: unknown, issuer: string): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const metadata = value as Record<string, unknown>;
  return metadata.issuer === issuer
    && ["authorization_endpoint", "token_endpoint", "registration_endpoint"]
      .every(key => validEndpoint(metadata[key], issuer))
    && Array.isArray(metadata.code_challenge_methods_supported)
    && metadata.code_challenge_methods_supported.includes("S256")
    && Array.isArray(metadata.grant_types_supported)
    && metadata.grant_types_supported.includes("authorization_code")
    && Array.isArray(metadata.response_types_supported)
    && metadata.response_types_supported.includes("code")
    && Array.isArray(metadata.token_endpoint_auth_methods_supported)
    && metadata.token_endpoint_auth_methods_supported.includes("none");
}

async function boundedMetadata(response: Response): Promise<unknown> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    const declared = Number(contentLength);
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > MAX_METADATA_BYTES) {
      throw new Error("oauth_discovery_oversized");
    }
  }
  if (!response.body) throw new Error("oauth_discovery_empty");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let count = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      count += value.byteLength;
      if (count > MAX_METADATA_BYTES) throw new Error("oauth_discovery_oversized");
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  const bytes = new Uint8Array(count);
  let offset = 0;
  for (const part of chunks) {
    bytes.set(part, offset);
    offset += part.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

export async function checkCanonicalProductOAuthDiscovery(
  issuer: string,
  fetchDiscovery: typeof fetch = fetch,
): Promise<ProductOAuthDiscovery> {
  if (!CANONICAL_ISSUER.test(issuer)) {
    return { ok: false, error: "oauth_issuer_invalid" };
  }
  const url = issuer.slice(0, -"/auth/v1".length)
    + "/.well-known/oauth-authorization-server/auth/v1";
  // Distinguish a network/runtime failure from an unreadable metadata body.
  // No exception text, upstream response body, user data or tokens are exposed.
  let response: Response;
  try {
    response = await fetchDiscovery(url, {
      method: "GET",
      redirect: "error",
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    return { ok: false, error: "oauth_discovery_unavailable", failure_stage: "fetch" };
  }
  if (response.status !== 200 || !response.ok) {
    return { ok: false, error: "oauth_discovery_unavailable", upstream_http_status: response.status };
  }
  let metadata: unknown;
  try {
    metadata = await boundedMetadata(response);
  } catch {
    return { ok: false, error: "oauth_discovery_unavailable", failure_stage: "read_metadata" };
  }
  if (!validMetadata(metadata, issuer)) {
    return { ok: false, error: "oauth_discovery_invalid" };
  }
  return { ok: true, error: null };
}
