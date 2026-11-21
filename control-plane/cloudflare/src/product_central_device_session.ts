import { authenticateProductMcpClientRequest, type ProductAuthEnv, type VerifiedProductMcpClient } from "./product_auth.ts";
import { scheduleProductDeviceWake } from "./product_device_wake.ts";
import { resolveForgeMcpInstance } from "./forge_mcp_store.ts";
import { validChatGptSessionMarker } from "./product_central_admission.ts";
import {
  confirmCentralDeviceSession,
  openCentralDeviceSession,
  pollCentralDeviceSession,
  resolveCentralDeviceSession,
} from "./product_central_device_session_store.ts";
import { ProductPostgresError, type ProductPostgresEnv } from "./product_postgres_store.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { readBoundedJsonObject } from "./request_json.ts";
import { MAX_MCP_REQUEST_BYTES, validMcpToolCallEnvelope } from "./mcp_http.ts";

type Env = ProductAuthEnv & ProductPostgresEnv & {
  // Rollout must be explicitly approved. Missing config fails closed.
  FORGE_NATIVE_DELEGATION_ENABLED?: string;
};
type Json = Record<string, unknown>;

export const PRODUCT_DEVICE_CENTRAL_SESSION_PATH = "/v3/product/device/central-session";
const TOKEN = /^[\x21-\x7e]{32,512}$/;

function json(value: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return Response.json(value, {
    status,
    headers: { "cache-control": "no-store", "x-content-type-options": "nosniff", ...extra },
  });
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * A correlation marker NEVER grants authority. Product OAuth + a fresh
 * PostgreSQL challenge + Runtime confirmation + per-action grants are always
 * required. The existing ChatGPT marker retains its original behavior.
 *
 * Forge Native uses the SAME canonical session/queue/receipt pipeline, but a
 * distinct, app-owned correlation namespace; it must not forge openai/session
 * or create an alternate device executor. Explicit rollout and existing
 * PostgreSQL Forge OAuth consent/instance are required before a challenge.
 */
type NativeClientProof = Extract<VerifiedProductMcpClient, { ok: true }>;
type NativeClientAuthorization = typeof resolveForgeMcpInstance;
type CentralMarkerContext = Readonly<{
  marker: string | null;
  nativeClientProof: NativeClientProof | null;
}>;

/** A verified native identity is reusable only in this request's open/resolve
 * call. Nothing survives the request or substitutes for the fresh SQL check. */
async function centralSessionContext(
  request: Request, env?: Env,
  authorizeNativeClient: NativeClientAuthorization = resolveForgeMcpInstance,
): Promise<CentralMarkerContext> {
  const denied = { marker: null, nativeClientProof: null } as const;
  const body = await readBoundedJsonObject(request.clone(), MAX_MCP_REQUEST_BYTES);
  if (!validMcpToolCallEnvelope(body)) return denied;
  const meta = body.params._meta;
  if (!meta || typeof meta !== "object" || Array.isArray(meta)) return denied;
  const native = (meta as Json)["ordax/native-session"];
  const chatgpt = (meta as Json)["openai/session"];
  // No ambiguous identity namespaces or shadow fallback.
  if (native !== undefined) {
    if (chatgpt !== undefined || !env
      || env.FORGE_NATIVE_DELEGATION_ENABLED !== "enabled"
      || typeof native !== "string"
      || !/^[A-Za-z0-9_-]{43}$/.test(native)) return denied;
    const identity = await authenticateProductMcpClientRequest(request.clone(), env);
    if (!identity.ok) return denied;
    // Reuse the EXACT PostgreSQL Forge consent/instance authority already
    // serving the Forge gateway. No Worker-pinned OAuth ID or second grant.
    // The idempotent Forge-instance binding NEVER selects a device or grants
    // computer execution; the Runtime attestation and grants remain mandatory.
    let forge;
    try {
      forge = await authorizeNativeClient(env, {
        ownerUserId: identity.ownerUserId, clientId: identity.clientId,
      });
    } catch { return denied; }
    if (forge?.ok !== true || !isCanonicalUuid(forge.instance_id))
      return denied;
    // Domain-separate the SQL hash from ChatGPT conversation correlations.
    // The nonce is generated only by the native Forge Core and never shown in
    // a tool result, App renderer, device selection or URL.
    return { marker: "forge-native-v1:" + native, nativeClientProof: identity };
  }
  return {
    marker: validChatGptSessionMarker(chatgpt) ? chatgpt : null,
    nativeClientProof: null,
  };
}

export async function centralSessionMarker(
  request: Request, env?: Env,
  deps: { authorizeNativeClient?: NativeClientAuthorization } = {},
): Promise<string | null> {
  return (await centralSessionContext(request, env, deps.authorizeNativeClient)).marker;
}

export async function openCentralSessionFromMcp(
  request: Request,
  env: Env,
  deps: {
    open?: typeof openCentralDeviceSession;
    authorizeNativeClient?: NativeClientAuthorization;
    signalWake?: typeof scheduleProductDeviceWake;
    scheduleWake?: (wake: Promise<void>) => void;
  } = {},
): Promise<Response> {
  const context = await centralSessionContext(request, env, deps.authorizeNativeClient);
  if (!context.marker) return json({ ok: false, error: "central_session_marker_required" }, 409);
  // Forge Native already checked this exact signed OAuth client while
  // validating its nonce; do not verify the same JWT twice in one request.
  const identity = context.nativeClientProof ?? await authenticateProductMcpClientRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
  try {
    const result = await (deps.open ?? openCentralDeviceSession)(env, {
      ownerUserId: identity.ownerUserId,
      clientId: identity.clientId,
      sessionSha256: await sha256(context.marker),
    });
    if (result.ok !== true) {
      const code = typeof result.error === "string" ? result.error : "central_session_unavailable";
      const status = code === "central_owner_selection_in_progress" ? 409
        : code === "central_device_target_ambiguous" ? 409
        : code === "central_device_offline" || code === "central_device_runtime_not_ready" ? 409
        : code === "central_device_target_missing" ? 403
        : code === "central_session_revoked" ? 403 : 503;
      return json({ ok: false, error: code }, status);
    }
    // SQL alone selects the eligible target. Notify its existing Runtime that
    // a challenge is waiting; the wake contains no challenge ID, grant or token.
    // Confirmation remains mandatory and the heartbeat fallback stays intact.
    if (result.status === "pending" && isCanonicalUuid(result.device_id)) {
      try {
        await (deps.signalWake ?? scheduleProductDeviceWake)(
          env, result.device_id, deps.scheduleWake,
        );
      } catch {
        // Best-effort notification must never invalidate the SQL challenge.
      }
    }
    return json(result, result.status === "pending" || result.status === "awaiting_owner" ? 202 : 200);
  } catch (error) {
    if (error instanceof ProductPostgresError) return json({ ok: false, error: error.code }, error.status);
    return json({ ok: false, error: "central_session_unavailable" }, 503);
  }
}

export async function resolveCentralSessionFromMcp(
  request: Request,
  env: Env,
  deps: { resolve?: typeof resolveCentralDeviceSession; authorizeNativeClient?: NativeClientAuthorization } = {},
) {
  const context = await centralSessionContext(request, env, deps.authorizeNativeClient);
  if (!context.marker) return { ok: false as const, error: "central_session_marker_required" };
  const identity = context.nativeClientProof ?? await authenticateProductMcpClientRequest(request, env);
  if (!identity.ok) return { ok: false as const, error: identity.error };
  try {
    const result = await (deps.resolve ?? resolveCentralDeviceSession)(env, {
      ownerUserId: identity.ownerUserId,
      clientId: identity.clientId,
      sessionSha256: await sha256(context.marker),
    });
    if (result.ok !== true || !isCanonicalUuid(result.device_id)) {
      return { ok: false as const, error: result.error ?? "central_session_unbound" };
    }
    return {
      ok: true as const,
      ownerUserId: identity.ownerUserId,
      clientId: identity.clientId,
      deviceId: result.device_id,
      requestId: result.request_id ?? null,
      expiresAt: result.expires_at ?? null,
    };
  } catch (error) {
    return {
      ok: false as const,
      error: error instanceof ProductPostgresError ? error.code : "central_session_unavailable",
    };
  }
}

/**
 * Device-side poll/confirm transport. Raw device tokens are hashed in memory
 * and never returned or stored by this handler. Polling/confirmation creates
 * no capability grant; it only attests which already-authorized PC owns the
 * current Product-MCP session.
 */
export async function handleProductDeviceCentralSession(
  request: Request,
  env: ProductPostgresEnv,
  deps: {
    poll?: typeof pollCentralDeviceSession;
    confirm?: typeof confirmCentralDeviceSession;
  } = {},
): Promise<Response> {
  const deviceId = request.headers.get("X-Ordax-Device-Id") ?? "";
  const token = request.headers.get("X-Ordax-Device-Token") ?? "";
  if (!isCanonicalUuid(deviceId) || !TOKEN.test(token)) {
    return json({ ok: false, error: "product_device_unauthorized" }, 401);
  }
  const tokenSha256 = await sha256(token);
  try {
    if (request.method === "GET") {
      const result = await (deps.poll ?? pollCentralDeviceSession)(env, { deviceId, tokenSha256 });
      if (result.ok !== true && result.error === "product_device_unauthorized") {
        return json({ ok: false, error: result.error }, 401);
      }
      return json(result, result.ok === true ? 200 : 503);
    }
    if (request.method !== "POST") {
      return json({ ok: false, error: "method_not_allowed" }, 405, { allow: "GET, POST" });
    }
    const mime = (request.headers.get("content-type") ?? "").split(";", 1)[0].trim().toLowerCase();
    if (mime !== "application/json") return json({ ok: false, error: "content_type_invalid" }, 415);
    const body = await readBoundedJsonObject(request, 4096);
    const challengeId = body && typeof body.challenge_id === "string" ? body.challenge_id : "";
    if (!isCanonicalUuid(challengeId) || !body || Object.keys(body).length !== 1) {
      return json({ ok: false, error: "central_session_challenge_invalid" }, 400);
    }
    const result = await (deps.confirm ?? confirmCentralDeviceSession)(env, {
      deviceId, tokenSha256, challengeId,
    });
    if (result.ok !== true) {
      const code = result.error ?? "central_session_unavailable";
      const status = code === "product_device_unauthorized" ? 401
        : code === "central_device_grant_revoked" || code === "central_session_revoked" ? 403
        : code === "central_session_challenge_invalid" || code === "central_session_challenge_expired" ? 409
        : 503;
      return json({ ok: false, error: code }, status);
    }
    return json(result);
  } catch (error) {
    if (error instanceof ProductPostgresError) return json({ ok: false, error: error.code }, error.status);
    return json({ ok: false, error: "central_session_unavailable" }, 503);
  }
}

