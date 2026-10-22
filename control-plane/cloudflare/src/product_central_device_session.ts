import { authenticateProductMcpClientRequest, type ProductAuthEnv } from "./product_auth.ts";
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

type Env = ProductAuthEnv & ProductPostgresEnv;
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
 * Read the ChatGPT correlation marker from a tools/call request. This value is
 * NEVER authority by itself. It becomes useful only after an exact Product
 * OAuth client opens a challenge and the exact Product device confirms it.
 */
export async function centralSessionMarker(request: Request): Promise<string | null> {
  try {
    const body = await request.clone().json() as Json;
    if (!body || body.jsonrpc !== "2.0" || body.method !== "tools/call") return null;
    const params = body.params;
    if (!params || typeof params !== "object" || Array.isArray(params)) return null;
    const meta = (params as Json)._meta;
    if (!meta || typeof meta !== "object" || Array.isArray(meta)) return null;
    const marker = (meta as Json)["openai/session"];
    return validChatGptSessionMarker(marker) ? marker : null;
  } catch {
    return null;
  }
}

export async function openCentralSessionFromMcp(
  request: Request,
  env: Env,
  deps: { open?: typeof openCentralDeviceSession } = {},
): Promise<Response> {
  const marker = await centralSessionMarker(request);
  if (!marker) return json({ ok: false, error: "central_session_marker_required" }, 409);
  const identity = await authenticateProductMcpClientRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
  try {
    const result = await (deps.open ?? openCentralDeviceSession)(env, {
      ownerUserId: identity.ownerUserId,
      clientId: identity.clientId,
      sessionSha256: await sha256(marker),
    });
    if (result.ok !== true) {
      const code = typeof result.error === "string" ? result.error : "central_session_unavailable";
      const status = code === "central_device_target_ambiguous" ? 409
        : code === "central_device_offline" || code === "central_device_runtime_not_ready" ? 409
        : code === "central_device_target_missing" ? 403
        : code === "central_session_revoked" ? 403 : 503;
      return json({ ok: false, error: code }, status);
    }
    return json(result, result.status === "pending" ? 202 : 200);
  } catch (error) {
    if (error instanceof ProductPostgresError) return json({ ok: false, error: error.code }, error.status);
    return json({ ok: false, error: "central_session_unavailable" }, 503);
  }
}

export async function resolveCentralSessionFromMcp(
  request: Request,
  env: Env,
  deps: { resolve?: typeof resolveCentralDeviceSession } = {},
) {
  const marker = await centralSessionMarker(request);
  if (!marker) return { ok: false as const, error: "central_session_marker_required" };
  const identity = await authenticateProductMcpClientRequest(request, env);
  if (!identity.ok) return { ok: false as const, error: identity.error };
  try {
    const result = await (deps.resolve ?? resolveCentralDeviceSession)(env, {
      ownerUserId: identity.ownerUserId,
      clientId: identity.clientId,
      sessionSha256: await sha256(marker),
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

