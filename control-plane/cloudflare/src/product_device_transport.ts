/**
 * Canonical Product device transport over PostgreSQL.
 *
 * This is the only device execution transport for the Product MCP path.
 * Durable identity, presence, queue state, leases and results live in PostgreSQL.
 * No D1, global operator bearer, legacy pairing database or business-state DO is used.
 */
import {
  authenticateProductDevice,
  claimProductAction,
  progressProductAction,
  recordProductPresence,
  renewProductActionLease,
  reportProductAction,
  startProductAction,
  ProductPostgresError,
  type ProductPostgresEnv,
  type ProductRemoteJob,
} from "./product_postgres_store.ts";
import { readBoundedJsonObject } from "./request_json.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";

type Json = Record<string, unknown>;
export const PRODUCT_DEVICE_TRANSPORT_PREFIX = "/v3/device/transport";
const HEX64 = /^[0-9a-f]{64}$/;

function respond(value: unknown, status = 200): Response {
  return Response.json(value, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (item) => item.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array | null {
  if (!value || value.length > 1024 * 1024 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return null;
  try {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    return bytes;
  } catch {
    return null;
  }
}

async function authenticateDeviceRequest(
  request: Request,
  env: ProductPostgresEnv,
): Promise<{ ok: true; deviceId: string } | { ok: false; response: Response }> {
  const deviceId = (request.headers.get("x-ordax-device-id") ?? "").trim().toLowerCase();
  const rawToken = request.headers.get("x-ordax-device-token") ?? "";
  if (!isCanonicalUuid(deviceId) || rawToken.length < 32 || rawToken.length > 512
      || /[\r\n]/.test(rawToken)) {
    return { ok: false, response: respond({ ok: false, error: "device_auth_required" }, 401) };
  }
  try {
    const accepted = await authenticateProductDevice(env, {
      deviceId,
      tokenSha256: await sha256Hex(rawToken),
    });
    if (!accepted) {
      return { ok: false, response: respond({ ok: false, error: "invalid_device_token" }, 401) };
    }
    return { ok: true, deviceId };
  } catch (error) {
    if (error instanceof ProductPostgresError) {
      return { ok: false, response: respond({ ok: false, error: error.code }, error.status) };
    }
    return { ok: false, response: respond({ ok: false, error: "product_postgres_unavailable" }, 503) };
  }
}

function runtimeIdentity(body: Json): { agentInstanceId: string; bootId: string } | null {
  const agentInstanceId = typeof body.agent_instance_id === "string"
    ? body.agent_instance_id.toLowerCase() : "";
  const bootId = typeof body.boot_id === "string" ? body.boot_id.trim() : "";
  if (!isCanonicalUuid(agentInstanceId) || bootId.length < 8 || bootId.length > 160
      || /[\x00-\x20\x7f]/u.test(bootId)) return null;
  return { agentInstanceId, bootId };
}

function executionContext(body: Json) {
  const requestId = typeof body.job_id === "string" ? body.job_id.toLowerCase() : "";
  const effectId = typeof body.effect_id === "string" ? body.effect_id.toLowerCase() : "";
  const attemptId = typeof body.attempt_id === "string" ? body.attempt_id.toLowerCase() : "";
  const leaseId = typeof body.lease_id === "string" ? body.lease_id.toLowerCase() : "";
  const identity = runtimeIdentity(body);
  const executionEpoch = Number.isSafeInteger(body.execution_epoch) && Number(body.execution_epoch) > 0
    ? Number(body.execution_epoch) : 0;
  if (!identity || !isCanonicalUuid(requestId) || !isCanonicalUuid(effectId)
      || !isCanonicalUuid(attemptId) || !isCanonicalUuid(leaseId) || executionEpoch < 1) return null;
  return { requestId, effectId, attemptId, leaseId, executionEpoch, ...identity };
}

async function wireJob(job: ProductRemoteJob): Promise<Json> {
  const raw = new TextEncoder().encode(JSON.stringify(job.payload));
  return {
    job_id: job.request_id,
    device_id: job.device_id,
    project_id: job.project_id,
    capability: job.capability,
    payload_canonical_b64: bytesToBase64(raw),
    payload_sha256: await sha256Hex(new TextDecoder().decode(raw)),
    effect_id: job.effect_id,
    attempt_id: job.attempt_id,
    lease_id: job.lease_id,
    execution_epoch: job.execution_epoch,
    agent_instance_id: job.agent_instance_id,
    boot_id: job.boot_id,
    lease_expires_at: job.lease_expires_at,
  };
}

async function heartbeat(request: Request, env: ProductPostgresEnv, deviceId: string): Promise<Response> {
  const body = await readBoundedJsonObject(request, 128 * 1024);
  if (!body) return respond({ ok: false, error: "heartbeat_invalid" }, 400);
  const status = body.status;
  const agentVersion = typeof body.agent_version === "string" ? body.agent_version.trim() : "";
  const actions = Array.isArray(body.capabilities) ? body.capabilities : null;
  if ((status !== "online" && status !== "busy" && status !== "offline")
      || agentVersion.length < 1 || agentVersion.length > 80
      || !actions || actions.length > 1024
      || !actions.every((item) => typeof item === "string" && item.length > 0 && item.length <= 160)) {
    return respond({ ok: false, error: "heartbeat_invalid" }, 400);
  }
  const normalized = [...new Set(actions as string[])].sort();
  const capabilityDigest = await sha256Hex(JSON.stringify(normalized));
  const recorded = await recordProductPresence(env, {
    deviceId,
    online: status !== "offline",
    runtimeKind: "desktop-agent",
    agentVersion,
    capabilityDigest,
    force: status === "offline",
  });
  return respond({ ok: true, recorded, server_time: new Date().toISOString() });
}

async function claim(request: Request, env: ProductPostgresEnv, deviceId: string): Promise<Response> {
  const body = await readBoundedJsonObject(request, 16 * 1024);
  if (!body) return respond({ ok: false, error: "claim_invalid" }, 400);
  const identity = runtimeIdentity(body);
  if (!identity) return respond({ ok: false, error: "claim_invalid" }, 400);
  const leaseSeconds = body.lease_seconds === undefined ? 120 : Number(body.lease_seconds);
  if (!Number.isInteger(leaseSeconds) || leaseSeconds < 30 || leaseSeconds > 300) {
    return respond({ ok: false, error: "claim_invalid" }, 400);
  }
  const claimed = await claimProductAction(env, {
    deviceId,
    agentInstanceId: identity.agentInstanceId,
    bootId: identity.bootId,
    leaseSeconds,
  });
  if (!claimed.ok) return respond({ ok: false, error: claimed.error ?? "claim_failed" }, 409);
  return respond({ ok: true, job: claimed.job ? await wireJob(claimed.job) : null });
}

async function start(request: Request, env: ProductPostgresEnv, deviceId: string): Promise<Response> {
  const body = await readBoundedJsonObject(request, 16 * 1024);
  const ctx = body ? executionContext(body) : null;
  if (!ctx) return respond({ ok: false, error: "start_invalid" }, 400);
  const ok = await startProductAction(env, { deviceId, ...ctx });
  return respond({ ok, ...(ok ? {} : { error: "lease_not_active" }) }, ok ? 200 : 409);
}

async function lease(request: Request, env: ProductPostgresEnv, deviceId: string): Promise<Response> {
  const body = await readBoundedJsonObject(request, 16 * 1024);
  const ctx = body ? executionContext(body) : null;
  if (!ctx) return respond({ ok: false, error: "lease_invalid" }, 400);
  const leaseSeconds = body!.lease_seconds === undefined ? 120 : Number(body!.lease_seconds);
  if (!Number.isInteger(leaseSeconds) || leaseSeconds < 30 || leaseSeconds > 300) {
    return respond({ ok: false, error: "lease_invalid" }, 400);
  }
  const leaseExpiresAt = await renewProductActionLease(env, { deviceId, ...ctx, leaseSeconds });
  return respond({ ok: leaseExpiresAt !== null, lease_expires_at: leaseExpiresAt,
    ...(leaseExpiresAt === null ? { error: "lease_not_active" } : {}) }, leaseExpiresAt ? 200 : 409);
}

async function progress(request: Request, env: ProductPostgresEnv, deviceId: string): Promise<Response> {
  const body = await readBoundedJsonObject(request, 32 * 1024);
  const ctx = body ? executionContext(body) : null;
  const stage = body && typeof body.stage === "string" ? body.stage.trim() : "";
  const message = body && body.message != null ? String(body.message) : null;
  const percent = body && body.progress_percent != null ? Number(body.progress_percent) : null;
  if (!ctx || stage.length < 1 || stage.length > 96 || (message !== null && message.length > 512)
      || (percent !== null && (!Number.isInteger(percent) || percent < 0 || percent > 100))) {
    return respond({ ok: false, error: "progress_invalid" }, 400);
  }
  const ok = await progressProductAction(env, { deviceId, ...ctx,
    stage, message, progressPercent: percent });
  return respond({ ok, ...(ok ? {} : { error: "lease_not_active" }) }, ok ? 200 : 409);
}

async function report(request: Request, env: ProductPostgresEnv, deviceId: string): Promise<Response> {
  const body = await readBoundedJsonObject(request, 640 * 1024);
  const ctx = body ? executionContext(body) : null;
  const reportId = body && typeof body.report_id === "string" ? body.report_id.toLowerCase() : "";
  const status = body?.status;
  const resultCanonicalB64 = body && typeof body.result_canonical_b64 === "string"
    ? body.result_canonical_b64 : "";
  const resultSha256 = body && typeof body.result_sha256 === "string"
    ? body.result_sha256.toLowerCase() : "";
  const errorCode = body?.error_code == null ? null : String(body.error_code);
  const resultBytes = base64ToBytes(resultCanonicalB64);
  if (!ctx || !isCanonicalUuid(reportId)
      || (status !== "succeeded" && status !== "failed" && status !== "cancelled")
      || !resultBytes || resultBytes.byteLength > 524288
      || !HEX64.test(resultSha256) || (errorCode !== null && errorCode.length > 120)) {
    return respond({ ok: false, error: "report_invalid" }, 400);
  }
  const observedDigest = await sha256Hex(new TextDecoder().decode(resultBytes));
  if (observedDigest !== resultSha256) {
    return respond({ ok: false, error: "result_digest_mismatch" }, 400);
  }
  let result: Json;
  try {
    const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(resultBytes));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("shape");
    result = parsed as Json;
  } catch {
    return respond({ ok: false, error: "report_invalid" }, 400);
  }
  const committed = await reportProductAction(env, {
    deviceId, ...ctx, reportId, status, result, resultSha256, errorCode,
  });
  if (committed.ok !== true) {
    const conflict = committed.error === "terminal_report_conflict" || committed.error === "lease_not_active";
    return respond(committed, conflict ? 409 : 400);
  }
  return respond(committed);
}

export async function handleProductDeviceTransport(
  request: Request,
  env: ProductPostgresEnv,
): Promise<Response> {
  if (request.method !== "POST") return respond({ ok: false, error: "method_not_allowed" }, 405);
  const auth = await authenticateDeviceRequest(request, env);
  if (!auth.ok) return auth.response;
  const path = new URL(request.url).pathname;
  try {
    if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/heartbeat") return heartbeat(request, env, auth.deviceId);
    if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/claim") return claim(request, env, auth.deviceId);
    if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/start") return start(request, env, auth.deviceId);
    if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/lease") return lease(request, env, auth.deviceId);
    if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/progress") return progress(request, env, auth.deviceId);
    if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/report"
        || path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/recover-report") {
      return report(request, env, auth.deviceId);
    }
    return respond({ ok: false, error: "not_found" }, 404);
  } catch (error) {
    if (error instanceof ProductPostgresError) {
      return respond({ ok: false, error: error.code }, error.status);
    }
    return respond({ ok: false, error: "product_postgres_unavailable" }, 503);
  }
}
