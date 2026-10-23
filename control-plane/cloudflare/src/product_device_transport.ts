/**
 * Canonical Product device transport over PostgreSQL.
 *
 * This is the only device execution transport for the Product MCP path.
 * Durable identity, presence, queue state, leases and results live in PostgreSQL.
 * No D1, global operator bearer, legacy pairing database or business-state DO is used.
 */
import {
  authenticateProductDevice,
  commitProjectWorkspaceResource,
  bindProductActionRuntimeProvenance,
  claimProductAction,
  progressProductAction,
  recordProductPresence,
  renewProductActionLease,
  resolveOrchestratorReadAuthorization,
  verifyProjectWorkspaceResource,
  reportProductAction,
  startProductAction,
  ProductPostgresError,
  type ProductPostgresEnv,
  type ProductRemoteJob,
} from "./product_postgres_store.ts";
import { readBoundedJsonObject } from "./request_json.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { projectWorkspaceGrantProjection } from "./project_workspace_grant_contract.ts";
import { canonicalDeviceWorkspaceConfirmation } from "./project_workspace_issue_contract.ts";
import { subscribeProductDeviceWake } from "./product_device_wake.ts";

type Json = Record<string, unknown>;
type RuntimeKind = "ordax-os" | "desktop-agent" | "mobile-client" | "other";
type RuntimeProvenance = { runtimeKind: RuntimeKind; agentVersion: string };
export const PRODUCT_DEVICE_TRANSPORT_PREFIX = "/v3/device/transport";
const HEX64 = /^[0-9a-f]{64}$/;
const RUNTIME_KINDS = new Set<RuntimeKind>(["ordax-os", "desktop-agent", "mobile-client", "other"]);

function respond(value: unknown, status = 200): Response {
  return Response.json(value, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

/**
 * PostgreSQL jsonb cannot store the U+0000 character, including when it
 * arrives JSON-escaped. Reject the invalid canonical result before any RPC
 * to avoid misreporting malformed output as a database outage.
 */
export function isProductReportJsonbSafe(value: unknown): boolean {
  if (typeof value === "string") return !value.includes(String.fromCharCode(0));
  if (Array.isArray(value)) return value.every(isProductReportJsonbSafe);
  if (value && typeof value === "object") {
    return Object.entries(value).every(([key, item]) =>
      isProductReportJsonbSafe(key) && isProductReportJsonbSafe(item));
  }
  return true;
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

function hasRuntimeProvenance(body: Json): boolean {
  return body.runtime_kind !== undefined || body.agent_version !== undefined;
}

function runtimeProvenance(body: Json): RuntimeProvenance | null {
  const runtimeKind = typeof body.runtime_kind === "string" ? body.runtime_kind : "";
  const agentVersion = typeof body.agent_version === "string" ? body.agent_version : "";
  if (!RUNTIME_KINDS.has(runtimeKind as RuntimeKind)
      || agentVersion.length < 1 || agentVersion.length > 80
      || agentVersion !== agentVersion.trim()
      || /[\x00-\x1f\x7f]/u.test(agentVersion)) return null;
  return { runtimeKind: runtimeKind as RuntimeKind, agentVersion };
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

// Transitional wire compatibility: installed Runtime 1.30.3 sends the bounded
// list while current Runtime sends the precomputed digest. Both represent the
// same canonical digest; PostgreSQL still persists *only* the hash. Remove this
// list branch after managed Runtime upgrades are proven in production.
const LEGACY_HEARTBEAT_MAX_CAPABILITIES = 1024;
const LEGACY_HEARTBEAT_MAX_NAME_CODEPOINTS = 160;
const LEGACY_HEARTBEAT_MAX_BODY_BYTES = 48 * 1024;

function compareCapabilityCodepoints(left: string, right: string): number {
  const a = Array.from(left, char => char.codePointAt(0)!);
  const b = Array.from(right, char => char.codePointAt(0)!);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}

export async function canonicalDeviceHeartbeatDigest(body: Json): Promise<string | null> {
  const modern = Object.prototype.hasOwnProperty.call(body, "capabilities_digest");
  const legacy = Object.prototype.hasOwnProperty.call(body, "capabilities");
  // Never trust an ambiguous schema or an empty/missing authority field.
  if (modern === legacy) return null;
  if (modern) {
    const digest = typeof body.capabilities_digest === "string"
      ? body.capabilities_digest.trim().toLowerCase() : "";
    return HEX64.test(digest) ? digest : null;
  }
  // Only installed, authenticated devices reach this code path. A legacy
  // heartbeat grants no new action, project, Space or user authority.
  if (Object.keys(body).some(key =>
    key !== "status" && key !== "agent_version" && key !== "capabilities")) return null;
  const values = body.capabilities;
  if (!Array.isArray(values) || values.length > LEGACY_HEARTBEAT_MAX_CAPABILITIES
      || values.some(item => typeof item !== "string" || item.length === 0
        || Array.from(item).length > LEGACY_HEARTBEAT_MAX_NAME_CODEPOINTS)) return null;
  const normalized = [...new Set(values as string[])].sort(compareCapabilityCodepoints);
  // Same SSOT as ordax_connector.capabilities.capability_digest:
  // sorted unique strings, compact UTF-8 JSON, SHA-256.
  return sha256Hex(JSON.stringify(normalized));
}

async function heartbeat(request: Request, env: ProductPostgresEnv, deviceId: string): Promise<Response> {
  // Canonical agents send a 64-byte digest. The higher body ceiling exists
  // solely for the bounded legacy format, not for new device capabilities.
  const body = await readBoundedJsonObject(request, LEGACY_HEARTBEAT_MAX_BODY_BYTES);
  if (!body) return respond({ ok: false, error: "heartbeat_invalid" }, 400);
  const status = body.status;
  const agentVersion = typeof body.agent_version === "string" ? body.agent_version.trim() : "";
  const capabilityDigest = await canonicalDeviceHeartbeatDigest(body);
  // Older desktop Runtime heartbeats intentionally omit provenance and remain
  // "desktop-agent". A Native OS Runtime must declare its actual kind; this
  // metadata is never a capability grant or an attested action session.
  const runtimeKind = body.runtime_kind === undefined ? "desktop-agent" : body.runtime_kind;
  if ((status !== "online" && status !== "busy" && status !== "offline")
      || agentVersion.length < 1 || agentVersion.length > 80
      || capabilityDigest === null
      || typeof runtimeKind !== "string"
      || !RUNTIME_KINDS.has(runtimeKind as RuntimeKind)
      || (body.runtime_kind !== undefined && !Object.prototype.hasOwnProperty.call(body, "capabilities_digest"))) {
    return respond({ ok: false, error: "heartbeat_invalid" }, 400);
  }
  const recorded = await recordProductPresence(env, {
    deviceId,
    online: status !== "offline",
    runtimeKind: runtimeKind as RuntimeKind,
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
  const provenance = runtimeProvenance(body);
  if (!identity || (hasRuntimeProvenance(body) && !provenance)) {
    return respond({ ok: false, error: "claim_invalid" }, 400);
  }
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
  const provenance = body ? runtimeProvenance(body) : null;
  if (!ctx || (body && hasRuntimeProvenance(body) && !provenance)) {
    return respond({ ok: false, error: "start_invalid" }, 400);
  }
  if (provenance) {
    const bound = await bindProductActionRuntimeProvenance(env, { deviceId, ...ctx, ...provenance });
    if (!bound) return respond({ ok: false, error: "runtime_provenance_conflict" }, 409);
  }
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

/** Product-workspace proof travels exclusively over the existing device-
 * authenticated transport, never through public MCP/LLM/UI inputs. Lab/actor
 * values are lookup keys; the SQL verifier owns their authorization.
 */
export type DeviceWorkspaceProofQuery = Readonly<{
  ownerUserId: string;
  actorId: string;
  clientId: string;
  labProjectId: string;
  workspaceSessionId: string;
  deviceId: string;
  resourceId: string;
}>;

const RESOURCE_ID = /^resource_[A-Za-z0-9_-]{8,160}$/;
const LAB_ID = /^[A-Za-z0-9_-]{1,180}$/;
const WORKSPACE_PROOF_KEYS = new Set([
  "owner_user_id", "actor_id", "client_id", "lab_project_id",
  "workspace_session_id", "resource_id",
]);
const VERIFIED_GRANT_KEYS = new Set([
  "grant_id", "owner_user_id", "space_id", "project_id",
  "lab_project_id", "actor_id", "client_id", "workspace_session_id",
  "device_id", "resource_id", "allowed_actions", "issued_by",
  "issued_at", "valid_until", "revoked_at", "active",
]);

export function canonicalDeviceWorkspaceProofQuery(
  body: unknown,
  authenticatedDeviceId: string,
): DeviceWorkspaceProofQuery | null {
  if (!body || typeof body !== "object" || Array.isArray(body)
      || !isCanonicalUuid(authenticatedDeviceId)) return null;
  const raw = body as Json;
  if (Object.keys(raw).length !== WORKSPACE_PROOF_KEYS.size
      || Object.keys(raw).some(key => !WORKSPACE_PROOF_KEYS.has(key))
      || !isCanonicalUuid(raw.owner_user_id)
      || !isCanonicalUuid(raw.actor_id)
      || !isCanonicalUuid(raw.client_id)
      || typeof raw.lab_project_id !== "string" || !LAB_ID.test(raw.lab_project_id)
      || typeof raw.workspace_session_id !== "string" || !LAB_ID.test(raw.workspace_session_id)
      || typeof raw.resource_id !== "string" || !RESOURCE_ID.test(raw.resource_id))
    return null;
  return Object.freeze({
    ownerUserId: raw.owner_user_id, actorId: raw.actor_id, clientId: raw.client_id,
    labProjectId: raw.lab_project_id, workspaceSessionId: raw.workspace_session_id,
    deviceId: authenticatedDeviceId, resourceId: raw.resource_id,
  });
}

export function projectWorkspaceVerifierResponse(
  result: unknown,
  query: DeviceWorkspaceProofQuery,
): Json | null {
  if (!result || typeof result !== "object" || Array.isArray(result)) return null;
  const raw = result as Json;
  if (Object.keys(raw).length !== 3 || raw.ok !== true
      || raw.schema !== "ordax.project-workspace-resource/1"
      || !raw.grant || typeof raw.grant !== "object" || Array.isArray(raw.grant))
    return null;
  const grant = raw.grant as Json;
  if (Object.keys(grant).length !== VERIFIED_GRANT_KEYS.size
      || Object.keys(grant).some(key => !VERIFIED_GRANT_KEYS.has(key))
      || !isCanonicalUuid(grant.space_id) || !isCanonicalUuid(grant.project_id))
    return null;
  const trusted = {
    ownerUserId: query.ownerUserId, spaceId: grant.space_id,
    projectId: grant.project_id, labProjectId: query.labProjectId,
    actorId: query.actorId, clientId: query.clientId,
    workspaceSessionId: query.workspaceSessionId, deviceId: query.deviceId,
    resourceId: query.resourceId,
  };
  if (!projectWorkspaceGrantProjection(grant, trusted, Date.now())) return null;
  return { ok: true, schema: "ordax.project-workspace-resource/1", grant };
}

async function workspaceResourceProof(
  request: Request, env: ProductPostgresEnv, deviceId: string,
): Promise<Response> {
  const body = await readBoundedJsonObject(request, 2048);
  const query = canonicalDeviceWorkspaceProofQuery(body, deviceId);
  if (!query) return respond({ ok: false, error: "workspace_proof_invalid" }, 400);
  // The SQL function is SECURITY DEFINER, read-only, and re-evaluates live
  // consent/grant/revocation. There is no code path for issuing a grant here.
  const result = await verifyProjectWorkspaceResource(env, query);
  const proof = projectWorkspaceVerifierResponse(result, query);
  return proof ? respond(proof)
    : respond({ ok: false, error: "workspace_authorization_required" }, 403);
}

/** The source-only Device confirmation MUST be composed by the already
 * enrolled trusted Runtime host after its native Owner picker and exact
 * in-process opaque resource selection. An arbitrary JSON payload/Device
 * bearer is NOT proof of a GUI event. Both SQL gates remain independent.
 */
async function workspaceResourceConfirmation(
  request: Request, env: ProductPostgresEnv, deviceId: string,
): Promise<Response> {
  const body = await readBoundedJsonObject(request, 2048);
  const input = canonicalDeviceWorkspaceConfirmation(body);
  if (!input)
    return respond({ ok: false, error: "workspace_confirmation_invalid" }, 400);
  const committed = await commitProjectWorkspaceResource(env, {
    deviceId, ...input,
  });
  return respond({ ok: committed, committed }, committed ? 200 : 403);
}

async function orchestratorAuthorization(request: Request, env: ProductPostgresEnv, deviceId: string): Promise<Response> {
  const body = await readBoundedJsonObject(request, 4096);
  const allowed = new Set(["job_id", "effect_id", "attempt_id", "lease_id",
    "execution_epoch", "agent_instance_id", "boot_id"]);
  const ctx = body ? executionContext(body) : null;
  if (!body || !ctx || Object.keys(body).some(key => !allowed.has(key)))
    return respond({ ok: false, error: "orchestrator_authorization_invalid" }, 400);
  const result = await resolveOrchestratorReadAuthorization(env, {deviceId, ...ctx});
  return respond(result, result.ok === true ? 200 : 403);
}

async function report(request: Request, env: ProductPostgresEnv, deviceId: string): Promise<Response> {
  const body = await readBoundedJsonObject(request, 640 * 1024);
  const ctx = body ? executionContext(body) : null;
  const provenance = body ? runtimeProvenance(body) : null;
  const reportId = body && typeof body.report_id === "string" ? body.report_id.toLowerCase() : "";
  const status = body?.status;
  const resultCanonicalB64 = body && typeof body.result_canonical_b64 === "string"
    ? body.result_canonical_b64 : "";
  const resultSha256 = body && typeof body.result_sha256 === "string"
    ? body.result_sha256.toLowerCase() : "";
  const errorCode = body?.error_code == null ? null : String(body.error_code);
  const resultBytes = base64ToBytes(resultCanonicalB64);
  if (!ctx || (body && hasRuntimeProvenance(body) && !provenance) || !isCanonicalUuid(reportId)
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
  if (!isProductReportJsonbSafe(result)) {
    return respond({ ok: false, error: "report_result_invalid_unicode" }, 422);
  }
  const committed = await reportProductAction(env, {
    deviceId, ...ctx, reportId, status, result, resultSha256, errorCode,
  });
  if (committed.ok !== true) {
    const conflict = committed.error === "terminal_report_conflict" || committed.error === "lease_not_active";
    return respond(committed, conflict ? 409 : 400);
  }
  if (provenance) {
    const bound = await bindProductActionRuntimeProvenance(env, { deviceId, ...ctx, ...provenance });
    if (!bound) return respond({ ok: false, error: "runtime_provenance_conflict" }, 409);
  }
  return respond(committed);
}

export async function handleProductDeviceTransport(
  request: Request,
  env: ProductPostgresEnv,
): Promise<Response> {
  const path = new URL(request.url).pathname;
  // Advisory signal subscribes through the same PostgreSQL-authenticated
  // device ingress. No second credential, grant or job queue is introduced.
  if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/wake") {
    if (request.method !== "GET") return respond({ ok: false, error: "method_not_allowed" }, 405);
    const auth = await authenticateDeviceRequest(request, env);
    if (!auth.ok) return auth.response;
    return subscribeProductDeviceWake(env, auth.deviceId, request);
  }
  if (request.method !== "POST") return respond({ ok: false, error: "method_not_allowed" }, 405);
  const auth = await authenticateDeviceRequest(request, env);
  if (!auth.ok) return auth.response;
  try {
    if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/heartbeat") return heartbeat(request, env, auth.deviceId);
    if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/claim") return claim(request, env, auth.deviceId);
    if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/start") return start(request, env, auth.deviceId);
    if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/lease") return lease(request, env, auth.deviceId);
    if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/orchestrator-read-authorization")
      return orchestratorAuthorization(request, env, auth.deviceId);
    if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/workspace-confirm") {
      if (env.WORKSPACE_RESOURCE_VERIFIER_ENABLED !== "enabled"
          || env.WORKSPACE_RESOURCE_ISSUANCE_ENABLED !== "enabled")
        return respond({ ok: false, error: "not_found" }, 404);
      return workspaceResourceConfirmation(request, env, auth.deviceId);
    }
    if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/workspace-proof") {
      // The SQL is still a proposal. Deploying this source cannot enable the
      // capability; explicit migration governance and this opt-in are required.
      if (env.WORKSPACE_RESOURCE_VERIFIER_ENABLED !== "enabled")
        return respond({ ok: false, error: "not_found" }, 404);
      return workspaceResourceProof(request, env, auth.deviceId);
    }
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
