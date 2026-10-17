/**
 * Least-privilege Product-MCP repository discovery boundary.
 *
 * This capability reads only the Runtime's registered Git repository catalog.
 * It is device-scoped and cannot be upgraded into project, filesystem, Git or
 * terminal authority.
 */
import {
  authenticateProductMcpClientRequest,
  type ProductAuthEnv,
  type VerifiedProductMcpClient,
} from "./product_auth.ts";
import {
  enqueueProductAction,
  listCanonicalProductTargets,
  ProductPostgresError,
  type ProductActionEnqueueResult,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { productCapabilityAccessMode } from "./product_owner_grant_profiles.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { readBoundedJsonObject } from "./request_json.ts";
import type { AttestedMcpDevice } from "./product_mcp_attested_device_action.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type Json = Record<string, unknown>;

type Dependencies = Readonly<{
  authenticate?: (request: Request, env: ProductAuthEnv) => Promise<VerifiedProductMcpClient>;
  listTargets?: typeof listCanonicalProductTargets;
  enqueue?: typeof enqueueProductAction;
  now?: () => number;
  operationId?: () => string;
}>;

const ACTION = "workspace.repository_catalog";
const PROFILE = "repository-catalog-read";
const QUEUE_TTL_MS = 2 * 60 * 1000;
const ACTIVE_STATUSES = new Set(["queued", "leased", "running", "succeeded", "failed", "cancelled"]);

function json(value: unknown, status = 200): Response {
  return Response.json(value, {
    status,
    headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });
}

function isRecord(value: unknown): value is Json {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validTrusted(value: AttestedMcpDevice | null): value is AttestedMcpDevice {
  return Boolean(value)
    && isCanonicalUuid(value!.ownerUserId)
    && isCanonicalUuid(value!.deviceId)
    && /^[A-Za-z0-9][A-Za-z0-9._:-]{7,159}$/.test(value!.clientId);
}

function validCreateBody(body: Json, trusted: AttestedMcpDevice): boolean {
  if (Object.keys(body).sort().join(",") !== "action,arguments,device_id,project,space_id") return false;
  return body.action === ACTION
    && isRecord(body.arguments)
    && Object.keys(body.arguments).length === 0
    && isCanonicalUuid(body.device_id)
    && body.device_id.toLowerCase() === trusted.deviceId.toLowerCase()
    && body.project === null
    && body.space_id === null;
}

function grantRequired(): Response {
  return json({
    ok: false,
    error: "product_grant_not_resolved",
    required_profile: PROFILE,
    owner_action: "authorize_in_ordax_studio",
  }, 403);
}

export function catalogAllowsRepositoryCatalog(catalog: unknown, trustedDeviceId: string): boolean {
  if (!isRecord(catalog) || catalog.ok !== true || !Array.isArray(catalog.targets)
    || catalog.targets.length < 1 || catalog.targets.length > 128 || !isCanonicalUuid(trustedDeviceId)) return false;

  const ids = new Set<string>();
  let target: Json | null = null;
  for (const rawTarget of catalog.targets) {
    if (!isRecord(rawTarget) || !isCanonicalUuid(rawTarget.device_id)) return false;
    const id = rawTarget.device_id.toLowerCase();
    if (ids.has(id)) return false;
    ids.add(id);
    if (id === trustedDeviceId.toLowerCase()) target = rawTarget;
  }
  if (!target || !Array.isArray(target.grant_groups)
    || target.grant_groups.length < 1 || target.grant_groups.length > 128) return false;

  for (const rawGroup of target.grant_groups) {
    if (!isRecord(rawGroup) || !Array.isArray(rawGroup.capabilities)
      || rawGroup.capabilities.length < 1 || rawGroup.capabilities.length > 128) return false;
    if (rawGroup.profile_key !== PROFILE || rawGroup.space_id !== null || rawGroup.project_id !== null) continue;
    const expires = rawGroup.valid_until;
    if (expires !== undefined && expires !== null
      && (typeof expires !== "string" || !Number.isFinite(Date.parse(expires)))) return false;
    if (typeof expires === "string" && Date.parse(expires) <= Date.now()) continue;

    const seen = new Set<string>();
    for (const rawCapability of rawGroup.capabilities) {
      if (!isRecord(rawCapability) || typeof rawCapability.capability !== "string"
        || (rawCapability.access_mode !== "read" && rawCapability.access_mode !== "write")
        || seen.has(rawCapability.capability)) return false;
      seen.add(rawCapability.capability);
      if (rawCapability.capability === ACTION && rawCapability.access_mode === "read") return true;
    }
  }
  return false;
}

export function createAttestedRepositoryCatalogHandler(
  env: Env,
  trusted: AttestedMcpDevice | null,
  deps: Dependencies = {},
) {
  const authenticate = deps.authenticate ?? authenticateProductMcpClientRequest;
  const listTargets = deps.listTargets ?? listCanonicalProductTargets;
  const enqueue = deps.enqueue ?? enqueueProductAction;
  const now = deps.now ?? Date.now;
  const operationId = deps.operationId ?? (() => crypto.randomUUID());

  return async function createAction(request: Request): Promise<Response> {
    if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
    if (!validTrusted(trusted)) return json({ ok: false, error: "trusted_operation_required" }, 403);

    const identity = await authenticate(request, env);
    if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
    if (identity.ownerUserId.toLowerCase() !== trusted.ownerUserId.toLowerCase()
      || identity.clientId !== trusted.clientId) {
      return json({ ok: false, error: "trusted_operation_required" }, 403);
    }

    const body = await readBoundedJsonObject(request, 16 * 1024);
    if (!body || !validCreateBody(body, trusted)) {
      return json({ ok: false, error: "product_repository_catalog_action_invalid" }, 400);
    }

    try {
      const catalog = await listTargets(env, {
        ownerUserId: identity.ownerUserId,
        clientKind: identity.clientKind,
        clientId: identity.clientId,
      });
      if (!catalogAllowsRepositoryCatalog(catalog, trusted.deviceId)) return grantRequired();

      const opId = operationId().toLowerCase();
      if (!isCanonicalUuid(opId)) return json({ ok: false, error: "product_action_unavailable" }, 503);
      const accessMode = productCapabilityAccessMode(ACTION);
      const result: ProductActionEnqueueResult = await enqueue(env, {
        ownerUserId: identity.ownerUserId,
        spaceId: null,
        projectId: null,
        deviceId: trusted.deviceId,
        clientKind: identity.clientKind,
        clientId: identity.clientId,
        capability: ACTION,
        accessMode,
        payload: {},
        idempotencyKey: `mcp-${accessMode}-${opId}`,
        expiresAt: new Date(now() + QUEUE_TTL_MS).toISOString(),
      });

      if (result.ok === false) {
        if (result.error === "product_grant_not_resolved" || result.error === "product_owner_auth_ineligible") {
          return grantRequired();
        }
        if (result.error === "idempotency_conflict") return json({ ok: false, error: "idempotency_conflict" }, 409);
        return json({ ok: false, error: "product_action_unavailable" }, 503);
      }
      if (result.ok !== true
        || !isCanonicalUuid(result.request_id)
        || !isCanonicalUuid(result.effect_id)
        || typeof result.replayed !== "boolean"
        || !ACTIVE_STATUSES.has(result.status ?? "")) {
        return json({ ok: false, error: "product_action_unavailable" }, 503);
      }
      return json({
        ok: true,
        request_id: result.request_id,
        effect_id: result.effect_id,
        status: result.status,
        replayed: result.replayed,
      }, result.replayed ? 200 : 202);
    } catch (error) {
      if (error instanceof ProductPostgresError
        && (error.code === "product_grant_not_resolved" || error.code === "product_owner_auth_ineligible")) {
        return grantRequired();
      }
      return json({ ok: false, error: "product_action_unavailable" }, 503);
    }
  };
}
