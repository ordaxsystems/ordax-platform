/**
 * Attested Product-MCP -> canonical project continuity action boundary.
 *
 * ChatGPT may name only a GitHub repository. The authoritative Space/project
 * identity is resolved server-side from the authenticated owner + attested
 * device + active project connection. The local Runtime slug is never an
 * authorization input.
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
import { PROJECT_CONTINUITY_ACTIONS } from "./product_action_scope.ts";
import { productCapabilityAccessMode } from "./product_owner_grant_profiles.ts";
import {
  canonicalGithubRepositoryFullName,
  resolveOwnerProjectScope,
} from "./product_owner_project_scope.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { readBoundedJsonObject } from "./request_json.ts";
import type { AttestedMcpDevice } from "./product_mcp_attested_device_action.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type Json = Record<string, unknown>;

type Dependencies = Readonly<{
  authenticate?: (request: Request, env: ProductAuthEnv) => Promise<VerifiedProductMcpClient>;
  listTargets?: typeof listCanonicalProductTargets;
  resolveProject?: typeof resolveOwnerProjectScope;
  enqueue?: typeof enqueueProductAction;
  now?: () => number;
  operationId?: () => string;
}>;

const QUEUE_TTL_MS = 2 * 60 * 1000;
const ACTIVE_STATUSES = new Set(["queued", "leased", "running", "succeeded", "failed", "cancelled"]);
const CONTINUITY_PROFILE = "project-continuity";
export const ATTESTED_MCP_PROJECT_CONTINUITY_ACTIONS: ReadonlySet<string> = new Set(PROJECT_CONTINUITY_ACTIONS);

function json(value: unknown, status = 200): Response {
  return Response.json(value, {
    status,
    headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });
}

function isRecord(value: unknown): value is Json {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validAttestedDevice(value: AttestedMcpDevice | null): value is AttestedMcpDevice {
  return Boolean(value)
    && isCanonicalUuid(value!.ownerUserId)
    && isCanonicalUuid(value!.deviceId)
    && /^[A-Za-z0-9][A-Za-z0-9._:-]{7,159}$/.test(value!.clientId);
}

function keysOnly(value: Json, allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  return Object.keys(value).every((key) => allowedSet.has(key));
}

function boundedString(value: unknown, max: number, allowEmpty = false): value is string {
  return typeof value === "string"
    && (allowEmpty || value.length > 0)
    && value.length <= max
    && !/[\x00\x7f]/u.test(value);
}

function boundedStringArray(value: unknown, maxItems: number): boolean {
  return value === undefined || (Array.isArray(value)
    && value.length <= maxItems
    && value.every((item) => boundedString(item, 8192, true)));
}

function boundedInteger(value: unknown, min: number, max: number): boolean {
  return Number.isInteger(value) && Number(value) >= min && Number(value) <= max;
}

/** Strict argument contract for the five continuity capabilities. */
export function validAttestedProjectContinuityArguments(action: string, value: unknown): value is Json {
  if (!ATTESTED_MCP_PROJECT_CONTINUITY_ACTIONS.has(action) || !isRecord(value)) return false;
  const repository = canonicalGithubRepositoryFullName(value.repository_full_name);
  if (repository === null) return false;

  if (action === "continuity.get") {
    return keysOnly(value, ["repository_full_name"]);
  }
  if (action === "agent.project_briefing") {
    return keysOnly(value, ["repository_full_name", "query", "recall_limit"])
      && (value.query === undefined || boundedString(value.query, 16_384, true))
      && (value.recall_limit === undefined || boundedInteger(value.recall_limit, 1, 50));
  }
  if (action === "handoff.get") {
    return keysOnly(value, ["repository_full_name", "handoff_id"])
      && boundedString(value.handoff_id, 160);
  }
  if (action === "continuity.update") {
    return keysOnly(value, [
      "repository_full_name", "summary", "next_action", "completed", "blockers", "changed_paths",
    ])
      && boundedString(value.summary, 65_536)
      && (value.next_action === undefined || boundedString(value.next_action, 16_384, true))
      && boundedStringArray(value.completed, 100)
      && boundedStringArray(value.blockers, 100)
      && boundedStringArray(value.changed_paths, 100);
  }
  if (action === "handoff.create") {
    return keysOnly(value, [
      "repository_full_name", "summary", "next_action", "completed", "blockers", "changed_paths", "ttl_hours",
    ])
      && boundedString(value.summary, 65_536)
      && (value.next_action === undefined || boundedString(value.next_action, 16_384, true))
      && boundedStringArray(value.completed, 100)
      && boundedStringArray(value.blockers, 100)
      && boundedStringArray(value.changed_paths, 100)
      && (value.ttl_hours === undefined || boundedInteger(value.ttl_hours, 1, 168));
  }
  return false;
}

function validCreateBody(body: Json, trusted: AttestedMcpDevice): body is Json & {
  action: string;
  arguments: Json;
} {
  const keys = Object.keys(body).sort();
  if (keys.join(",") !== "action,arguments,device_id,project,space_id") return false;
  if (typeof body.action !== "string" || !validAttestedProjectContinuityArguments(body.action, body.arguments)) {
    return false;
  }
  return isCanonicalUuid(body.device_id)
    && body.device_id.toLowerCase() === trusted.deviceId.toLowerCase()
    && body.project === null
    && body.space_id === null;
}

function grantRequired(): Response {
  return json({
    ok: false,
    error: "product_grant_not_resolved",
    required_profile: CONTINUITY_PROFILE,
    owner_action: "authorize_in_ordax_studio",
  }, 403);
}

function parseResolvedProject(value: unknown): Readonly<{
  spaceId: string;
  projectId: string;
  repositoryFullName: string;
}> | null {
  if (!isRecord(value) || value.ok !== true) return null;
  const repository = canonicalGithubRepositoryFullName(value.repository_full_name);
  if (!isCanonicalUuid(value.space_id) || !isCanonicalUuid(value.project_id) || repository === null) return null;
  return {
    spaceId: value.space_id.toLowerCase(),
    projectId: value.project_id.toLowerCase(),
    repositoryFullName: repository,
  };
}

/**
 * Fail-closed preflight over canonical grant groups. The enqueue RPC remains
 * final authority and re-resolves the same grant immediately before enqueue.
 */
export function catalogAllowsAttestedProjectContinuityAction(
  catalog: unknown,
  trustedDeviceId: string,
  spaceId: string,
  projectId: string,
  action: string,
): boolean {
  if (!isRecord(catalog) || catalog.ok !== true || !Array.isArray(catalog.targets)
    || catalog.targets.length < 1 || catalog.targets.length > 128
    || !isCanonicalUuid(trustedDeviceId) || !isCanonicalUuid(spaceId) || !isCanonicalUuid(projectId)
    || !ATTESTED_MCP_PROJECT_CONTINUITY_ACTIONS.has(action)) return false;

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

  const accessMode = productCapabilityAccessMode(action);
  let allowed = false;
  for (const rawGroup of target.grant_groups) {
    if (!isRecord(rawGroup) || !Array.isArray(rawGroup.capabilities)
      || rawGroup.capabilities.length < 1 || rawGroup.capabilities.length > 128) return false;
    const groupSpace = typeof rawGroup.space_id === "string" ? rawGroup.space_id.toLowerCase() : "";
    const groupProject = typeof rawGroup.project_id === "string" ? rawGroup.project_id.toLowerCase() : "";
    if (rawGroup.profile_key !== CONTINUITY_PROFILE
      || groupSpace !== spaceId.toLowerCase()
      || groupProject !== projectId.toLowerCase()) continue;

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
      if (rawCapability.capability === action && rawCapability.access_mode === accessMode) allowed = true;
    }
  }
  return allowed;
}

function scopeFailureStatus(value: Json): number {
  if (value.error === "owner_project_scope_not_found") return 404;
  if (value.error === "owner_project_scope_ambiguous") return 409;
  if (value.error === "product_owner_auth_ineligible" || value.error === "device_not_owned") return 403;
  return 400;
}

/** Build the only project-continuity createAction handler exposed to direct MCP. */
export function createAttestedProjectContinuityHandler(
  env: Env,
  trusted: AttestedMcpDevice | null,
  deps: Dependencies = {},
) {
  const authenticate = deps.authenticate ?? authenticateProductMcpClientRequest;
  const listTargets = deps.listTargets ?? listCanonicalProductTargets;
  const resolveProject = deps.resolveProject ?? resolveOwnerProjectScope;
  const enqueue = deps.enqueue ?? enqueueProductAction;
  const now = deps.now ?? Date.now;
  const operationId = deps.operationId ?? (() => crypto.randomUUID());

  return async function createAction(request: Request): Promise<Response> {
    if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
    if (!validAttestedDevice(trusted)) return json({ ok: false, error: "trusted_operation_required" }, 403);

    const identity = await authenticate(request, env);
    if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
    if (identity.ownerUserId.toLowerCase() !== trusted.ownerUserId.toLowerCase()
      || identity.clientId !== trusted.clientId) {
      return json({ ok: false, error: "trusted_operation_required" }, 403);
    }

    const body = await readBoundedJsonObject(request, 96 * 1024);
    if (!body || !validCreateBody(body, trusted)) {
      return json({ ok: false, error: "product_project_continuity_action_invalid" }, 400);
    }

    const repositoryFullName = canonicalGithubRepositoryFullName(body.arguments.repository_full_name);
    if (repositoryFullName === null) {
      return json({ ok: false, error: "owner_project_scope_invalid" }, 400);
    }

    try {
      const resolvedRaw = await resolveProject(
        env,
        identity.ownerUserId,
        trusted.deviceId,
        repositoryFullName,
      );
      if (resolvedRaw.ok !== true) {
        return json({ ok: false, error: String(resolvedRaw.error ?? "owner_project_scope_invalid") }, scopeFailureStatus(resolvedRaw));
      }
      const resolved = parseResolvedProject(resolvedRaw);
      if (!resolved) return json({ ok: false, error: "product_project_scope_invalid_response" }, 503);

      const catalog = await listTargets(env, {
        ownerUserId: identity.ownerUserId,
        clientKind: identity.clientKind,
        clientId: identity.clientId,
      });
      if (!catalogAllowsAttestedProjectContinuityAction(
        catalog,
        trusted.deviceId,
        resolved.spaceId,
        resolved.projectId,
        body.action,
      )) {
        return grantRequired();
      }

      const opId = operationId().toLowerCase();
      if (!isCanonicalUuid(opId)) return json({ ok: false, error: "product_action_unavailable" }, 503);
      const actionArguments = { ...body.arguments };
      delete actionArguments.repository_full_name;
      const payload: Json = {
        ...actionArguments,
        _ordax_project_scope: {
          project_id: resolved.projectId,
          repository_full_name: resolved.repositoryFullName,
        },
      };
      const accessMode = productCapabilityAccessMode(body.action);
      const result: ProductActionEnqueueResult = await enqueue(env, {
        ownerUserId: identity.ownerUserId,
        spaceId: resolved.spaceId,
        projectId: resolved.projectId,
        deviceId: trusted.deviceId,
        clientKind: identity.clientKind,
        clientId: identity.clientId,
        capability: body.action,
        accessMode,
        payload,
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
