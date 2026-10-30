/**
 * Attested Product-MCP -> canonical native terminal/process enqueue boundary.
 *
 * This is intentionally separate from computer control. The ChatGPT model may
 * name a repository, but repository/project identity is resolved again by the
 * canonical PostgreSQL authority. Runtime receives a hidden project-scope
 * attestation and rebinds the local project by canonical Git origin, so a model
 * supplied slug can never become authorization provenance.
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
import {
  canonicalGithubRepositoryFullName,
  resolveOwnerProjectScope,
} from "./product_owner_project_scope.ts";
import { productCapabilityAccessMode } from "./product_owner_grant_profiles.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { readBoundedJsonObject } from "./request_json.ts";
import type { AttestedMcpDevice } from "./product_mcp_attested_device_action.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type Json = Record<string, unknown>;

type ProjectScope = Readonly<{
  spaceId: string;
  projectId: string;
  repositoryFullName: string;
}>;

type Dependencies = Readonly<{
  authenticate?: (request: Request, env: ProductAuthEnv) => Promise<VerifiedProductMcpClient>;
  resolveProject?: typeof resolveOwnerProjectScope;
  listTargets?: typeof listCanonicalProductTargets;
  enqueue?: typeof enqueueProductAction;
  now?: () => number;
  operationId?: () => string;
}>;

const QUEUE_TTL_MS = 2 * 60 * 1000;
const TERMINAL_PROFILE = "project-native-terminal";
const PROCESS_PROFILE = "project-native-process";
const PROJECT_NATIVE_ACTIONS = new Set(["terminal.exec", "process.start", "process.status",
  "process.list", "process.logs", "process.write_stdin", "process.stop"]);
function profileForAction(action: string): string | null {
  if (action === "terminal.exec") return TERMINAL_PROFILE;
  return PROJECT_NATIVE_ACTIONS.has(action) ? PROCESS_PROFILE : null;
}
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

function validAttestedDevice(value: AttestedMcpDevice | null): value is AttestedMcpDevice {
  return Boolean(value)
    && isCanonicalUuid(value!.ownerUserId)
    && isCanonicalUuid(value!.deviceId)
    && /^[A-Za-z0-9][A-Za-z0-9._:-]{7,159}$/.test(value!.clientId);
}

function keysOnly(value: Json, allowed: readonly string[]): boolean {
  const allow = new Set(allowed);
  return Object.keys(value).every((key) => allow.has(key));
}

function boundedInteger(value: unknown, min: number, max: number): boolean {
  return Number.isInteger(value) && Number(value) >= min && Number(value) <= max;
}

function boundedString(value: unknown, max: number, allowEmpty = false): value is string {
  return typeof value === "string"
    && (allowEmpty || value.length > 0)
    && value.length <= max
    && !/[\x00\x7f]/u.test(value);
}

function boundedStringArray(value: unknown, maxItems = 100, maxItemLength = 8192): boolean {
  return Array.isArray(value)
    && value.length <= maxItems
    && value.every((item) => boundedString(item, maxItemLength, true));
}

/** Keep terminal and supervised-process arguments typed and bounded. */
function validEnv(value: unknown): boolean {
  if (value === undefined) return true;
  if (!isRecord(value) || Object.keys(value).length > 64) return false;
  return Object.entries(value).every(([k, v]) =>
    k.length >= 1 && k.length <= 128 && !/[\x00=]/u.test(k)
    && (typeof v === "string" || typeof v === "number" || typeof v === "boolean")
    && (typeof v !== "number" || Number.isFinite(v))
    && String(v).length <= 8192 && !String(v).includes("\x00"));
}
function validArgv(value: unknown, limit: number): boolean {
  return Array.isArray(value) && value.length >= 1 && value.length <= limit
    && value.every((v) => boundedString(v, 8192) && !v.includes("\x00"));
}
export function validAttestedProjectActionArguments(action: string, value: unknown): value is Json {
  if (!PROJECT_NATIVE_ACTIONS.has(action) || !isRecord(value)) return false;
  if (action === "terminal.exec") {
    if (!keysOnly(value, ["argv", "command", "shell", "cwd", "timeout_seconds", "env"])
        || (value.shell !== undefined && typeof value.shell !== "boolean")
        || (value.cwd !== undefined && !boundedString(value.cwd, 4096))
        || (value.timeout_seconds !== undefined && !boundedInteger(value.timeout_seconds, 1, 1800))
        || !validEnv(value.env)) return false;
    if (value.argv !== undefined) return value.command === undefined && value.shell !== true && validArgv(value.argv, 256);
    return value.shell === true && boundedString(value.command, 32768);
  }
  if (action === "process.start") {
    return keysOnly(value, ["argv", "cwd", "env", "wait_seconds"])
      && validArgv(value.argv, 128)
      && (value.cwd === undefined || boundedString(value.cwd, 4096))
      && validEnv(value.env)
      && (value.wait_seconds === undefined || (typeof value.wait_seconds === "number"
          && Number.isFinite(value.wait_seconds) && value.wait_seconds >= 0.1 && value.wait_seconds <= 5));
  }
  if (action === "process.list") return Object.keys(value).length === 0;
  if (action === "process.status" || action === "process.stop")
    return keysOnly(value, ["process_id"]) && isCanonicalUuid(value.process_id);
  if (action === "process.logs")
    return keysOnly(value, ["process_id", "max_bytes"]) && isCanonicalUuid(value.process_id)
      && (value.max_bytes === undefined || boundedInteger(value.max_bytes, 1024, 262144));
  if (action === "process.write_stdin")
    return keysOnly(value, ["process_id", "text", "newline"]) && isCanonicalUuid(value.process_id)
      && boundedString(value.text, 65536, true)
      && (value.newline === undefined || typeof value.newline === "boolean");
  return false;
}

function parseScope(value: unknown): ProjectScope | null {
  if (!isRecord(value) || value.ok !== true
    || !isCanonicalUuid(value.space_id)
    || !isCanonicalUuid(value.project_id)) return null;
  const repository = canonicalGithubRepositoryFullName(value.repository_full_name);
  if (repository === null) return null;
  return Object.freeze({
    spaceId: String(value.space_id).toLowerCase(),
    projectId: String(value.project_id).toLowerCase(),
    repositoryFullName: repository,
  });
}

function validCreateBody(body: Json, trusted: AttestedMcpDevice): body is Json & {
  action: string;
  project: string;
  arguments: Json;
} {
  const keys = Object.keys(body).sort();
  if (keys.join(",") !== "action,arguments,device_id,project,space_id") return false;
  if (typeof body.action !== "string" || !validAttestedProjectActionArguments(body.action, body.arguments)) return false;
  if (!isCanonicalUuid(body.device_id) || body.device_id.toLowerCase() !== trusted.deviceId.toLowerCase()) return false;
  if (canonicalGithubRepositoryFullName(body.project) === null) return false;
  return body.space_id === null || isCanonicalUuid(body.space_id);
}

function grantRequired(action: string): Response {
  return json({
    ok: false,
    error: "product_grant_not_resolved",
    required_profile: profileForAction(action),
    // Do not require Windows Studio on native OrdaX OS devices.
    owner_action: "authorize_in_ordax_owner_permissions",
  }, 403);
}

/**
 * Fail-closed current-grant preflight. The enqueue RPC remains final authority.
 * A project grant must match the exact resolved Space + project UUID pair.
 */
export function catalogAllowsAttestedProjectAction(
  catalog: unknown,
  trustedDeviceId: string,
  scope: ProjectScope,
  action: string,
): boolean {
  if (!isRecord(catalog) || catalog.ok !== true || !Array.isArray(catalog.targets)
    || catalog.targets.length < 1 || catalog.targets.length > 128
    || !isCanonicalUuid(trustedDeviceId) || !PROJECT_NATIVE_ACTIONS.has(action)) return false;

  const accessMode = productCapabilityAccessMode(action);
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

  let allowed = false;
  for (const rawGroup of target.grant_groups) {
    if (!isRecord(rawGroup) || !Array.isArray(rawGroup.capabilities)
      || rawGroup.capabilities.length < 1 || rawGroup.capabilities.length > 128) return false;
    if (rawGroup.profile_key !== profileForAction(action)) continue;
    if (!isCanonicalUuid(rawGroup.space_id) || !isCanonicalUuid(rawGroup.project_id)) return false;
    if (rawGroup.space_id.toLowerCase() !== scope.spaceId || rawGroup.project_id.toLowerCase() !== scope.projectId) continue;
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

function scopeError(value: unknown): string {
  if (!isRecord(value) || typeof value.error !== "string") return "product_project_scope_unavailable";
  switch (value.error) {
    case "owner_project_scope_not_found": return "product_project_scope_not_found";
    case "owner_project_scope_ambiguous": return "product_project_scope_ambiguous";
    case "product_owner_auth_ineligible": return "product_owner_auth_ineligible";
    case "device_not_owned": return "device_not_owned";
    default: return "product_project_scope_unavailable";
  }
}

/** Build the attested Product action handler without a second execution path. */
export function createAttestedProjectActionHandler(
  env: Env,
  trusted: AttestedMcpDevice | null,
  deps: Dependencies = {},
) {
  const authenticate = deps.authenticate ?? authenticateProductMcpClientRequest;
  const resolveProject = deps.resolveProject ?? resolveOwnerProjectScope;
  const listTargets = deps.listTargets ?? listCanonicalProductTargets;
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
      return json({ ok: false, error: "product_project_action_invalid" }, 400);
    }
    const repository = canonicalGithubRepositoryFullName(body.project)!;

    let resolvedRaw: Json;
    try {
      resolvedRaw = await resolveProject(env, identity.ownerUserId, trusted.deviceId, repository);
    } catch {
      return json({ ok: false, error: "product_project_scope_unavailable" }, 503);
    }
    const scope = parseScope(resolvedRaw);
    if (!scope) return json({ ok: false, error: scopeError(resolvedRaw) }, 403);
    if (scope.repositoryFullName.toLowerCase() !== repository.toLowerCase()) {
      return json({ ok: false, error: "product_project_scope_mismatch" }, 409);
    }
    if (body.space_id !== null && body.space_id.toLowerCase() !== scope.spaceId) {
      return json({ ok: false, error: "product_project_scope_mismatch" }, 409);
    }

    const accessMode = productCapabilityAccessMode(body.action);
    try {
      const catalog = await listTargets(env, {
        ownerUserId: identity.ownerUserId,
        clientKind: identity.clientKind,
        clientId: identity.clientId,
      });
      if (!catalogAllowsAttestedProjectAction(catalog, trusted.deviceId, scope, body.action)) {
        return grantRequired(body.action);
      }

      const opId = operationId().toLowerCase();
      if (!isCanonicalUuid(opId)) return json({ ok: false, error: "product_action_unavailable" }, 503);
      const payload: Json = {
        ...body.arguments,
        _ordax_project_scope: {
          project_id: scope.projectId,
          repository_full_name: scope.repositoryFullName,
        },
      };
      const result: ProductActionEnqueueResult = await enqueue(env, {
        ownerUserId: identity.ownerUserId,
        spaceId: scope.spaceId,
        projectId: scope.projectId,
        deviceId: trusted.deviceId,
        clientKind: identity.clientKind,
        clientId: identity.clientId,
        capability: body.action,
        accessMode,
        payload,
        idempotencyKey: `mcp-project-${accessMode}-${opId}`,
        expiresAt: new Date(now() + QUEUE_TTL_MS).toISOString(),
      });

      if (result.ok === false) {
        if (result.error === "product_grant_not_resolved" || result.error === "product_owner_auth_ineligible") {
          return grantRequired(body.action);
        }
        if (result.error === "idempotency_conflict") return json({ ok: false, error: "idempotency_conflict" }, 409);
        return json({ ok: false, error: "product_action_unavailable" }, 503);
      }
      if (result.ok !== true || !isCanonicalUuid(result.request_id) || !isCanonicalUuid(result.effect_id)
        || typeof result.replayed !== "boolean" || !ACTIVE_STATUSES.has(result.status ?? "")) {
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
        return grantRequired(body.action);
      }
      return json({ ok: false, error: "product_action_unavailable" }, 503);
    }
  };
}
