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
import { PROJECT_ARTIFACT_ACTIONS, PROJECT_BLENDER_ACTIONS, PROJECT_BROWSER_ACTIONS } from "./product_action_scope.ts";
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
  /** Supplied only by Worker waitUntil; no model or HTTP input controls it. */
  scheduleWake?: (wake: Promise<void>) => void;
  now?: () => number;
  operationId?: () => string;
}>;

const QUEUE_TTL_MS = 2 * 60 * 1000;
const TERMINAL_PROFILE = "project-native-terminal";
const PROCESS_PROFILE = "project-native-process";
const PROJECT_NATIVE_ACTIONS = new Set(["terminal.exec", "process.start", "process.status",
  "process.list", "process.logs", "process.write_stdin", "process.stop"]);
function profileForAction(action: string): string | null {
  if (PROJECT_BLENDER_ACTIONS.has(action)) return "project-blender-control";
  if (PROJECT_BROWSER_ACTIONS.has(action)) return "project-browser-automation";
  if (PROJECT_ARTIFACT_ACTIONS.has(action)) return "project-artifact-read";
  if (action === "terminal.exec") return TERMINAL_PROFILE;
  return PROJECT_NATIVE_ACTIONS.has(action) ? PROCESS_PROFILE : null;
}
const ACTIVE_STATUSES = new Set(["queued", "leased", "running", "succeeded", "failed", "cancelled", "expired"]);

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

/** Product exposes only typed Blender operations, never arbitrary bpy/Python. */
function finiteNumber(value: unknown, min: number, max: number): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= min && value <= max;
}
function blenderVector(value: unknown, min = -100000, max = 100000): value is number[] {
  return Array.isArray(value) && value.length === 3 && value.every(v => finiteNumber(v, min, max));
}
function blenderName(value: unknown, max = 127): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max && !/[\x00-\x1f\x7f]/u.test(value);
}
function blenderSelector(value: Json): boolean {
  const name = value.object_name, id = value.ordax_object_id;
  return (name === undefined && blenderName(id)) || (id === undefined && blenderName(name));
}
function optionalTimeout(value: Json): boolean {
  return value.timeout_seconds === undefined || finiteNumber(value.timeout_seconds, 1, 300);
}
function rigBoneName(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z][A-Za-z0-9_. -]{0,62}$/.test(value.trim());
}
function validRigBones(value: unknown): boolean {
  if (!Array.isArray(value) || value.length < 1 || value.length > 64) return false;
  const seen = new Set<string>();
  for (const raw of value) {
    if (!isRecord(raw) || !keysOnly(raw, ["name", "head", "tail", "parent"])
        || !rigBoneName(raw.name) || !blenderVector(raw.head, -10000, 10000)
        || !blenderVector(raw.tail, -10000, 10000)) return false;
    const name = raw.name.trim();
    if (seen.has(name) || (raw.parent !== undefined
        && (!rigBoneName(raw.parent) || !seen.has(raw.parent.trim())))) return false;
    const head = raw.head as number[], tail = raw.tail as number[];
    if (Math.hypot(head[0] - tail[0], head[1] - tail[1], head[2] - tail[2]) < 0.0001) return false;
    seen.add(name);
  }
  return true;
}
export function validAttestedBlenderActionArguments(action: string, value: unknown): value is Json {
  if (!PROJECT_BLENDER_ACTIONS.has(action) || !isRecord(value) || !optionalTimeout(value)) return false;
  if (action === "blender.live_status" || action === "blender.live_modeling_schema") {
    return Object.keys(value).length === 0;
  }
  if (action === "blender.live_scene_snapshot") {
    return keysOnly(value, ["max_objects", "object_names", "timeout_seconds"])
      && (value.max_objects === undefined || boundedInteger(value.max_objects, 1, 500))
      && (value.object_names === undefined || (Array.isArray(value.object_names)
        && value.object_names.length <= 500 && value.object_names.every(x => blenderName(x))));
  }
  if (action === "blender.live_object_inspect") {
    return keysOnly(value, ["object_name", "ordax_object_id", "timeout_seconds"])
      && blenderSelector(value);
  }
  if (action === "blender.live_start") {
    return keysOnly(value, ["wait_seconds", "timeout_seconds", "pid", "adopt_blank"])
      && (value.wait_seconds === undefined || finiteNumber(value.wait_seconds, 1, 120))
      && (value.pid === undefined || boundedInteger(value.pid, 1, 2147483647))
      && (value.adopt_blank === undefined || typeof value.adopt_blank === "boolean");
  }
  if (action === "blender.live_object_transform") {
    return keysOnly(value, ["object_name", "ordax_object_id", "location", "rotation_euler", "scale", "dimensions", "timeout_seconds"])
      && blenderSelector(value)
      && (value.location === undefined || blenderVector(value.location))
      && (value.rotation_euler === undefined || blenderVector(value.rotation_euler))
      && (value.scale === undefined || blenderVector(value.scale, 0.00001, 1000))
      && (value.dimensions === undefined || blenderVector(value.dimensions, 0.00001, 100000))
      && ["location", "rotation_euler", "scale", "dimensions"].some(key => value[key] !== undefined);
  }
  if (action === "blender.live_create_primitive") {
    return keysOnly(value, ["name", "primitive", "location", "size", "radius", "depth", "segments", "timeout_seconds"])
      && blenderName(value.name) && ["cube", "sphere", "cylinder"].includes(value.primitive as string)
      && (value.location === undefined || blenderVector(value.location))
      && (value.size === undefined || finiteNumber(value.size, 0.0001, 10000))
      && (value.radius === undefined || finiteNumber(value.radius, 0.0001, 10000))
      && (value.depth === undefined || finiteNumber(value.depth, 0.0001, 10000))
      && (value.segments === undefined || boundedInteger(value.segments, 8, 64));
  }
  if (action === "blender.live_rig_create") {
    return keysOnly(value, ["name", "bones", "location", "timeout_seconds"])
      && rigBoneName(value.name) && validRigBones(value.bones)
      && (value.location === undefined || blenderVector(value.location, -10000, 10000));
  }
  if (action === "blender.live_material_apply") {
    return keysOnly(value, ["object_name", "ordax_object_id", "material_name", "base_color", "roughness", "metallic", "transmission", "alpha", "ior", "surface_render_method", "transparency_overlap", "timeout_seconds"])
      && blenderSelector(value) && blenderName(value.material_name)
      && (value.base_color === undefined || (Array.isArray(value.base_color)
        && [3, 4].includes(value.base_color.length) && value.base_color.every(v => finiteNumber(v, 0, 1))))
      && (value.roughness === undefined || finiteNumber(value.roughness, 0, 1))
      && (value.metallic === undefined || finiteNumber(value.metallic, 0, 1))
      && (value.transmission === undefined || finiteNumber(value.transmission, 0, 1))
      && (value.alpha === undefined || finiteNumber(value.alpha, 0, 1))
      && (value.ior === undefined || finiteNumber(value.ior, 1, 3))
      && (value.surface_render_method === undefined || blenderName(value.surface_render_method, 64))
      && (value.transparency_overlap === undefined || typeof value.transparency_overlap === "boolean");
  }
  if (action === "blender.live_save") {
    return keysOnly(value, ["target_path", "timeout_seconds"])
      && (value.target_path === undefined || boundedString(value.target_path, 4096));
  }
  return false;
}


function validBrowserUrl(value: unknown, optional = false): boolean {
  if (value === undefined) return optional;
  if (!boundedString(value, 4096)) return false;
  if (value === "about:blank") return optional;
  try {
    const parsed = new URL(value);
    return (parsed.protocol === "http:" || parsed.protocol === "https:")
      && Boolean(parsed.hostname) && !parsed.username && !parsed.password;
  } catch { return false; }
}
function validBrowserTabId(value: unknown): boolean {
  return typeof value === "string" && /^[A-Za-z0-9_-]{8,128}$/.test(value);
}
function validBrowserArgs(action: string, value: unknown): value is Json {
  if (!PROJECT_BROWSER_ACTIONS.has(action) || !isRecord(value)) return false;
  const id = value.session_id;
  const optionalTab = value.tab_id === undefined || validBrowserTabId(value.tab_id);
  const wait = value.wait_seconds === undefined || finiteNumber(value.wait_seconds, 1, 60);
  if (action === "browser.list") return Object.keys(value).length === 0;
  if (action === "browser.start")
    return keysOnly(value, ["url", "headless", "resume_session_id", "wait_seconds"])
      && validBrowserUrl(value.url, true) && wait
      && (value.resume_session_id === undefined || isCanonicalUuid(value.resume_session_id))
      && (value.headless === undefined || typeof value.headless === "boolean");
  if (!boundedString(id, 128)) return false;
  if (action === "browser.status" || action === "browser.tabs" || action === "browser.stop")
    return keysOnly(value, ["session_id"]);
  if (action === "browser.tab_open")
    return keysOnly(value, ["session_id", "url", "wait_seconds"])
      && validBrowserUrl(value.url, true) && wait;
  if (action === "browser.navigate")
    return keysOnly(value, ["session_id", "tab_id", "url", "wait_seconds"])
      && optionalTab && validBrowserUrl(value.url) && wait;
  if (action === "browser.snapshot")
    return keysOnly(value, ["session_id", "tab_id", "max_elements"])
      && optionalTab && (value.max_elements === undefined || boundedInteger(value.max_elements, 20, 500));
  if (action === "browser.screenshot")
    return keysOnly(value, ["session_id", "tab_id", "width", "height"])
      && optionalTab && (value.width === undefined || boundedInteger(value.width, 320, 2560))
      && (value.height === undefined || boundedInteger(value.height, 240, 1600));
  if (action === "browser.click")
    return keysOnly(value, ["session_id", "tab_id", "node_id"])
      && optionalTab && boundedString(value.node_id, 100);
  if (action === "browser.type")
    return keysOnly(value, ["session_id", "tab_id", "node_id", "text", "clear"])
      && optionalTab && boundedString(value.node_id, 100)
      && boundedString(value.text, 10000, true)
      && (value.clear === undefined || typeof value.clear === "boolean");
  return false;
}

function validProjectArtifactArgs(action: string, value: unknown): value is Json {
  if (!PROJECT_ARTIFACT_ACTIONS.has(action) || !isRecord(value)) return false;
  if (action === "artifacts.list") {
    return keysOnly(value, ["max_items"])
      && (value.max_items === undefined || boundedInteger(value.max_items, 1, 100));
  }
  if (!keysOnly(value, ["artifact_name", "project_artifact_path", "project_artifact_paths",
    "thumbnail", "max_bytes", "max_width", "max_height", "quality"])) return false;
  const paths = value.project_artifact_paths;
  if (paths !== undefined) {
    if (!Array.isArray(paths) || paths.length < 1 || paths.length > 100
      || paths.some(path => !boundedString(path, 4096))
      || paths.reduce((total: number, path: string) => total + new TextEncoder().encode(path).length, 0) > 16384
      || value.artifact_name !== undefined || value.project_artifact_path !== undefined
      || value.thumbnail === true) return false;
  } else {
    if (value.artifact_name !== undefined && !boundedString(value.artifact_name, 4096)) return false;
    if (value.project_artifact_path !== undefined && !boundedString(value.project_artifact_path, 4096)) return false;
    if (value.artifact_name !== undefined && value.project_artifact_path !== undefined) return false;
  }
  return (value.thumbnail === undefined || typeof value.thumbnail === "boolean")
    && (value.max_bytes === undefined || boundedInteger(value.max_bytes, 1, 262144))
    && (value.max_width === undefined || boundedInteger(value.max_width, 64, 4096))
    && (value.max_height === undefined || boundedInteger(value.max_height, 64, 4096))
    && (value.quality === undefined || boundedInteger(value.quality, 30, 92));
}

export function validAttestedProjectActionArguments(action: string, value: unknown): value is Json {
  if (PROJECT_ARTIFACT_ACTIONS.has(action)) return validProjectArtifactArgs(action, value);
  if (PROJECT_BROWSER_ACTIONS.has(action)) return validBrowserArgs(action, value);
  if (PROJECT_BLENDER_ACTIONS.has(action)) return validAttestedBlenderActionArguments(action, value);
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
    || !isCanonicalUuid(trustedDeviceId)
    || (!PROJECT_NATIVE_ACTIONS.has(action) && !PROJECT_BLENDER_ACTIONS.has(action)
      && !PROJECT_BROWSER_ACTIONS.has(action) && !PROJECT_ARTIFACT_ACTIONS.has(action))) return false;

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

  return async function createAction(request: Request, retryDigest?: string | null): Promise<Response> {
    if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
    if (!validAttestedDevice(trusted)) return json({ ok: false, error: "trusted_operation_required" }, 403);
    // Gateway-derived digest is a protocol retry identifier, not a grant.
    // Retain attestation fail-closed priority even if the marker is absent.
    if (retryDigest === null || (retryDigest !== undefined && !/^[a-f0-9]{64}$/.test(retryDigest))) {
      return json({ ok: false, error: "product_mcp_retry_correlation_invalid" }, 400);
    }

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
    if (!scope) {
      const error = scopeError(resolvedRaw);
      // A missing canonical Project binding is not a grant or an executable
      // action. Give the Owner one precise onboarding path, without trying
      // alternate repository/device scopes or queuing a Blender command.
      return json(error === "product_project_scope_not_found"
        ? { ok: false, error, setup_required: "space_project_repository_device_binding",
            owner_action: "register_project_and_device_in_ordax_owner", action_dispatched: false }
        : { ok: false, error }, 403);
    }
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

      // Project reads are observational and must remain fresh. Only writes use
      // the stable retry digest to protect physical effects from duplicate replay.
      const stableRetry = accessMode === "write" ? retryDigest : undefined;
      const opId = stableRetry ?? operationId().toLowerCase();
      if (stableRetry === undefined && !isCanonicalUuid(opId))
        return json({ ok: false, error: "product_action_unavailable" }, 503);
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
        ...(deps.scheduleWake ? { scheduleWake: deps.scheduleWake } : {}),
      });

      if (result.ok === false) {
        if (result.error === "product_grant_not_resolved" || result.error === "product_owner_auth_ineligible") {
          return grantRequired(body.action);
        }
        // PostgreSQL rejects new work with no live executor; never advertise
        // a queued request that cannot currently be claimed. Replay receipts
        // for previously accepted effects remain authoritative in the SQL RPC.
        if (result.error === "product_device_busy") {
          return json({ ok: false, error: "product_device_busy", action_dispatched: false }, 503);
        }
        if (result.error === "product_device_offline") {
          return json({ ok: false, error: "product_device_offline", action_dispatched: false }, 503);
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
