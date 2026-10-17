/**
 * Attested Product-MCP -> canonical device action enqueue boundary.
 *
 * The model may request only capabilities explicitly published by the Product
 * MCP. Device identity comes from the Runtime-attested Product-MCP session;
 * the model never selects the authoritative device. Current PostgreSQL grants
 * are re-resolved before every enqueue and the canonical enqueue RPC performs
 * the final capability/access-mode authorization again.
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
  CLIPBOARD_COMPUTER_CONTROL_MODE,
  FILESYSTEM_COMPUTER_CONTROL_MODE,
  INTERACTIVE_COMPUTER_CONTROL_MODE,
  OBSERVE_COMPUTER_CONTROL_MODE,
  OWNER_DEVICE_COMPUTER_GRANT_PROFILES,
} from "./product_action_scope.ts";
import { productCapabilityAccessMode } from "./product_owner_grant_profiles.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { readBoundedJsonObject } from "./request_json.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type Json = Record<string, unknown>;

export type AttestedMcpDevice = Readonly<{
  ownerUserId: string;
  clientId: string;
  deviceId: string;
}>;

type Dependencies = Readonly<{
  authenticate?: (request: Request, env: ProductAuthEnv) => Promise<VerifiedProductMcpClient>;
  listTargets?: typeof listCanonicalProductTargets;
  enqueue?: typeof enqueueProductAction;
  now?: () => number;
  operationId?: () => string;
}>;

const QUEUE_TTL_MS = 2 * 60 * 1000;
const ACTIVE_STATUSES = new Set(["queued", "leased", "running", "succeeded", "failed", "cancelled"]);
const FULL_COMPUTER_CONTROL_MODE = "full-computer-control";
const OBSERVE_ACTIONS = new Set<string>(OWNER_DEVICE_COMPUTER_GRANT_PROFILES[OBSERVE_COMPUTER_CONTROL_MODE]);
const INTERACTIVE_ACTIONS = new Set<string>(OWNER_DEVICE_COMPUTER_GRANT_PROFILES[INTERACTIVE_COMPUTER_CONTROL_MODE]);
const FILESYSTEM_ACTIONS = new Set<string>(OWNER_DEVICE_COMPUTER_GRANT_PROFILES[FILESYSTEM_COMPUTER_CONTROL_MODE]);
const CLIPBOARD_ACTIONS = new Set<string>(OWNER_DEVICE_COMPUTER_GRANT_PROFILES[CLIPBOARD_COMPUTER_CONTROL_MODE]);
const ATTESTED_FILESYSTEM_READ_ACTIONS = new Set([
  "computer.file_stat",
  "computer.directory_list",
  "computer.text_read",
  "computer.search",
]);
const ATTESTED_CLIPBOARD_READ_ACTIONS = new Set(["computer.clipboard_read"]);
export const ATTESTED_MCP_DEVICE_ACTIONS: ReadonlySet<string> = new Set([
  ...OBSERVE_ACTIONS,
  ...INTERACTIVE_ACTIONS,
  ...ATTESTED_FILESYSTEM_READ_ACTIONS,
  ...ATTESTED_CLIPBOARD_READ_ACTIONS,
]);

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

function requiredProfile(action: string): string | null {
  // Observation remains the least-privilege answer for the five capabilities
  // shared with the broader interactive profile.
  if (OBSERVE_ACTIONS.has(action)) return OBSERVE_COMPUTER_CONTROL_MODE;
  if (INTERACTIVE_ACTIONS.has(action)) return INTERACTIVE_COMPUTER_CONTROL_MODE;
  if (ATTESTED_FILESYSTEM_READ_ACTIONS.has(action) && FILESYSTEM_ACTIONS.has(action)) {
    return FILESYSTEM_COMPUTER_CONTROL_MODE;
  }
  if (ATTESTED_CLIPBOARD_READ_ACTIONS.has(action) && CLIPBOARD_ACTIONS.has(action)) {
    return CLIPBOARD_COMPUTER_CONTROL_MODE;
  }
  return null;
}

function grantRequired(action: string): Response {
  return json({
    ok: false,
    error: "product_grant_not_resolved",
    required_profile: requiredProfile(action),
    owner_action: "authorize_in_ordax_studio",
  }, 403);
}

function keysOnly(value: Json, allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  return Object.keys(value).every((key) => allowedSet.has(key));
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

function validButton(value: unknown): boolean {
  return value === undefined || value === "left" || value === "right" || value === "middle";
}

/** Strict argument allowlist for the published attested device tranche. */
export function validAttestedDeviceActionArguments(action: string, value: unknown): value is Json {
  if (!ATTESTED_MCP_DEVICE_ACTIONS.has(action) || !isRecord(value)) return false;
  const keys = Object.keys(value);

  if (["computer.access_status", "computer.active_window", "computer.screen_info"].includes(action)) {
    return keys.length === 0;
  }
  if (action === "computer.windows") {
    return keysOnly(value, ["max_items"])
      && (value.max_items === undefined || boundedInteger(value.max_items, 1, 500));
  }
  if (action === "computer.processes") {
    return keysOnly(value, ["query", "max_items"])
      && (value.query === undefined || boundedString(value.query, 256, true))
      && (value.max_items === undefined || boundedInteger(value.max_items, 1, 1000));
  }
  if (action === "computer.screenshot") {
    return keysOnly(value, ["mode"])
      && (value.mode === undefined || value.mode === "desktop" || value.mode === "active_window");
  }
  if (action === "computer.clipboard_read") {
    return keysOnly(value, ["max_bytes"])
      && (value.max_bytes === undefined || boundedInteger(value.max_bytes, 1, 1_048_576));
  }
  if (action === "computer.file_stat") {
    return keysOnly(value, ["path"]) && boundedString(value.path, 4096);
  }
  if (action === "computer.directory_list") {
    return keysOnly(value, ["path", "max_depth", "max_entries", "include_hidden"])
      && boundedString(value.path, 4096)
      && (value.max_depth === undefined || boundedInteger(value.max_depth, 1, 12))
      && (value.max_entries === undefined || boundedInteger(value.max_entries, 1, 5000))
      && (value.include_hidden === undefined || typeof value.include_hidden === "boolean");
  }
  if (action === "computer.text_read") {
    return keysOnly(value, ["path", "start_line", "end_line"])
      && boundedString(value.path, 4096)
      && (value.start_line === undefined || boundedInteger(value.start_line, 1, 10_000_000))
      && (value.end_line === undefined || boundedInteger(value.end_line, 1, 10_000_000))
      && (value.start_line === undefined || value.end_line === undefined || Number(value.end_line) >= Number(value.start_line));
  }
  if (action === "computer.search") {
    return keysOnly(value, ["root", "query", "mode", "max_results", "max_depth", "include_hidden"])
      && boundedString(value.root, 4096)
      && boundedString(value.query, 4096)
      && (value.mode === undefined || value.mode === "name" || value.mode === "content" || value.mode === "both")
      && (value.max_results === undefined || boundedInteger(value.max_results, 1, 500))
      && (value.max_depth === undefined || boundedInteger(value.max_depth, 1, 12))
      && (value.include_hidden === undefined || typeof value.include_hidden === "boolean");
  }
  if (action === "computer.focus_window") {
    return keysOnly(value, ["handle"]) && boundedString(value.handle, 128);
  }
  if (action === "computer.click") {
    return keysOnly(value, ["x", "y", "button", "clicks"])
      && boundedInteger(value.x, -1_000_000, 1_000_000)
      && boundedInteger(value.y, -1_000_000, 1_000_000)
      && validButton(value.button)
      && (value.clicks === undefined || boundedInteger(value.clicks, 1, 3));
  }
  if (action === "computer.mouse_move") {
    return keysOnly(value, ["x", "y", "duration_ms"])
      && boundedInteger(value.x, -1_000_000, 1_000_000)
      && boundedInteger(value.y, -1_000_000, 1_000_000)
      && (value.duration_ms === undefined || boundedInteger(value.duration_ms, 0, 5000));
  }
  if (action === "computer.drag") {
    return keysOnly(value, ["from_x", "from_y", "to_x", "to_y", "button", "duration_ms"])
      && boundedInteger(value.from_x, -1_000_000, 1_000_000)
      && boundedInteger(value.from_y, -1_000_000, 1_000_000)
      && boundedInteger(value.to_x, -1_000_000, 1_000_000)
      && boundedInteger(value.to_y, -1_000_000, 1_000_000)
      && validButton(value.button)
      && (value.duration_ms === undefined || boundedInteger(value.duration_ms, 50, 5000));
  }
  if (action === "computer.launch_app") {
    if (!keysOnly(value, ["application", "args"]) || !boundedString(value.application, 4096)) return false;
    if (value.args === undefined) return true;
    return Array.isArray(value.args)
      && value.args.length <= 32
      && value.args.every((item) => boundedString(item, 8192, true));
  }
  if (action === "computer.scroll") {
    return keysOnly(value, ["amount", "horizontal"])
      && boundedInteger(value.amount, -100, 100)
      && (value.horizontal === undefined || typeof value.horizontal === "boolean");
  }
  if (action === "computer.type") {
    return keysOnly(value, ["text"]) && boundedString(value.text, 65_536, true);
  }
  if (action === "computer.hotkey") {
    return keysOnly(value, ["keys"])
      && Array.isArray(value.keys)
      && value.keys.length >= 1
      && value.keys.length <= 6
      && value.keys.every((item) => boundedString(item, 32));
  }
  return false;
}

function validCreateBody(body: Json, trusted: AttestedMcpDevice): body is Json & {
  action: string;
  arguments: Json;
} {
  const keys = Object.keys(body).sort();
  if (keys.join(",") !== "action,arguments,device_id,project,space_id") return false;
  if (typeof body.action !== "string" || !validAttestedDeviceActionArguments(body.action, body.arguments)) {
    return false;
  }
  return isCanonicalUuid(body.device_id)
    && body.device_id.toLowerCase() === trusted.deviceId.toLowerCase()
    && body.project === null
    && body.space_id === null;
}

/**
 * Fail-closed preflight over the canonical target projection. The enqueue RPC
 * remains the final authority; this check exists to return useful remediation
 * without dispatching an action that is already known to lack a current grant.
 */
export function catalogAllowsAttestedDeviceAction(
  catalog: unknown,
  trustedDeviceId: string,
  action: string,
): boolean {
  if (!isRecord(catalog) || catalog.ok !== true || !Array.isArray(catalog.targets)
    || catalog.targets.length < 1 || catalog.targets.length > 128
    || !isCanonicalUuid(trustedDeviceId)) return false;

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

  const profile = requiredProfile(action);
  if (!profile) return false;
  const accessMode = productCapabilityAccessMode(action);
  let allowed = false;

  for (const rawGroup of target.grant_groups) {
    if (!isRecord(rawGroup) || !Array.isArray(rawGroup.capabilities)
      || rawGroup.capabilities.length < 1 || rawGroup.capabilities.length > 128) return false;
    if (rawGroup.space_id !== null || rawGroup.project_id !== null) continue;
    const expires = rawGroup.valid_until;
    if (expires !== undefined && expires !== null
      && (typeof expires !== "string" || !Number.isFinite(Date.parse(expires)))) return false;
    if (typeof expires === "string" && Date.parse(expires) <= Date.now()) continue;
    if (rawGroup.profile_key !== profile && rawGroup.profile_key !== FULL_COMPUTER_CONTROL_MODE) continue;

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

/** Build the only createAction handler exposed by the attested device MCP surface. */
export function createAttestedDeviceActionHandler(
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
    if (!validAttestedDevice(trusted)) return json({ ok: false, error: "trusted_operation_required" }, 403);

    const identity = await authenticate(request, env);
    if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
    if (identity.ownerUserId.toLowerCase() !== trusted.ownerUserId.toLowerCase()
      || identity.clientId !== trusted.clientId) {
      return json({ ok: false, error: "trusted_operation_required" }, 403);
    }

    const body = await readBoundedJsonObject(request, 16 * 1024);
    if (!body || !validCreateBody(body, trusted)) {
      return json({ ok: false, error: "product_device_action_invalid" }, 400);
    }

    const accessMode = productCapabilityAccessMode(body.action);
    try {
      const catalog = await listTargets(env, {
        ownerUserId: identity.ownerUserId,
        clientKind: identity.clientKind,
        clientId: identity.clientId,
      });
      if (!catalogAllowsAttestedDeviceAction(catalog, trusted.deviceId, body.action)) {
        return grantRequired(body.action);
      }

      const opId = operationId().toLowerCase();
      if (!isCanonicalUuid(opId)) return json({ ok: false, error: "product_action_unavailable" }, 503);
      const result: ProductActionEnqueueResult = await enqueue(env, {
        ownerUserId: identity.ownerUserId,
        spaceId: null,
        projectId: null,
        deviceId: trusted.deviceId,
        clientKind: identity.clientKind,
        clientId: identity.clientId,
        capability: body.action,
        accessMode,
        payload: body.arguments,
        idempotencyKey: `mcp-${accessMode}-${opId}`,
        expiresAt: new Date(now() + QUEUE_TTL_MS).toISOString(),
      });

      if (result.ok === false) {
        if (result.error === "product_grant_not_resolved" || result.error === "product_owner_auth_ineligible") {
          return grantRequired(body.action);
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
        return grantRequired(body.action);
      }
      return json({ ok: false, error: "product_action_unavailable" }, 503);
    }
  };
}
