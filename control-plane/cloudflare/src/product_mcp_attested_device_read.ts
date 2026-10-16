/**
 * Attested Product-MCP -> canonical device read enqueue boundary.
 *
 * The model may request one explicitly read-only operation, but it never
 * chooses the authoritative device or grant. The device comes from the
 * Product-MCP session attested by the Runtime and the current grant is
 * re-resolved from PostgreSQL immediately before enqueue.
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
  RELAY_DEVICE_READ_CAPABILITIES,
  selectCanonicalRelayDeviceScope,
} from "./product_relay_scope.ts";
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
const REQUIRED_OBSERVE_PROFILE = "computer-observe";

function json(value: unknown, status = 200): Response {
  return Response.json(value, {
    status,
    headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });
}

function observeGrantRequired(): Response {
  return json({
    ok: false,
    error: "product_grant_not_resolved",
    required_profile: REQUIRED_OBSERVE_PROFILE,
    owner_action: "authorize_in_ordax_studio",
  }, 403);
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

export function validAttestedDeviceReadArguments(action: string, value: unknown): value is Json {
  if (!RELAY_DEVICE_READ_CAPABILITIES.has(action) || !isRecord(value)) return false;
  const keys = Object.keys(value);
  if (["computer.access_status", "computer.active_window", "computer.screen_info"].includes(action)) {
    return keys.length === 0;
  }
  if (action === "computer.windows") {
    if (keys.some((key) => key !== "max_items")) return false;
    return value.max_items === undefined
      || (Number.isInteger(value.max_items) && Number(value.max_items) >= 1 && Number(value.max_items) <= 500);
  }
  if (action === "computer.processes") {
    if (keys.some((key) => key !== "query" && key !== "max_items")) return false;
    if (value.query !== undefined && (
      typeof value.query !== "string"
      || value.query.length > 256
      || /[\x00-\x1f\x7f]/u.test(value.query)
    )) return false;
    return value.max_items === undefined
      || (Number.isInteger(value.max_items) && Number(value.max_items) >= 1 && Number(value.max_items) <= 1000);
  }
  return false;
}

function validCreateBody(body: Json, trusted: AttestedMcpDevice): body is Json & {
  action: string;
  arguments: Json;
} {
  const keys = Object.keys(body).sort();
  if (keys.join(",") !== "action,arguments,device_id,project,space_id") return false;
  if (typeof body.action !== "string" || !validAttestedDeviceReadArguments(body.action, body.arguments)) {
    return false;
  }
  return isCanonicalUuid(body.device_id)
    && body.device_id.toLowerCase() === trusted.deviceId.toLowerCase()
    && body.project === null
    && body.space_id === null;
}

/**
 * Build the only createAction handler exposed by the first attested read-only
 * Product-MCP surface. A missing/stale session or grant always fails closed.
 */
export function createAttestedDeviceReadActionHandler(
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
    if (request.method !== "POST") {
      return json({ ok: false, error: "method_not_allowed" }, 405);
    }
    if (!validAttestedDevice(trusted)) {
      return json({ ok: false, error: "trusted_operation_required" }, 403);
    }

    const identity = await authenticate(request, env);
    if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
    if (identity.ownerUserId.toLowerCase() !== trusted.ownerUserId.toLowerCase()
      || identity.clientId !== trusted.clientId) {
      return json({ ok: false, error: "trusted_operation_required" }, 403);
    }

    const body = await readBoundedJsonObject(request, 16 * 1024);
    if (!body || !validCreateBody(body, trusted)) {
      return json({ ok: false, error: "product_read_action_invalid" }, 400);
    }

    try {
      const catalog = await listTargets(env, {
        ownerUserId: identity.ownerUserId,
        clientKind: identity.clientKind,
        clientId: identity.clientId,
      });
      const scope = selectCanonicalRelayDeviceScope(catalog, trusted.deviceId);
      if (!scope || !scope.allowedActions.includes(body.action)) {
        return observeGrantRequired();
      }

      const opId = operationId().toLowerCase();
      if (!isCanonicalUuid(opId)) {
        return json({ ok: false, error: "product_action_unavailable" }, 503);
      }
      const result: ProductActionEnqueueResult = await enqueue(env, {
        ownerUserId: identity.ownerUserId,
        spaceId: null,
        projectId: null,
        deviceId: scope.deviceId,
        clientKind: identity.clientKind,
        clientId: identity.clientId,
        capability: body.action,
        accessMode: "read",
        payload: body.arguments,
        idempotencyKey: `mcp-read-${opId}`,
        expiresAt: new Date(now() + QUEUE_TTL_MS).toISOString(),
      });

      if (result.ok === false) {
        if (result.error === "product_grant_not_resolved"
          || result.error === "product_owner_auth_ineligible") {
          return observeGrantRequired();
        }
        if (result.error === "idempotency_conflict") {
          return json({ ok: false, error: "idempotency_conflict" }, 409);
        }
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
      if (error instanceof ProductPostgresError) {
        if (error.code === "product_grant_not_resolved"
          || error.code === "product_owner_auth_ineligible") {
          return observeGrantRequired();
        }
      }
      return json({ ok: false, error: "product_action_unavailable" }, 503);
    }
  };
}
