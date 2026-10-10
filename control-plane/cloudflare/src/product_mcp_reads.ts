import { authenticateProductMcpClientRequest, type ProductAuthEnv } from "./product_auth.ts";
import { sanitizeTargets, isProductActionStatus, type OrdaxMcpHandlers } from "./mcp_http.ts";
import {
  listCanonicalProductTargets,
  getProductAction,
  ProductPostgresError,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";

type ReadEnv = ProductAuthEnv & ProductPostgresEnv;
type ReadHandlers = Pick<OrdaxMcpHandlers, "session" | "targets" | "getAction">;
type ReadDependencies = {
  listTargets?: typeof listCanonicalProductTargets;
  getAction?: typeof getProductAction;
};

function json(value: unknown, status = 200): Response {
  return Response.json(value, { status, headers: { "cache-control": "no-store" } });
}

function validCatalog(value: unknown): value is { ok: true; targets: Record<string, unknown>[] } {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const result = value as Record<string, unknown>;
  if (result.ok !== true || !Array.isArray(result.targets)) return false;
  const ids = new Set<string>();
  return result.targets.every((target) => {
    if (!target || typeof target !== "object" || Array.isArray(target)) return false;
    const id = (target as Record<string, unknown>).device_id;
    if (!isCanonicalUuid(id) || ids.has(id.toLowerCase())) return false;
    ids.add(id.toLowerCase());
    return true;
  });
}

function timestamp(value: unknown): string | null {
  return typeof value === "string" && value.length <= 40 && Number.isFinite(Date.parse(value))
    ? new Date(value).toISOString() : null;
}

function validAction(value: unknown, requestId: string): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const action = value as Record<string, unknown>;
  return action.ok === true
    && isCanonicalUuid(action.request_id)
    && action.request_id.toLowerCase() === requestId.toLowerCase()
    && isCanonicalUuid(action.device_id)
    && isCanonicalUuid(action.effect_id)
    && (action.project_id === null || isCanonicalUuid(action.project_id))
    && typeof action.capability === "string"
    && action.capability.length >= 2 && action.capability.length <= 120
    && /^[a-z][a-z0-9._-]+$/.test(action.capability)
    && isProductActionStatus(action.status)
    && timestamp(action.created_at) !== null
    && [action.started_at, action.finished_at].every(item => item === null || timestamp(item) !== null)
    && (action.error_code === null || (typeof action.error_code === "string"
      && action.error_code.length >= 1 && action.error_code.length <= 120
      && !/[\x00-\x1f]/.test(action.error_code)))
    && Object.hasOwn(action, "result") && action.result !== undefined;
}

function unavailable(error: unknown, code: string): Response {
  // Do not publish database messages, connection strings or SQL details.
  const unconfigured = error instanceof ProductPostgresError
    && error.code === "product_postgres_unconfigured";
  return json({ ok: false, error: unconfigured ? "product_postgres_unconfigured" : code }, 503);
}

/**
 * Read handlers for the coordinated Product MCP cutover (#42).
 * Not wired into index.ts while action/grant/status routes still use D1.
 * The signed OAuth identity selects the existing canonical RPC; no caller
 * header/body, registry scan, legacy fallback or local grant decision is used.
 * Dependencies are transport-test seams, never request input. Status reads do
 * not enumerate targets or enqueue/replay work: accepted action history is
 * scoped by the existing RPC to its owner and exact client, including offline.
 */
export function createCanonicalProductMcpReadHandlers(
  env: ReadEnv,
  dependencies: ReadDependencies = {},
): ReadHandlers {
  const readTargets = dependencies.listTargets ?? listCanonicalProductTargets;
  const readAction = dependencies.getAction ?? getProductAction;
  return {
    async session(request) {
      const identity = await authenticateProductMcpClientRequest(request, env);
      if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
      return json({
        ok: true,
        session: {
          subject_id: identity.ownerUserId,
          client_kind: identity.clientKind,
          client_id: identity.clientId,
          expires_at_unix: identity.expiresAt,
        },
      });
    },
    async targets(request) {
      const identity = await authenticateProductMcpClientRequest(request, env);
      if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
      try {
        const result = await readTargets(env, {
          ownerUserId: identity.ownerUserId,
          clientKind: identity.clientKind,
          clientId: identity.clientId,
        });
        // Eligibility and exact-client grant resolution remain in PostgreSQL.
        if (result?.ok === false && result.error === "product_owner_auth_ineligible") {
          return json({ ok: false, error: "product_owner_auth_ineligible" }, 403);
        }
        if (!validCatalog(result)) {
          return json({ ok: false, error: "product_postgres_invalid_response" }, 502);
        }
        return json(sanitizeTargets(result));
      } catch (error) {
        return unavailable(error, "product_targets_unavailable");
      }
    },
    async getAction(request, requestId) {
      const identity = await authenticateProductMcpClientRequest(request, env);
      if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
      if (!isCanonicalUuid(requestId)) return json({ ok: false, error: "product_request_id_invalid" }, 400);
      try {
        const result = await readAction(env, {
          ownerUserId: identity.ownerUserId,
          clientKind: identity.clientKind,
          clientId: identity.clientId,
          requestId,
        });
        if (result === null) return json({ ok: false, error: "product_action_not_found" }, 404);
        if (result?.ok === false && result.error === "product_owner_auth_ineligible") {
          return json({ ok: false, error: "product_owner_auth_ineligible" }, 403);
        }
        if (!validAction(result, requestId)) {
          return json({ ok: false, error: "product_postgres_invalid_response" }, 502);
        }
        // Preserve the canonical project UUID, never invent a legacy slug.
        // The authorized RPC result is a Runtime-owned Product result; HTTP
        // exposes only the published action fields, not arbitrary DB columns.
        return json({ ok: true, action: {
          request_id: result.request_id,
          device_id: result.device_id,
          action: result.capability,
          project: null,
          project_id: result.project_id,
          status: result.status,
          effect_id: result.effect_id,
          result: result.result,
          error_code: result.error_code,
          created_at: timestamp(result.created_at),
          started_at: timestamp(result.started_at),
          finished_at: timestamp(result.finished_at),
        } });
      } catch (error) {
        return unavailable(error, "product_action_status_unavailable");
      }
    },
  };
}
