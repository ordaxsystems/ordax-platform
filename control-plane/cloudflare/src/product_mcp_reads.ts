import { authenticateProductMcpClientRequest, type ProductAuthEnv } from "./product_auth.ts";
import { sanitizeTargets, isProductActionStatus, type OrdaxMcpHandlers } from "./mcp_http.ts";
import {
  listCanonicalProductTargets,
  getProductAction,
  ProductPostgresError,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { ensureProductMcpTargetDiscovery } from "./product_mcp_discovery_store.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";

type ReadEnv = ProductAuthEnv & ProductPostgresEnv;
type ReadHandlers = Pick<OrdaxMcpHandlers, "session" | "targets" | "getAction">;
type ReadDependencies = {
  listTargets?: typeof listCanonicalProductTargets;
  getAction?: typeof getProductAction;
  ensureDiscovery?: typeof ensureProductMcpTargetDiscovery;
};

const RUNTIME_KINDS = new Set(["ordax-os", "desktop-agent", "mobile-client", "other"]);

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

function validRuntimeProvenance(action: Record<string, unknown>): boolean {
  const kind = action.execution_runtime_kind;
  const version = action.execution_agent_version;
  const absentKind = kind === null || kind === undefined;
  const absentVersion = version === null || version === undefined;
  if (absentKind && absentVersion) return true;
  if (absentKind !== absentVersion) return false;
  return typeof kind === "string" && RUNTIME_KINDS.has(kind)
    && typeof version === "string" && version.length >= 1 && version.length <= 80
    && version === version.trim() && !/[\x00-\x1f\x7f]/u.test(version);
}

function validAction(value: unknown, requestId: string): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const action = value as Record<string, unknown>;
  return action.ok === true
    && isCanonicalUuid(action.request_id)
    && action.request_id.toLowerCase() === requestId.toLowerCase()
    && isCanonicalUuid(action.device_id)
    && isCanonicalUuid(action.effect_id)
    && (action.space_id === null || isCanonicalUuid(action.space_id))
    && (action.project_id === null || isCanonicalUuid(action.project_id))
    && typeof action.capability === "string"
    && action.capability.length >= 2 && action.capability.length <= 120
    && /^[a-z][a-z0-9._-]+$/.test(action.capability)
    && isProductActionStatus(action.status)
    && validRuntimeProvenance(action)
    && timestamp(action.created_at) !== null
    && [action.started_at, action.finished_at].every(item => item === null || timestamp(item) !== null)
    && (action.error_code === null || (typeof action.error_code === "string"
      && action.error_code.length >= 1 && action.error_code.length <= 120
      && !/[\x00-\x1f]/.test(action.error_code)))
    && Object.hasOwn(action, "result") && action.result !== undefined;
}

function unavailable(error: unknown, code: string): Response {
  const unconfigured = error instanceof ProductPostgresError
    && error.code === "product_postgres_unconfigured";
  return json({ ok: false, error: unconfigured ? "product_postgres_unconfigured" : code }, 503);
}

/**
 * Read handlers for the canonical Product MCP boundary. The signed OAuth
 * identity selects both the owner and exact MCP client. On target reads, that
 * already-consented identity may materialize only product.target.read/read
 * grants for active devices owned by the same subject; PostgreSQL independently
 * verifies consent and ownership before any authority changes.
 */
export function createCanonicalProductMcpReadHandlers(
  env: ReadEnv,
  dependencies: ReadDependencies = {},
): ReadHandlers {
  const readTargets = dependencies.listTargets ?? listCanonicalProductTargets;
  const readAction = dependencies.getAction ?? getProductAction;
  const ensureDiscovery = dependencies.ensureDiscovery ?? ensureProductMcpTargetDiscovery;
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
        const discovery = await ensureDiscovery(env, identity.ownerUserId, identity.clientId);
        if (!discovery.ok) {
          if (discovery.error === "product_mcp_oauth_consent_required") {
            return json({ ok: false, error: discovery.error }, 403);
          }
          return json({ ok: false, error: "product_target_discovery_grant_failed" }, 403);
        }
        const result = await readTargets(env, {
          ownerUserId: identity.ownerUserId,
          clientKind: identity.clientKind,
          clientId: identity.clientId,
        });
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
        return json({ ok: true, action: {
          request_id: result.request_id,
          device_id: result.device_id,
          space_id: result.space_id,
          action: result.capability,
          project: null,
          project_id: result.project_id,
          status: result.status,
          effect_id: result.effect_id,
          result: result.result,
          error_code: result.error_code,
          execution_runtime_kind: result.execution_runtime_kind ?? null,
          execution_agent_version: result.execution_agent_version ?? null,
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
