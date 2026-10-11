/**
 * Internal Relay -> canonical Product enqueue contract.
 *
 * The model only supplies an action and its constrained read arguments. Device,
 * project, space and the persistent idempotency identity are passed separately
 * by a trusted, server-side caller. This handler is intentionally not mounted
 * on the public MCP Worker: its second argument cannot be reconstructed from
 * tool JSON or user-controlled HTTP headers.
 *
 * PostgreSQL's existing enqueue RPC owns grants, durable idempotency and jobs.
 */
import { authenticateProductMcpClientRequest, type ProductAuthEnv } from "./product_auth.ts";
import {
  enqueueProductAction, listCanonicalProductTargets, type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { selectCanonicalRelayProjectScope } from "./product_relay_scope.ts";
import { readBoundedJsonObject } from "./request_json.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type Dependencies = Readonly<{
  listTargets?: typeof listCanonicalProductTargets;
  enqueue?: typeof enqueueProductAction;
  now?: () => number;
}>;
export type TrustedRelayOperation = Readonly<{
  /** Signed Product subject, never read from a model payload. */
  subjectId: string;
  /** Exact OAuth client from the authorized transport. */
  clientId: string;
  /** Selected by Product/Studio, never by the model. */
  deviceId: string;
  spaceId: string;
  projectId: string;
  /** Persisted UUID allocated ONCE by the trusted host before dispatch. */
  operationId: string;
}>;

type Json = Record<string, unknown>;
const QUEUE_TTL_MS = 5 * 60 * 1000;
const READ_ACTIONS = new Set([
  "project.text_read", "workspace.directory_list",
  "workspace.file_stat", "workspace.text_read",
]);
const json = (value: unknown, status = 200): Response => Response.json(value, {
  status, headers: { "cache-control": "no-store" },
});
const denied = () => json({ ok: false, error: "relay_action_denied" }, 403);
const unavailable = () => json({ ok: false, error: "relay_action_unavailable" }, 503);
function isRecord(value: unknown): value is Json {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function validBinding(value: unknown): value is TrustedRelayOperation {
  if (!isRecord(value) || Object.keys(value).sort().join(",") !==
      "clientId,deviceId,operationId,projectId,spaceId,subjectId") return false;
  return isCanonicalUuid(value.subjectId) && isCanonicalUuid(value.deviceId)
    && isCanonicalUuid(value.spaceId) && isCanonicalUuid(value.projectId)
    && isCanonicalUuid(value.operationId)
    && typeof value.clientId === "string" && value.clientId.length >= 8
    && value.clientId.length <= 160
    && /^[A-Za-z0-9][A-Za-z0-9._:-]+$/.test(value.clientId);
}
function validRelativePath(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > 512
    || value.startsWith("/") || value.endsWith("/")) return false;
  return value.split("/").every(part => part !== "" && part !== "." && part !== ".."
    && !part.endsWith(" ") && !part.endsWith(".") && part.normalize("NFKC") === part
    && !/[\\:%\x00-\x1f\x7f\u2215\u2044\uFF0F]/u.test(part)
    && !/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i.test(part));
}
function validArguments(action: string, value: unknown): value is Json {
  if (!isRecord(value) || !validRelativePath(value.path)) return false;
  const extra = action === "workspace.directory_list"
    ? ["max_depth", "max_entries", "include_hidden"]
    : action === "workspace.text_read" ? ["start_line", "end_line"] : [];
  if (Object.keys(value).some(key => key !== "path" && !extra.includes(key))) return false;
  for (const [key, item] of Object.entries(value)) {
    if (key === "path") continue;
    if (key === "include_hidden" && typeof item === "boolean") continue;
    if (key === "max_depth" && Number.isInteger(item) && (item as number) >= 1 && (item as number) <= 12) continue;
    if (key === "max_entries" && Number.isInteger(item) && (item as number) >= 1 && (item as number) <= 5000) continue;
    if ((key === "start_line" || key === "end_line") && Number.isInteger(item)
      && (item as number) >= 1 && (item as number) <= 1000000) continue;
    return false;
  }
  if (typeof value.start_line === "number" && typeof value.end_line === "number"
    && value.start_line > value.end_line) return false;
  return true;
}

/**
 * No route adapter is supplied here. The trusted host MUST persist operationId
 * before its first send and reuse the exact same binding for retry/recovery.
 * A missing binding fails closed. Passing an LLM-generated binding is forbidden.
 */
export function createCanonicalRelayActionSubmitHandler(env: Env, deps: Dependencies = {}) {
  const targets = deps.listTargets ?? listCanonicalProductTargets;
  const enqueue = deps.enqueue ?? enqueueProductAction;
  const now = deps.now ?? Date.now;
  return async function createAction(
    request: Request, trustedOperation: TrustedRelayOperation | null,
  ): Promise<Response> {
    if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
    const identity = await authenticateProductMcpClientRequest(request, env);
    if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
    if (!validBinding(trustedOperation)
      || trustedOperation.subjectId.toLowerCase() !== identity.ownerUserId.toLowerCase()
      || trustedOperation.clientId !== identity.clientId) return denied();

    const body = await readBoundedJsonObject(request, 16 * 1024);
    if (!body || Object.keys(body).sort().join(",") !== "action,arguments"
      || typeof body.action !== "string" || !READ_ACTIONS.has(body.action)
      || !validArguments(body.action, body.arguments)) {
      return json({ ok: false, error: "relay_action_invalid" }, 400);
    }

    try {
      const catalog = await targets(env, {
        ownerUserId: identity.ownerUserId,
        clientKind: identity.clientKind,
        clientId: identity.clientId,
      });
      const scope = selectCanonicalRelayProjectScope(catalog, trustedOperation.deviceId);
      if (!scope
        || scope.deviceId.toLowerCase() !== trustedOperation.deviceId.toLowerCase()
        || scope.spaceId.toLowerCase() !== trustedOperation.spaceId.toLowerCase()
        || scope.projectId.toLowerCase() !== trustedOperation.projectId.toLowerCase()
        || !scope.allowedActions.includes(body.action)) return denied();

      // Trusted operation UUID, NOT a model-provided key. The PostgreSQL RPC
      // records one effect per owner/idempotency key and prevents unsafe replay.
      const idempotencyKey = "relay-" + trustedOperation.operationId.toLowerCase();
      const expiresAt = new Date(now() + QUEUE_TTL_MS).toISOString();
      const result = await enqueue(env, {
        ownerUserId: identity.ownerUserId,
        clientKind: identity.clientKind,
        clientId: identity.clientId,
        deviceId: scope.deviceId,
        spaceId: scope.spaceId,
        projectId: scope.projectId,
        capability: body.action,
        accessMode: "read",
        payload: body.arguments,
        idempotencyKey,
        expiresAt,
      });
      if (result?.ok === false) {
        if (result.error === "idempotency_conflict")
          return json({ ok: false, error: "idempotency_conflict" }, 409);
        if (result.error === "product_grant_not_resolved" ||
          result.error === "product_owner_auth_ineligible") return denied();
        return unavailable();
      }
      if (result?.ok !== true || !isCanonicalUuid(result.request_id)
        || !isCanonicalUuid(result.effect_id) || typeof result.replayed !== "boolean"
        || !["queued", "leased", "running", "succeeded", "failed", "cancelled"]
          .includes(result.status ?? "")) return unavailable();

      return json({
        ok: true, request_id: result.request_id, effect_id: result.effect_id,
        status: result.status, replayed: result.replayed,
        device_id: scope.deviceId, project_id: scope.projectId,
      }, result.replayed ? 200 : 202);
    } catch {
      // Timeout after commit is ambiguous: NEVER mint another operationId.
      return unavailable();
    }
  };
}
