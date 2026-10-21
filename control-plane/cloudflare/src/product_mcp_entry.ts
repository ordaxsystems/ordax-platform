/**
 * Product MCP over the canonical PostgreSQL authority.
 *
 * This is the direct-user ChatGPT MCP path. It may coordinate OAuth, device
 * identity, grants and short-lived session attestation, but it MUST NOT relay
 * the user's prompt to a model provider. Historical `product_central_*` names
 * in this entrypoint refer to session/attestation machinery, not to the OrdaX
 * Central multi-client inference relay.
 *
 * Never imports the legacy D1 Worker and never makes model arguments an
 * authorization source. Device actions are dispatched only through the
 * Runtime-attested Product session and current canonical PostgreSQL grants.
 */
import { handleOrdaxMcp, type OrdaxMcpHandlers } from "./mcp_http.ts";
import { handleProductDevicePresence, PRODUCT_DEVICE_PRESENCE_PATH } from "./product_device_presence.ts";
import { createCanonicalProductMcpReadHandlers } from "./product_mcp_reads.ts";
import { productAuthConfigured, productOwnerAccountSession, type ProductAuthEnv } from "./product_auth.ts";
import { checkCanonicalProductPostgresReadiness, productPostgresConfigured, type ProductPostgresEnv } from "./product_postgres_store.ts";
import { checkCanonicalProductOAuthDiscovery } from "./product_oauth_readiness.ts";
import {
  handleProductDeviceCentralSession,
  openCentralSessionFromMcp,
  resolveCentralSessionFromMcp,
  PRODUCT_DEVICE_CENTRAL_SESSION_PATH,
} from "./product_central_device_session.ts";
import {
  createAttestedDeviceActionHandler,
  type AttestedMcpDevice,
} from "./product_mcp_attested_device_action.ts";
import { createAttestedProjectActionHandler } from "./product_mcp_attested_project_action.ts";
import {
  handleProductDeviceSetup,
  PRODUCT_DEVICE_SETUP_PATH,
} from "./product_device_setup.ts";
import {
  handleProductDeviceTransport,
  PRODUCT_DEVICE_TRANSPORT_PREFIX,
} from "./product_device_transport.ts";
import {
  handleProductOwnerGrantAdmin,
  PRODUCT_OWNER_REMOTE_AUTHORITY_PATH,
  PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH,
} from "./product_owner_grant_admin.ts";
import {
  handleProductOwnerProjectScope,
  PRODUCT_OWNER_PROJECT_SCOPE_PATH,
} from "./product_owner_project_scope.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;

// ChatGPT keeps the only public MCP identity on mcp.ordax.com.br. The
// workers.dev hostname is a separate, path-restricted network ingress for the
// installed Runtime and Studio when the branded custom domain is unreachable
// from a device network. It reuses the same Worker, OAuth checks, PostgreSQL
// authority and handlers; it is not a second MCP server or fallback authority.
export const PRODUCT_TRUSTED_CLIENT_HOSTNAME = "ordax-mcp.ordaxsystems.workers.dev";
export const PRODUCT_OWNER_SESSION_PATH = "/v3/product/session";
export function isProductTrustedClientPath(pathname: string): boolean {
  return pathname === PRODUCT_OWNER_SESSION_PATH
    || pathname === PRODUCT_DEVICE_SETUP_PATH
    || pathname === PRODUCT_DEVICE_PRESENCE_PATH
    || pathname === PRODUCT_DEVICE_CENTRAL_SESSION_PATH
    || pathname === PRODUCT_OWNER_PROJECT_SCOPE_PATH
    || pathname === PRODUCT_OWNER_REMOTE_AUTHORITY_PATH
    || pathname === PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH
    || pathname.startsWith(PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH + "/")
    || pathname.startsWith(PRODUCT_DEVICE_TRANSPORT_PREFIX + "/");
}

export const PRODUCT_MCP_CORE_READ_TOOLS: ReadonlySet<string> = new Set([
  "ordax_session", "ordax_profile", "ordax_targets", "ordax_action_status",
]);
const ATTESTED_DEVICE_OBSERVE_TOOLS: ReadonlySet<string> = new Set([
  "computer_access_status",
  "computer_active_window",
  "computer_processes",
  "computer_screen_info",
  "computer_windows",
]);
const ATTESTED_DEVICE_INTERACTIVE_TOOLS: ReadonlySet<string> = new Set([
  "computer_screenshot",
  "computer_focus_window",
  "computer_click",
  "computer_mouse_move",
  "computer_drag",
  "computer_launch_app",
  "computer_scroll",
  "computer_type",
  "computer_hotkey",
]);
const ATTESTED_DEVICE_FILESYSTEM_READ_TOOLS: ReadonlySet<string> = new Set([
  "computer_file_stat",
  "computer_directory_list",
  "computer_text_read",
  "computer_search",
]);
const ATTESTED_DEVICE_TEXT_EDIT_TOOLS: ReadonlySet<string> = new Set([
  "computer_text_write",
  "computer_text_patch",
]);
const ATTESTED_DEVICE_FILESYSTEM_MUTATION_TOOLS: ReadonlySet<string> = new Set([
  "computer_directory_create",
  "computer_path_move",
  "computer_path_remove",
]);
const ATTESTED_DEVICE_CLIPBOARD_TOOLS: ReadonlySet<string> = new Set([
  "computer_clipboard_read",
  "computer_clipboard_write",
]);
const ATTESTED_DEVICE_PROCESS_TOOLS: ReadonlySet<string> = new Set([
  "computer_terminate_process",
]);
const ATTESTED_DEVICE_NATIVE_EXECUTION_TOOLS: ReadonlySet<string> = new Set([
  "computer_terminal_exec",
  "computer_process_start",
  "computer_process_status",
  "computer_process_list",
  "computer_process_logs",
  "computer_process_write_stdin",
  "computer_process_stop",
]);
const ATTESTED_DEVICE_ACTION_TOOLS: ReadonlySet<string> = new Set([
  ...ATTESTED_DEVICE_OBSERVE_TOOLS,
  ...ATTESTED_DEVICE_INTERACTIVE_TOOLS,
  ...ATTESTED_DEVICE_FILESYSTEM_READ_TOOLS,
  ...ATTESTED_DEVICE_TEXT_EDIT_TOOLS,
  ...ATTESTED_DEVICE_FILESYSTEM_MUTATION_TOOLS,
  ...ATTESTED_DEVICE_CLIPBOARD_TOOLS,
  ...ATTESTED_DEVICE_PROCESS_TOOLS,
  ...ATTESTED_DEVICE_NATIVE_EXECUTION_TOOLS,
]);
export const ATTESTED_PROJECT_NATIVE_TOOLS: ReadonlySet<string> = new Set([
  "terminal_exec", "process_start", "process_status", "process_list",
  "process_logs", "process_write_stdin", "process_stop",
]);
export const PRODUCT_MCP_DIRECT_TOOLS: ReadonlySet<string> = new Set([
  ...PRODUCT_MCP_CORE_READ_TOOLS,
  ...ATTESTED_DEVICE_ACTION_TOOLS,
  ...ATTESTED_PROJECT_NATIVE_TOOLS,
]);
// Compatibility export for callers/tests that previously consumed the read-only name.
export const PRODUCT_MCP_DIRECT_READ_TOOLS = PRODUCT_MCP_DIRECT_TOOLS;
type ReadHandlers = Pick<OrdaxMcpHandlers, "session" | "targets" | "getAction">;
function respond(value: unknown, status = 200): Response {
  return Response.json(value, { status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
}
function resourceMetadata(origin: string, issuer: string) {
  return {
    resource: origin + "/mcp",
    authorization_servers: [issuer],
    bearer_methods_supported: ["header"],
    scopes_supported: ["openid", "email", "offline_access"],
  };
}

async function mcpToolName(request: Request): Promise<string | null> {
  if (request.method !== "POST") return null;
  try {
    const body = await request.clone().json() as Record<string, unknown>;
    if (!body || body.jsonrpc !== "2.0" || body.method !== "tools/call") return null;
    const params = body.params;
    if (!params || typeof params !== "object" || Array.isArray(params)) return null;
    const name = (params as Record<string, unknown>).name;
    return typeof name === "string" ? name : null;
  } catch {
    return null;
  }
}

/** Session recovery is only coordination. A device remains trusted exclusively
 * after the canonical PostgreSQL binding has been confirmed by that Runtime.
 * A missing, invalid or revoked OAuth/session identity never triggers recovery.
 */
type SessionRecoveryDependencies = Readonly<{
  resolve?: typeof resolveCentralSessionFromMcp;
  open?: typeof openCentralSessionFromMcp;
  wait?: (milliseconds: number) => Promise<void>;
}>;

// The installed Runtime 1.30.3 polls challenges every 20 seconds. Keep one
// bounded legacy compatibility window until managed Runtime upgrades converge
// on the existing five-second heartbeat. Device confirmation is still required.
// Public, bounded remediation codes. They explain why a trusted session was
// not established, but never grant a device or dispatch an action.
const CENTRAL_SESSION_REMEDIATION_ERRORS: ReadonlySet<string> = new Set([
  "central_session_marker_required",
  "central_device_target_missing",
  "central_device_target_ambiguous",
  "central_session_revoked",
  "central_session_target_mismatch",
]);
const SESSION_CONFIRMATION_ATTEMPTS = 12;
const SESSION_CONFIRMATION_INTERVAL_MS = 2000;
function waitForSessionConfirmation(milliseconds: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

export async function resolveOrBootstrapAttestedSession(
  request: Request,
  env: Env,
  deps: SessionRecoveryDependencies = {},
): Promise<Awaited<ReturnType<typeof resolveCentralSessionFromMcp>>> {
  const resolve = deps.resolve ?? resolveCentralSessionFromMcp;
  let result = await resolve(request.clone(), env);
  if (result.ok || result.error !== "central_session_unbound") return result;

  // This is the same device-confirmed challenge normally opened by ordax_session.
  // PostgreSQL chooses an eligible target; no device_id from MCP arguments is used.
  const opened = await (deps.open ?? openCentralSessionFromMcp)(request.clone(), env);
  if (!opened.ok) {
    const failed: unknown = await opened.clone().json().catch(() => null);
    const code = failed && typeof failed === "object" && !Array.isArray(failed)
      ? (failed as Record<string, unknown>).error : null;
    return typeof code === "string" && CENTRAL_SESSION_REMEDIATION_ERRORS.has(code)
      ? { ok: false as const, error: code }
      : result;
  }
  const payload: unknown = await opened.clone().json().catch(() => null);
  if (!payload || typeof payload !== "object" || (payload as Record<string, unknown>).ok !== true) {
    return result;
  }
  const wait = deps.wait ?? waitForSessionConfirmation;
  for (let attempt = 0; attempt < SESSION_CONFIRMATION_ATTEMPTS; attempt += 1) {
    await wait(SESSION_CONFIRMATION_INTERVAL_MS);
    result = await resolve(request.clone(), env);
    if (result.ok || result.error !== "central_session_unbound") return result;
  }
  // No grant, device target or operation is inferred from a pending challenge.
  return { ok: false as const, error: "central_session_pending" };
}

/** Injecting read handlers or a narrower tool projection is an internal test/composition seam, never an HTTP option. */
export function createCanonicalProductMcpGateway(
  env: Env,
  reads: ReadHandlers = createCanonicalProductMcpReadHandlers(env),
  discoveryFetch: typeof fetch = fetch,
  allowedTools: ReadonlySet<string> = PRODUCT_MCP_DIRECT_TOOLS,
  recoveryDependencies: SessionRecoveryDependencies = {},
  postgresReadiness: typeof checkCanonicalProductPostgresReadiness = checkCanonicalProductPostgresReadiness,
) {
  const deniedHandlers: OrdaxMcpHandlers = {
    ...reads,
    createAction: async () => respond({ ok: false, error: "trusted_operation_required" }, 403),
  };
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (url.hostname === PRODUCT_TRUSTED_CLIENT_HOSTNAME && !isProductTrustedClientPath(url.pathname)) {
      return respond({ ok: false, error: "not_found" }, 404);
    }
    const metadata = url.pathname === "/.well-known/oauth-protected-resource";
    if (request.method === "GET" && url.pathname === "/health") {
      return respond({
        ok: true, service: "ordax-platform-mcp",
        mode: "attested-device-control",
        conversation_topology: "user_chatgpt_direct",
        model_relay: false,
        auth_configured: productAuthConfigured(env),
        postgres_configured: productPostgresConfigured(env),
        supports_attested_remote_reads: true,
        supports_remote_actions: true,
      });
    }
    if (request.method === "GET" && url.pathname === "/ready") {
      if (!productAuthConfigured(env) || !productPostgresConfigured(env)) {
        return respond({
          ok: false, service: "ordax-platform-mcp", oauth_discovery_ready: false,
          postgres_ready: null,
          conversation_topology: "user_chatgpt_direct", model_relay: false,
          supports_attested_remote_reads: false,
          supports_remote_actions: false, error: "platform_mcp_unconfigured",
        }, 503);
      }
      const discovery = await checkCanonicalProductOAuthDiscovery(String(env.PRODUCT_AUTH_ISSUER), discoveryFetch);
      // OAuth metadata alone is NOT database readiness. During the Hyperdrive
      // outage, discovery was healthy while all target/heartbeat SQL failed.
      // Do not add a second connection authority or synthesize device state.
      const postgres = discovery.ok ? await postgresReadiness(env) : null;
      const ready = discovery.ok && postgres?.ok === true;
      return respond({
        ok: ready, service: "ordax-platform-mcp",
        oauth_discovery_ready: discovery.ok,
        postgres_ready: postgres?.ok ?? null,
        conversation_topology: "user_chatgpt_direct",
        model_relay: false,
        supports_attested_remote_reads: ready,
        supports_remote_actions: ready,
        ...(discovery.error ? { error: discovery.error } : {}),
        ...(discovery.upstream_http_status !== undefined ? { upstream_http_status: discovery.upstream_http_status } : {}),
        ...(discovery.failure_stage ? { failure_stage: discovery.failure_stage } : {}),
        ...(postgres?.error ? { error: postgres.error } : {}),
        ...(postgres?.failure_stage ? { postgres_failure_stage: postgres.failure_stage } : {}),
      }, ready ? 200 : 503);
    }
    if (request.method === "GET" && metadata) {
      if (!productAuthConfigured(env)) return respond({ ok: false, error: "product_auth_unconfigured" }, 503);
      return respond(resourceMetadata(url.origin, String(env.PRODUCT_AUTH_ISSUER)));
    }
    if (request.method === "GET" && url.pathname === PRODUCT_OWNER_SESSION_PATH) {
      // Studio owner validation shares the same signed Product identity boundary
      // as enrollment. It does not grant MCP client permissions or remote actions.
      return productOwnerAccountSession(request, env);
    }
    if (url.pathname === PRODUCT_DEVICE_SETUP_PATH) {
      return handleProductDeviceSetup(request, env);
    }
    if (url.pathname === PRODUCT_DEVICE_PRESENCE_PATH) {
      // Same PostgreSQL device identity as MCP targets; never the legacy D1 writer.
      return handleProductDevicePresence(request, env);
    }
    if (url.pathname === PRODUCT_DEVICE_CENTRAL_SESSION_PATH) {
      return handleProductDeviceCentralSession(request, env);
    }
    if (url.pathname.startsWith(PRODUCT_DEVICE_TRANSPORT_PREFIX + "/")) {
      return handleProductDeviceTransport(request, env);
    }
    if (url.pathname === PRODUCT_OWNER_PROJECT_SCOPE_PATH) {
      return handleProductOwnerProjectScope(request, env);
    }
    if (url.pathname === PRODUCT_OWNER_REMOTE_AUTHORITY_PATH
        || url.pathname === PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH
        || url.pathname.startsWith(PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH + "/")) {
      return handleProductOwnerGrantAdmin(request, env);
    }
    if (url.pathname === "/mcp") {
      const toolName = await mcpToolName(request);
      // ordax_session is already a safe authenticated read tool. Its only new
      // side effect is opening/renewing a short-lived, server-selected device
      // challenge from the hidden provider correlation marker. This is session
      // coordination for the direct MCP path; it is not Central model relay.
      if (toolName === "ordax_session") {
        try { await openCentralSessionFromMcp(request.clone(), env); } catch { /* fail closed */ }
      }

      let handlers = deniedHandlers;
      if (toolName && allowedTools.has(toolName)
        && (ATTESTED_DEVICE_ACTION_TOOLS.has(toolName) || ATTESTED_PROJECT_NATIVE_TOOLS.has(toolName))) {
        let trusted: AttestedMcpDevice | null = null;
        let pending = false;
        let trustFailure: string | null = null;
        try {
          const resolved = await resolveOrBootstrapAttestedSession(request.clone(), env, recoveryDependencies);
          if (resolved.ok) {
            trusted = Object.freeze({
              ownerUserId: resolved.ownerUserId,
              clientId: resolved.clientId,
              deviceId: resolved.deviceId,
            });
          } else {
            pending = resolved.error === "central_session_pending";
            if (CENTRAL_SESSION_REMEDIATION_ERRORS.has(resolved.error)) {
              trustFailure = resolved.error;
            }
          }
        } catch {
          trusted = null;
        }
        handlers = {
          ...reads,
          createAction: pending
            ? async () => respond({ ok: false, error: "central_session_pending" }, 409)
            : trustFailure
              ? async () => respond({ ok: false, error: trustFailure }, 409)
              : ATTESTED_PROJECT_NATIVE_TOOLS.has(toolName)
              ? createAttestedProjectActionHandler(env, trusted)
              : createAttestedDeviceActionHandler(env, trusted),
        };
      }
      return handleOrdaxMcp(request, handlers, allowedTools);
    }
    return respond({ ok: false, error: "not_found" }, 404);
  };
}

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return createCanonicalProductMcpGateway(env)(request);
  },
};
