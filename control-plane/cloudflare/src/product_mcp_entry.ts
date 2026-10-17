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
 * authorization source. Device/project actions are dispatched only through the
 * Runtime-attested Product session and current canonical PostgreSQL grants.
 */
import { handleOrdaxMcp, type OrdaxMcpHandlers } from "./mcp_http.ts";
import { createCanonicalProductMcpReadHandlers } from "./product_mcp_reads.ts";
import { productAuthConfigured, productOwnerAccountSession, type ProductAuthEnv } from "./product_auth.ts";
import { productPostgresConfigured, type ProductPostgresEnv } from "./product_postgres_store.ts";
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
import { createAttestedRepositoryCatalogHandler } from "./product_mcp_attested_repository_catalog.ts";
import {
  ATTESTED_MCP_PROJECT_CONTINUITY_ACTIONS,
  createAttestedProjectContinuityHandler,
} from "./product_mcp_attested_project_continuity.ts";
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
    || pathname === PRODUCT_DEVICE_CENTRAL_SESSION_PATH
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
const ATTESTED_DEVICE_COMPUTER_TOOLS: ReadonlySet<string> = new Set([
  ...ATTESTED_DEVICE_OBSERVE_TOOLS,
  ...ATTESTED_DEVICE_INTERACTIVE_TOOLS,
]);
const ATTESTED_REPOSITORY_CATALOG_TOOLS: ReadonlySet<string> = new Set([
  "repository_catalog",
]);
const ATTESTED_PROJECT_CONTINUITY_TOOLS: ReadonlySet<string> = new Set([
  "project_briefing",
  "continuity_state",
  "continuity_update",
  "handoff_create",
  "handoff_get",
]);
const ATTESTED_ACTION_TOOLS: ReadonlySet<string> = new Set([
  ...ATTESTED_DEVICE_COMPUTER_TOOLS,
  ...ATTESTED_REPOSITORY_CATALOG_TOOLS,
  ...ATTESTED_PROJECT_CONTINUITY_TOOLS,
]);
export const PRODUCT_MCP_DIRECT_TOOLS: ReadonlySet<string> = new Set([
  ...PRODUCT_MCP_CORE_READ_TOOLS,
  ...ATTESTED_ACTION_TOOLS,
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

async function resolveTrustedDevice(request: Request, env: Env): Promise<AttestedMcpDevice | null> {
  try {
    const resolved = await resolveCentralSessionFromMcp(request.clone(), env);
    if (!resolved.ok) return null;
    return Object.freeze({
      ownerUserId: resolved.ownerUserId,
      clientId: resolved.clientId,
      deviceId: resolved.deviceId,
    });
  } catch {
    return null;
  }
}

/** Injecting read handlers or a narrower tool projection is an internal test/composition seam, never an HTTP option. */
export function createCanonicalProductMcpGateway(
  env: Env,
  reads: ReadHandlers = createCanonicalProductMcpReadHandlers(env),
  discoveryFetch: typeof fetch = fetch,
  allowedTools: ReadonlySet<string> = PRODUCT_MCP_DIRECT_TOOLS,
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
        supports_project_continuity: true,
      });
    }
    if (request.method === "GET" && url.pathname === "/ready") {
      if (!productAuthConfigured(env) || !productPostgresConfigured(env)) {
        return respond({
          ok: false, service: "ordax-platform-mcp", oauth_discovery_ready: false,
          conversation_topology: "user_chatgpt_direct", model_relay: false,
          supports_attested_remote_reads: false,
          supports_remote_actions: false,
          supports_project_continuity: false,
          error: "platform_mcp_unconfigured",
        }, 503);
      }
      const discovery = await checkCanonicalProductOAuthDiscovery(String(env.PRODUCT_AUTH_ISSUER), discoveryFetch);
      return respond({
        ok: discovery.ok, service: "ordax-platform-mcp",
        oauth_discovery_ready: discovery.ok,
        conversation_topology: "user_chatgpt_direct",
        model_relay: false,
        supports_attested_remote_reads: discovery.ok,
        supports_remote_actions: discovery.ok,
        supports_project_continuity: discovery.ok,
        ...(discovery.error ? { error: discovery.error } : {}),
        ...(discovery.upstream_http_status !== undefined ? { upstream_http_status: discovery.upstream_http_status } : {}),
        ...(discovery.failure_stage ? { failure_stage: discovery.failure_stage } : {}),
      }, discovery.ok ? 200 : 503);
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
      if (toolName && allowedTools.has(toolName) && ATTESTED_ACTION_TOOLS.has(toolName)) {
        const trusted = await resolveTrustedDevice(request, env);
        if (ATTESTED_DEVICE_COMPUTER_TOOLS.has(toolName)) {
          handlers = { ...reads, createAction: createAttestedDeviceActionHandler(env, trusted) };
        } else if (ATTESTED_REPOSITORY_CATALOG_TOOLS.has(toolName)) {
          handlers = { ...reads, createAction: createAttestedRepositoryCatalogHandler(env, trusted) };
        } else if (ATTESTED_PROJECT_CONTINUITY_TOOLS.has(toolName)) {
          handlers = { ...reads, createAction: createAttestedProjectContinuityHandler(env, trusted) };
        }
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
