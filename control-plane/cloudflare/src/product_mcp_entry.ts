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
 * authorization source. Device-attested read-only dispatch is allowed through
 * the canonical Product queue; mutating remote actions remain blocked.
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
  createAttestedDeviceReadActionHandler,
  type AttestedMcpDevice,
} from "./product_mcp_attested_device_read.ts";
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

type Env = ProductAuthEnv & ProductPostgresEnv;
export const PRODUCT_MCP_CORE_READ_TOOLS: ReadonlySet<string> = new Set([
  "ordax_session", "ordax_profile", "ordax_targets", "ordax_action_status",
]);
const ATTESTED_DEVICE_READ_TOOLS: ReadonlySet<string> = new Set([
  "computer_access_status",
  "computer_active_window",
  "computer_processes",
  "computer_screen_info",
  "computer_windows",
]);
export const PRODUCT_MCP_DIRECT_READ_TOOLS: ReadonlySet<string> = new Set([
  ...PRODUCT_MCP_CORE_READ_TOOLS,
  ...ATTESTED_DEVICE_READ_TOOLS,
]);
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

/** Injecting read handlers or a narrower tool projection is an internal test/composition seam, never an HTTP option. */
export function createCanonicalProductMcpGateway(
  env: Env,
  reads: ReadHandlers = createCanonicalProductMcpReadHandlers(env),
  discoveryFetch: typeof fetch = fetch,
  allowedTools: ReadonlySet<string> = PRODUCT_MCP_DIRECT_READ_TOOLS,
) {
  const deniedHandlers: OrdaxMcpHandlers = {
    ...reads,
    createAction: async () => respond({ ok: false, error: "trusted_operation_required" }, 403),
  };
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const metadata = url.pathname === "/.well-known/oauth-protected-resource";
    if (request.method === "GET" && url.pathname === "/health") {
      return respond({
        ok: true, service: "ordax-platform-mcp",
        mode: "attested-read-only",
        conversation_topology: "user_chatgpt_direct",
        model_relay: false,
        auth_configured: productAuthConfigured(env),
        postgres_configured: productPostgresConfigured(env),
        supports_attested_remote_reads: true,
        supports_remote_actions: false,
      });
    }
    if (request.method === "GET" && url.pathname === "/ready") {
      if (!productAuthConfigured(env) || !productPostgresConfigured(env)) {
        return respond({
          ok: false, service: "ordax-platform-mcp", oauth_discovery_ready: false,
          conversation_topology: "user_chatgpt_direct", model_relay: false,
          supports_attested_remote_reads: false,
          supports_remote_actions: false, error: "platform_mcp_unconfigured",
        }, 503);
      }
      const discovery = await checkCanonicalProductOAuthDiscovery(String(env.PRODUCT_AUTH_ISSUER), discoveryFetch);
      return respond({
        ok: discovery.ok, service: "ordax-platform-mcp",
        oauth_discovery_ready: discovery.ok,
        conversation_topology: "user_chatgpt_direct",
        model_relay: false,
        supports_attested_remote_reads: discovery.ok,
        supports_remote_actions: false,
        ...(discovery.error ? { error: discovery.error } : {}),
        ...(discovery.upstream_http_status !== undefined ? { upstream_http_status: discovery.upstream_http_status } : {}),
        ...(discovery.failure_stage ? { failure_stage: discovery.failure_stage } : {}),
      }, discovery.ok ? 200 : 503);
    }
    if (request.method === "GET" && metadata) {
      if (!productAuthConfigured(env)) return respond({ ok: false, error: "product_auth_unconfigured" }, 503);
      return respond(resourceMetadata(url.origin, String(env.PRODUCT_AUTH_ISSUER)));
    }
    if (request.method === "GET" && url.pathname === "/v3/product/session") {
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
      if (toolName && allowedTools.has(toolName) && ATTESTED_DEVICE_READ_TOOLS.has(toolName)) {
        let trusted: AttestedMcpDevice | null = null;
        try {
          const resolved = await resolveCentralSessionFromMcp(request.clone(), env);
          if (resolved.ok) {
            trusted = Object.freeze({
              ownerUserId: resolved.ownerUserId,
              clientId: resolved.clientId,
              deviceId: resolved.deviceId,
            });
          }
        } catch {
          trusted = null;
        }
        handlers = {
          ...reads,
          createAction: createAttestedDeviceReadActionHandler(env, trusted),
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
