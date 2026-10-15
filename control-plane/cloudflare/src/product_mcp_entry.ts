/**
 * Product MCP over the canonical PostgreSQL authority.
 *
 * Staging entrypoint for #42; OAuth discovery must be proven before activation.
 * Never imports the legacy D1 Worker and never makes model arguments an
 * authorization source. Device-attested Central session bootstrap is allowed,
 * but remote action dispatch remains blocked until that bootstrap is proven E2E.
 */
import { handleOrdaxMcp, type OrdaxMcpHandlers } from "./mcp_http.ts";
import { createCanonicalProductMcpReadHandlers } from "./product_mcp_reads.ts";
import { productAuthConfigured, type ProductAuthEnv } from "./product_auth.ts";
import { productPostgresConfigured, type ProductPostgresEnv } from "./product_postgres_store.ts";
import { checkCanonicalProductOAuthDiscovery } from "./product_oauth_readiness.ts";
import {
  handleProductDeviceCentralSession,
  openCentralSessionFromMcp,
  PRODUCT_DEVICE_CENTRAL_SESSION_PATH,
} from "./product_central_device_session.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
const READ_ONLY_TOOLS: ReadonlySet<string> = new Set([
  "ordax_session", "ordax_profile", "ordax_targets", "ordax_action_status",
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

/** Injecting read handlers is an internal test seam, never an HTTP option. */
export function createCanonicalProductMcpGateway(
  env: Env,
  reads: ReadHandlers = createCanonicalProductMcpReadHandlers(env),
  discoveryFetch: typeof fetch = fetch,
) {
  const handlers: OrdaxMcpHandlers = {
    ...reads,
    // The public model still cannot choose a PC, Space, project or operation.
    // Remote enqueue is promoted only after the device-attested session path
    // has independent E2E evidence.
    createAction: async () => respond({ ok: false, error: "trusted_operation_required" }, 403),
  };
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const metadata = url.pathname === "/.well-known/oauth-protected-resource";
    if (request.method === "GET" && url.pathname === "/health") {
      return respond({
        ok: true, service: "ordax-platform-mcp",
        mode: "device-attested-session-canary",
        auth_configured: productAuthConfigured(env),
        postgres_configured: productPostgresConfigured(env),
        supports_device_attested_sessions: true,
        supports_remote_actions: false,
      });
    }
    if (request.method === "GET" && url.pathname === "/ready") {
      if (!productAuthConfigured(env) || !productPostgresConfigured(env)) {
        return respond({ ok: false, service: "ordax-platform-mcp", oauth_discovery_ready: false,
          supports_device_attested_sessions: true, supports_remote_actions: false,
          error: "platform_mcp_unconfigured" }, 503);
      }
      const discovery = await checkCanonicalProductOAuthDiscovery(String(env.PRODUCT_AUTH_ISSUER), discoveryFetch);
      return respond({
        ok: discovery.ok, service: "ordax-platform-mcp",
        oauth_discovery_ready: discovery.ok,
        supports_device_attested_sessions: true,
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
    if (url.pathname === PRODUCT_DEVICE_CENTRAL_SESSION_PATH) {
      return handleProductDeviceCentralSession(request, env);
    }
    if (url.pathname === "/mcp") {
      // ordax_session is already a safe authenticated read tool. Its only new
      // side effect is opening/renewing a short-lived, server-selected device
      // challenge from the hidden provider correlation marker. Failure to
      // open the challenge never fabricates a binding and does not weaken the
      // existing session-auth result.
      if (await mcpToolName(request) === "ordax_session") {
        try { await openCentralSessionFromMcp(request.clone(), env); } catch { /* fail closed */ }
      }
      return handleOrdaxMcp(request, handlers, READ_ONLY_TOOLS);
    }
    return respond({ ok: false, error: "not_found" }, 404);
  };
}

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return createCanonicalProductMcpGateway(env)(request);
  },
};
