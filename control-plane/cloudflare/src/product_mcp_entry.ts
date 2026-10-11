/**
 * Product MCP over the canonical PostgreSQL authority.
 *
 * Staging entrypoint for #42. Never imports the legacy D1 Worker, never
 * dispatches a model-provided operation and never becomes a second grant owner.
 * Runtime enrolment, durable trusted-operation dispatch and provider inference
 * must be completed before promoting this source to the production Worker.
 */
import { handleOrdaxMcp, type OrdaxMcpHandlers } from "./mcp_http.ts";
import { createCanonicalProductMcpReadHandlers } from "./product_mcp_reads.ts";
import { productAuthConfigured, type ProductAuthEnv } from "./product_auth.ts";
import { productPostgresConfigured, type ProductPostgresEnv } from "./product_postgres_store.ts";

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

/** Injecting read handlers is an internal test seam, never an HTTP option. */
export function createCanonicalProductMcpGateway(env: Env, reads: ReadHandlers = createCanonicalProductMcpReadHandlers(env)) {
  const handlers: OrdaxMcpHandlers = {
    ...reads,
    // The public model cannot choose a PC, Space, project or operation ID.
    // Relay submission needs a durable trusted binding through the existing
    // PostgreSQL enqueue RPC, not an extra model-facing createAction route.
    createAction: async () => respond({ ok: false, error: "trusted_operation_required" }, 403),
  };
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const metadata = url.pathname === "/.well-known/oauth-protected-resource";
    if (request.method === "GET" && url.pathname === "/health") {
      // Not a liveness guarantee for accounts/devices/inference.
      return respond({
        ok: true, service: "ordax-platform-mcp",
        mode: "read-only-canary",
        auth_configured: productAuthConfigured(env),
        postgres_configured: productPostgresConfigured(env),
        supports_remote_actions: false,
      });
    }
    if (request.method === "GET" && metadata) {
      if (!productAuthConfigured(env)) return respond({ ok: false, error: "product_auth_unconfigured" }, 503);
      return respond(resourceMetadata(url.origin, String(env.PRODUCT_AUTH_ISSUER)));
    }
    if (url.pathname === "/mcp") {
      return handleOrdaxMcp(request, handlers, READ_ONLY_TOOLS);
    }
    // No inherited legacy routes, unscoped actions, worker-admin endpoints,
    // device enrolment, D1 fallback or provider credentials in this canary.
    return respond({ ok: false, error: "not_found" }, 404);
  };
}

export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return createCanonicalProductMcpGateway(env)(request);
  },
};
