/**
 * Product-authorized, read-only Relay MCP composition candidate.
 *
 * Uses existing signed OAuth and PostgreSQL SECURITY DEFINER RPCs for device
 * discovery and accepted action history. It does not route, enqueue, or
 * execute actions. NOT wired to the public MCP Worker pending #42 cutover.
 */
import { authenticateProductMcpClientRequest, type ProductAuthEnv } from "./product_auth.ts";
import { createCanonicalProductMcpReadHandlers } from "./product_mcp_reads.ts";
import { ensureProductMcpTargetDiscovery } from "./product_mcp_discovery_store.ts";
import {
  listCanonicalProductTargets, getProductAction,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { selectCanonicalRelayProjectScope, selectCanonicalRelayDeviceScope } from "./product_relay_scope.ts";
import { createCanonicalRelayReceiptVerifier } from "./product_relay_receipt.ts";
import { scopeRelayMcp } from "./product_mcp_scoped.ts";
import type { OrdaxMcpHandlers } from "./mcp_http.ts";
import { createCanonicalProductMcpGateway } from "./product_mcp_entry.ts";
import { createCanonicalCentralAdmissionVerifier, createPostgresCentralSessionVerifier, validChatGptSessionMarker, type TrustedCentralConversation } from "./product_central_admission.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type Dependencies = Readonly<{
  listTargets?: typeof listCanonicalProductTargets;
  getAction?: typeof getProductAction;
  ensureDiscovery?: typeof ensureProductMcpTargetDiscovery;
}>;

/**
 * Production-owner candidate for Central's read-only MCP projection.
 * Connection isolation is by SIGNED OAuth subject + exact client grants,
 * never by ChatGPT chat/project labels, prompts, headers or model arguments.
 * NOTE: a shared OAuth client across multiple Web conversations cannot
 * securely distinguish those conversations. Do not activate shared-client
 * multi-PC routing without independent caller attestation.
 *
 * Deliberately rejects clients with ambiguous entitlements. A signed Product
 * OAuth client must have exactly one authorized target and ONE read-only
 * scope type: either a device-only NULL-Space/NULL-project grant or a
 * project-scoped grant. It cannot mix the two without a trusted persisted
 * Central conversation mapping. All IDs come from canonical grants.
 *
 * A real user with multiple devices needs an explicit, server-side binding
 * flow under Product (not model/device discovery) before Relay can support it.
 */
export function createCanonicalCentralMcpReadHandlers(
  env: Env, deps: Dependencies = {},
): OrdaxMcpHandlers {
  const listTargets = deps.listTargets ?? listCanonicalProductTargets;
  const authorizedAction = deps.getAction ?? getProductAction;
  const ensureDiscovery = deps.ensureDiscovery ?? ensureProductMcpTargetDiscovery;
  const canonical = createCanonicalProductMcpReadHandlers(env,{
    listTargets, getAction: authorizedAction, ensureDiscovery,
  });
  const attest = createCanonicalRelayReceiptVerifier(env,{getAction:authorizedAction});

  const resolver = async (request: Request) => {
    try {
      const identity = await authenticateProductMcpClientRequest(request, env);
      if (!identity.ok) return null;
      const discovery = await ensureDiscovery(env, identity.ownerUserId, identity.clientId);
      if (!discovery.ok) return null;
      const catalog = await listTargets(env,{
        ownerUserId: identity.ownerUserId,
        clientKind: identity.clientKind,
        clientId: identity.clientId,
      });
      const project = selectCanonicalRelayProjectScope(catalog);
      const device = selectCanonicalRelayDeviceScope(catalog);
      // Without a durable session mapping the OAuth client must represent
      // exactly ONE type of authority on precisely ONE computer. Never
      // prefer global PC reads over scoped projects or vice versa.
      if (!!project === !!device) return null;
      const target = project ?? device;
      if (!target) return null;
      return Object.freeze({
        deviceId: target.deviceId,
        subjectId: identity.ownerUserId,
        clientId: identity.clientId,
        spaceId: target.spaceId,
        project: "canonical",
        projectId: target.projectId,
        rootPath: "canonical",
        actions: target.allowedActions,
      });
    } catch { return null; }
  };

  return scopeRelayMcp({
    ...canonical,
    // Never forward writes to legacy D1 or a guessed Runtime target.
    async createAction() {
      return Response.json({ok:false,error:"relay_read_only"},{
        status:403,headers:{"cache-control":"no-store"},
      });
    },
  },resolver,(request,requestId,scope)=>{
    if (scope.projectId === undefined) return Promise.resolve(false);
    return attest(request,requestId,{
      subjectId:scope.subjectId,clientId:scope.clientId,
      deviceId:scope.deviceId,projectId:scope.projectId,
      allowedActions:scope.actions,
    });
  });
}

// Preserve the laboratory export shape while keeping one canonical owner.
export const createCanonicalRelayReadOnlyHandlers = createCanonicalCentralMcpReadHandlers;

/**
 * Inactive composition candidate for a Central-bound Product MCP connection.
 * Reuses the existing read-only canary gateway, protocol and OAuth discovery.
 * It advertises only the four safe Product MCP tools; no execution endpoint,
 * D1 Worker, provider session, cookie or conversation-specific authority.
 * DO NOT install/activate for a shared ChatGPT OAuth connection unless each
 * plugin connection is independently attested for exactly one device.
 */
export function createCanonicalCentralMcpGateway(
  env: Env, deps: Dependencies = {}, discoveryFetch: typeof fetch = fetch,
) {
  return createCanonicalProductMcpGateway(env,createCanonicalCentralMcpReadHandlers(env,deps),discoveryFetch);
}

/**
 * ChatGPT includes an anonymized per-conversation correlation marker in
 * tools/call params._meta["openai/session"] (Jan 2026 host contract).
 * It is NOT a signed identity or grant. A client can spoof request metadata;
 * only the canonical OAuth, Product grant and durable verifySession can
 * establish authority. On every tool call, still refuse another marker.
 *
 * tools/list/initialize do not carry the marker and are not action receipts;
 * existing Product gateway handles their authenticated discovery.
 */
export async function matchesCentralMcpSession(
  request:Request, trusted:TrustedCentralConversation | null,
):Promise<boolean> {
  try {
    const value=await request.clone().json() as Record<string,unknown>;
    if(!value || typeof value!=="object" || Array.isArray(value))return false;
    if(value.method!=="tools/call")return true;
    if(!validChatGptSessionMarker(trusted?.sessionId))return false;
    const params=value.params;
    if(!params || typeof params!=="object" || Array.isArray(params))return false;
    const meta=(params as Record<string,unknown>)._meta;
    if(!meta || typeof meta!=="object" || Array.isArray(meta))return false;
    return (meta as Record<string,unknown>)["openai/session"]===trusted?.sessionId;
  }catch{return false;}
}

/**
 * Internal MCP composition for a trusted, persisted Central turn. Enforces
 * admission on EVERY exposed tool call, including tools/list via session(),
 * before invoking canonical read handlers. No public route is installed here.
 *
 * A caller MUST supply a genuine durable verifySession function from the
 * Product conversation authority; a browser's chat ID is not that authority.
 * With no such owner connected, this factory refuses construction.
 */
export function createCanonicalCentralSessionMcpGateway(
  env: Env, trusted: TrustedCentralConversation | null,
  deps: Dependencies & { verifySession: Parameters<typeof createCanonicalCentralAdmissionVerifier>[1]["verifySession"] },
  discoveryFetch: typeof fetch = fetch,
) {
  const verify=createCanonicalCentralAdmissionVerifier(env,deps);
  const authorizedAction=deps.getAction ?? getProductAction;
  const ensureDiscovery=deps.ensureDiscovery ?? ensureProductMcpTargetDiscovery;
  const canonical=createCanonicalProductMcpReadHandlers(env,{
    listTargets:deps.listTargets ?? listCanonicalProductTargets,
    getAction:authorizedAction,
    ensureDiscovery,
  });
  const attest=createCanonicalRelayReceiptVerifier(env,{getAction:authorizedAction});
  const denied=()=>Response.json({ok:false,error:"central_admission_denied"},{
    status:403,headers:{"cache-control":"no-store"},
  });

  // Crucially, use the SAME authenticated, durable-session admission to
  // select the authorized PC for every read. An unbound OAuth client with
  // several targets is intentionally ambiguous, but an independently
  // attested Central request can select its precise PC. NEVER use a model
  // argument or a device header as a replacement for this admission.
  const resolver=async(request:Request)=>{
    const allowed=await verify(request,trusted);
    if(!allowed.ok)return null;
    return Object.freeze({
      deviceId:allowed.deviceId,subjectId:allowed.subjectId,
      clientId:allowed.clientId,spaceId:allowed.spaceId,
      project:"canonical",projectId:allowed.projectId,
      rootPath:"canonical",actions:allowed.allowedActions,
    });
  };
  const scoped=scopeRelayMcp({
    ...canonical,
    // A provider session gets only read projections and existing receipts;
    // durable Product command enqueue is a distinct trusted request path.
    createAction:async()=>denied(),
  },resolver,(request,requestId,scope)=>attest(request,requestId,{
    subjectId:scope.subjectId,clientId:scope.clientId,
    deviceId:scope.deviceId,
    projectId:scope.projectId === undefined ? null : scope.projectId,
    allowedActions:scope.actions,
  }));
  const gateway=createCanonicalProductMcpGateway(env,scoped,discoveryFetch);
  return async (request:Request):Promise<Response>=>{
    // The original JSON-RPC request carries the provider correlation marker.
    // Internal read projections become GET Requests and lose that body, so
    // correlate BEFORE dispatch and recheck Product session per tool call.
    if(request.method==="POST" && new URL(request.url).pathname==="/mcp"
      && !(await matchesCentralMcpSession(request,trusted)))return denied();
    return gateway(request);
  };
}

/**
 * Production-candidate composition with the REAL durable session verifier.
 *
 * This is the single canonical path from the Product PostgreSQL association
 * to the existing scoped MCP read gateway. A caller must still supply a
 * TRUSTED binding from its authenticated Central host; constructing this
 * gateway does not attest the ChatGPT provider marker. No route is mounted
 * in the public Worker until such an independent host attestation exists.
 *
 * Unlike test-only construction, there is no optional verifySession callback
 * that can be replaced by a model-provided boolean or header.
 */
export function createPersistedCentralSessionMcpGateway(
  env: Env,
  trusted: TrustedCentralConversation | null,
  deps: Dependencies = {},
  discoveryFetch: typeof fetch = fetch,
) {
  return createCanonicalCentralSessionMcpGateway(
    env,trusted,{...deps,verifySession:createPostgresCentralSessionVerifier(env)},
    discoveryFetch,
  );
}
