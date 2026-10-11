/**
 * Product-authorized, read-only Relay MCP composition candidate.
 *
 * Uses existing signed OAuth and PostgreSQL SECURITY DEFINER RPCs for device
 * discovery and accepted action history. It does not route, enqueue, or
 * execute actions. NOT wired to the public MCP Worker pending #42 cutover.
 */
import { authenticateProductMcpClientRequest, type ProductAuthEnv } from "./product_auth.ts";
import { createCanonicalProductMcpReadHandlers } from "./product_mcp_reads.ts";
import {
  listCanonicalProductTargets, getProductAction,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { selectCanonicalRelayProjectScope } from "./product_relay_scope.ts";
import { createCanonicalRelayReceiptVerifier } from "./product_relay_receipt.ts";
import { scopeRelayMcp } from "./product_mcp_scoped.ts";
import type { OrdaxMcpHandlers } from "./mcp_http.ts";
import { createCanonicalProductMcpGateway } from "./product_mcp_entry.ts";
import { createCanonicalCentralAdmissionVerifier, validChatGptSessionMarker, type TrustedCentralConversation } from "./product_central_admission.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type Dependencies = Readonly<{
  listTargets?: typeof listCanonicalProductTargets;
  getAction?: typeof getProductAction;
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
 * OAuth client must have exactly one authorized target with precisely one
 * project-scoped, read-only group. The authorized project UUID is authoritative
 * even if a model provides a different device/project/path argument.
 *
 * A real user with multiple devices needs an explicit, server-side binding
 * flow under Product (not model/device discovery) before Relay can support it.
 */
export function createCanonicalCentralMcpReadHandlers(
  env: Env, deps: Dependencies = {},
): OrdaxMcpHandlers {
  const listTargets = deps.listTargets ?? listCanonicalProductTargets;
  const authorizedAction = deps.getAction ?? getProductAction;
  const canonical = createCanonicalProductMcpReadHandlers(env,{
    listTargets, getAction: authorizedAction,
  });
  const attest = createCanonicalRelayReceiptVerifier(env,{getAction:authorizedAction});

  const resolver = async (request: Request) => {
    try {
      const identity = await authenticateProductMcpClientRequest(request, env);
      if (!identity.ok) return null;
      const catalog = await listTargets(env,{
        ownerUserId: identity.ownerUserId,
        clientKind: identity.clientKind,
        clientId: identity.clientId,
      });
      const target = selectCanonicalRelayProjectScope(catalog);
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
  const reads=createCanonicalCentralMcpReadHandlers(env,deps);
  const denied=()=>Response.json({ok:false,error:"central_admission_denied"},{
    status:403,headers:{"cache-control":"no-store"},
  });
  // handleOrdaxMcp intentionally creates internal GET Requests for session,
  // targets and receipts, without the incoming JSON-RPC body. Keep the
  // provider _meta check at the ORIGINAL /mcp HTTP boundary, not inside
  // the handler that receives only the authenticated internal projection.
  const admit=async(request:Request)=> (await verify(request,trusted)).ok===true;
  const guarded:OrdaxMcpHandlers={
    session:async req=>(await admit(req))?reads.session(req):denied(),
    targets:async req=>(await admit(req))?reads.targets(req):denied(),
    getAction:async(req,id)=>(await admit(req))?reads.getAction(req,id):denied(),
    createAction:async()=>denied(),
  };
  const gateway=createCanonicalProductMcpGateway(env,guarded,discoveryFetch);
  return async (request:Request):Promise<Response>=>{
    // Correlate before the canonical gateway consumes/clones the tool body.
    // GET metadata/discovery paths have no model action to correlate.
    if(request.method==="POST" && new URL(request.url).pathname==="/mcp"
      && !(await matchesCentralMcpSession(request,trusted)))return denied();
    return gateway(request);
  };
}
