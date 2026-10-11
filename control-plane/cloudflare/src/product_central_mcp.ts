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
