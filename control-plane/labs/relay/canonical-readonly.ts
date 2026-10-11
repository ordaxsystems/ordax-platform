/**
 * Product-authorized, read-only Relay MCP composition candidate.
 *
 * Uses existing signed OAuth and PostgreSQL SECURITY DEFINER RPCs for device
 * discovery and accepted action history. It does not route, enqueue, or
 * execute actions. NOT wired to the public MCP Worker pending #42 cutover.
 */
import { authenticateProductMcpClientRequest, type ProductAuthEnv } from "../../cloudflare/src/product_auth.ts";
import { createCanonicalProductMcpReadHandlers } from "../../cloudflare/src/product_mcp_reads.ts";
import {
  listCanonicalProductTargets, getProductAction,
  type ProductPostgresEnv,
} from "../../cloudflare/src/product_postgres_store.ts";
import { isCanonicalUuid } from "../../cloudflare/src/product_remote_grant_contract.ts";
import { createCanonicalRelayReceiptVerifier } from "../../cloudflare/src/product_relay_receipt.ts";
import { scopeRelayMcp } from "./scoped-mcp.ts";
import type { OrdaxMcpHandlers } from "../../cloudflare/src/mcp_http.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type Dependencies = Readonly<{
  listTargets?: typeof listCanonicalProductTargets;
  getAction?: typeof getProductAction;
}>;
const READ_ACTIONS = new Set(["workspace.directory_list", "workspace.file_stat", "workspace.text_read"]);

/**
 * Deliberately rejects clients with ambiguous entitlements. A signed Product
 * OAuth client must have exactly one authorized target with precisely one
 * project-scoped, read-only group. The authorized project UUID is authoritative
 * even if a model provides a different device/project/path argument.
 *
 * A real user with multiple devices needs an explicit, server-side binding
 * flow under Product (not model/device discovery) before Relay can support it.
 */
export function createCanonicalRelayReadOnlyHandlers(
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
      if (!catalog || catalog.ok !== true || !Array.isArray(catalog.targets)
        || catalog.targets.length !== 1) return null;
      const target = catalog.targets[0] as Record<string,unknown>;
      if (!target || !isCanonicalUuid(target.device_id)
        || !Array.isArray(target.grant_groups)) return null;

      const grants = target.grant_groups.filter(grant => {
        if (!grant || typeof grant !== "object" || Array.isArray(grant)) return false;
        const g = grant as Record<string,unknown>;
        // The RPC is authoritative for active grants. Expiration is also
        // checked here to fail closed if an outdated projection is returned.
        if (g.valid_until !== undefined && g.valid_until !== null
          && (typeof g.valid_until !== "string"
            || !Number.isFinite(Date.parse(g.valid_until))
            || Date.parse(g.valid_until) <= Date.now())) return false;
        return isCanonicalUuid(g.project_id) && isCanonicalUuid(g.space_id)
          && Array.isArray(g.capabilities)
          && g.capabilities.some(item => {
            if (!item || typeof item !== "object" || Array.isArray(item)) return false;
            const p = item as Record<string,unknown>;
            return READ_ACTIONS.has(p.capability as string) && p.access_mode === "read";
          });
      }) as Record<string,unknown>[];

      // Deny ambiguous multi-project scopes. No silent picking by order.
      if (grants.length !== 1) return null;
      const grant = grants[0];
      const available = (grant.capabilities as Record<string,unknown>[])
        .filter(item => item && typeof item === "object"
          && READ_ACTIONS.has(item.capability as string) && item.access_mode === "read")
        .map(item => item.capability as string);
      if (!available.length || new Set(available).size !== available.length) return null;
      return Object.freeze({
        deviceId: target.device_id as string,
        subjectId: identity.ownerUserId,
        clientId: identity.clientId,
        spaceId: grant.space_id as string,
        project: "canonical",
        projectId: grant.project_id as string,
        rootPath: "canonical",
        actions: available,
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
