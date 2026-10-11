/**
 * Canonical, read-only receipt attestation for a Relay client.
 *
 * This is NOT a second identity system or action store. The caller supplies a
 * server-owned, immutable destination scope; the signed Product MCP OAuth
 * identity and PostgreSQL SECURITY DEFINER RPC decide who may read a receipt.
 *
 * No public route or executable action is enabled by this module. The Product
 * PostgreSQL cutover (#42) must finish before Relay production exposure.
 */
import { authenticateProductMcpClientRequest, type ProductAuthEnv } from "./product_auth.ts";
import { getProductAction, type ProductPostgresEnv } from "./product_postgres_store.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";

export type ProductRelayReceiptScope = Readonly<{
  subjectId: string;
  clientId: string;
  deviceId: string;
  projectId: string | null;
  allowedActions: readonly string[];
}>;

type Env = ProductAuthEnv & ProductPostgresEnv;
type Dependencies = Readonly<{ getAction?: typeof getProductAction }>;
const CAPABILITY = /^[a-z][a-z0-9._-]{1,119}$/;

function normalizedUuid(value: unknown): string | null {
  return isCanonicalUuid(value) ? value.toLowerCase() : null;
}

function validScope(value: ProductRelayReceiptScope): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || !normalizedUuid(value.subjectId) || !normalizedUuid(value.deviceId)
    || typeof value.clientId !== "string" || value.clientId.length < 8
    || value.clientId.length > 160 || !/^[A-Za-z0-9][A-Za-z0-9._:-]+$/.test(value.clientId)
    || !(value.projectId === null || normalizedUuid(value.projectId))
    || !Array.isArray(value.allowedActions)
    || value.allowedActions.length < 1 || value.allowedActions.length > 32
    || value.allowedActions.some(action => typeof action !== "string" || !CAPABILITY.test(action))) {
    return false;
  }
  return new Set(value.allowedActions).size === value.allowedActions.length;
}

/**
 * Resolve ONLY an existing action. A valid request ID is never sufficient:
 * both signed subject/exact OAuth client and the server-selected device,
 * project and capability must match the canonical PostgreSQL record.
 *
 * The return value is boolean so no result data or identities leak to the
 * model or another spoke. Errors, revocation and database outages fail closed.
 */
export function createCanonicalRelayReceiptVerifier(env: Env, dependencies: Dependencies = {}) {
  const lookup = dependencies.getAction ?? getProductAction;
  return async (request: Request, requestId: string, scope: ProductRelayReceiptScope): Promise<boolean> => {
    if (!normalizedUuid(requestId) || !validScope(scope)) return false;
    try {
      const identity = await authenticateProductMcpClientRequest(request, env);
      if (!identity.ok
        || normalizedUuid(identity.ownerUserId) !== normalizedUuid(scope.subjectId)
        || identity.clientId !== scope.clientId || identity.clientKind !== "product-mcp") return false;

      // The existing RPC enforces owner AND exact OAuth client. Do not fall
      // back to the old D1 status handler or search for another target.
      const record = await lookup(env, {
        ownerUserId: identity.ownerUserId,
        clientKind: identity.clientKind,
        clientId: identity.clientId,
        requestId,
      });
      if (!record || typeof record !== "object" || Array.isArray(record)
        || record.ok !== true
        || normalizedUuid(record.request_id) !== normalizedUuid(requestId)
        || normalizedUuid(record.device_id) !== normalizedUuid(scope.deviceId)
        || (record.project_id === null ? null : normalizedUuid(record.project_id))
          !== (scope.projectId === null ? null : normalizedUuid(scope.projectId))
        || typeof record.capability !== "string"
        || !scope.allowedActions.includes(record.capability)) return false;
      return true;
    } catch {
      // Never expose SQL errors, JWT material, other clients' information or
      // the existence of an action to an unauthorised caller.
      return false;
    }
  };
}
