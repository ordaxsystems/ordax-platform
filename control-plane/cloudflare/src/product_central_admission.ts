/**
 * Product-authorized Central conversation admission.
 *
 * NOT a ChatGPT conversation authentication mechanism. Each request has a
 * signed OAuth client, one canonical Product target and an independent,
 * trusted, durable conversation mapping verified by the host's authority.
 * A browser URL, ChatGPT Project, model prompt or MCP argument cannot mint
 * that mapping. No Product mapping adapter is wired up yet: consumers must
 * supply verifySession from an authenticated, authoritative implementation.
 *
 * Internal only. Never mount the "binding" parameter on a model-facing route.
 */
import { authenticateProductMcpClientRequest, type ProductAuthEnv } from "./product_auth.ts";
import { listCanonicalProductTargets, type ProductPostgresEnv } from "./product_postgres_store.ts";
import { selectCanonicalRelayProjectScope } from "./product_relay_scope.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type CanonicalClient = Readonly<{ownerUserId:string; clientId:string; clientKind:"product-mcp"}>;
export type TrustedCentralConversation = Readonly<{
  subjectId: string;
  clientId: string;
  deviceId: string;
  spaceId: string;
  projectId: string;
  requestId: string;
  /** Stable, host-observed provider conversation identifier, not a grant. */
  conversationId: string;
  /** ChatGPT MCP _meta["openai/session"] marker; correlation only. */
  sessionId?: string;
}>;
export type VerifiedCentralAdmission = Readonly<{
  subjectId: string;
  clientId: string;
  deviceId: string;
  spaceId: string;
  projectId: string;
  requestId: string;
  conversationId: string;
  allowedActions: readonly string[];
  expiresAt: number;
}>;
type VerifySession = (client: CanonicalClient, binding: TrustedCentralConversation) => Promise<boolean>;
type Dependencies = Readonly<{
  listTargets?: typeof listCanonicalProductTargets;
  /** Required authority lookup, backed by persisted server-owned records.
   * This callback MUST NOT simply return true or trust the model/request body. */
  verifySession: VerifySession;
}>;

const CLIENT=/^[A-Za-z0-9][A-Za-z0-9._:-]+$/;
const CONVERSATION=/^[A-Za-z0-9_-]{8,128}$/;
const KEYS="clientId,conversationId,deviceId,projectId,requestId,spaceId,subjectId";
const KEYS_WITH_SESSION="clientId,conversationId,deviceId,projectId,requestId,sessionId,spaceId,subjectId";
export const validChatGptSessionMarker=(value:unknown):value is string=>
  typeof value==="string" && value.length>=8 && value.length<=256
  && !/[\x00-\x20\x7f]/u.test(value);
function validBinding(value: unknown): value is TrustedCentralConversation {
  if(!value || typeof value!=="object" || Array.isArray(value))return false;
  const b=value as Record<string,unknown>;
  return (Object.keys(b).sort().join(",")===KEYS
      || Object.keys(b).sort().join(",")===KEYS_WITH_SESSION)
    && (b.sessionId===undefined || validChatGptSessionMarker(b.sessionId))
    && isCanonicalUuid(b.subjectId) && isCanonicalUuid(b.deviceId)
    && isCanonicalUuid(b.spaceId) && isCanonicalUuid(b.projectId)
    && isCanonicalUuid(b.requestId) && typeof b.clientId==="string"
    && b.clientId.length>=8 && b.clientId.length<=160
    && CLIENT.test(b.clientId)
    && typeof b.conversationId==="string" && CONVERSATION.test(b.conversationId);
}
const deny=()=>Object.freeze({ok:false as const,error:"central_admission_denied" as const});
const unavailable=()=>Object.freeze({ok:false as const,error:"central_admission_unavailable" as const});
export type CentralAdmissionResult = VerifiedCentralAdmission & {ok:true} |
  ReturnType<typeof deny> | ReturnType<typeof unavailable>;

/**
 * Revalidates ALL authority for each operation. This includes a second
 * independent check that the conversation mapping actually exists in the
 * trusted owner. Without a real verifySession provider, construction fails.
 *
 * The OAuth client MUST have exactly one eligible device and project; there
 * is no "pick the device ID from the prompt" fallback. Any grant revocation,
 * invalid OAuth client or missing/stale mapping fails closed.
 */
export function createCanonicalCentralAdmissionVerifier(env: Env, deps: Dependencies) {
  if(!deps || typeof deps.verifySession!=="function") {
    throw new TypeError("central_session_authority_required");
  }
  const targets=deps.listTargets ?? listCanonicalProductTargets;
  return async (request: Request, trusted: TrustedCentralConversation | null): Promise<CentralAdmissionResult> => {
    if(!validBinding(trusted))return deny();
    try {
      const identity=await authenticateProductMcpClientRequest(request,env);
      if(!identity.ok || identity.ownerUserId.toLowerCase()!==trusted.subjectId.toLowerCase()
        || identity.clientId!==trusted.clientId) return deny();
      const client:CanonicalClient=Object.freeze({
        ownerUserId:identity.ownerUserId, clientKind:identity.clientKind,
        clientId:identity.clientId,
      });
      const catalog=await targets(env,client);
      // No trusted-device hint here: a single OAuth client with multiple
      // PCs is ambiguous for ChatGPT Web and must never choose by prompt.
      const scope=selectCanonicalRelayProjectScope(catalog);
      if(!scope || scope.deviceId.toLowerCase()!==trusted.deviceId.toLowerCase()
        || scope.spaceId.toLowerCase()!==trusted.spaceId.toLowerCase()
        || scope.projectId.toLowerCase()!==trusted.projectId.toLowerCase())return deny();
      // The callback must consult an authoritative durable owner; its boolean
      // is NOT inferred from the URL, JavaScript state or a model argument.
      if((await deps.verifySession(client,trusted))!==true)return deny();
      return Object.freeze({
        ok:true as const,
        subjectId:identity.ownerUserId, clientId:identity.clientId,
        deviceId:scope.deviceId, spaceId:scope.spaceId, projectId:scope.projectId,
        requestId:trusted.requestId, conversationId:trusted.conversationId,
        allowedActions:scope.allowedActions, expiresAt:identity.expiresAt,
      });
    } catch {
      return unavailable();
    }
  };
}
