/**
 * Canonical Product Relay submission candidate. Not routed publicly until
 * Product PostgreSQL cutover and a trusted, idempotent Relay command port.
 *
 * Transport supplies a unique, stable idempotency_key per user instruction.
 * GPT text cannot choose an implicit device, grant, project or executor.
 * Queue authority + effect ledger remain entirely in Product PostgreSQL.
 */
import { authenticateProductMcpClientRequest, type ProductAuthEnv } from "./product_auth.ts";
import {
  enqueueProductAction, listCanonicalProductTargets, type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { selectCanonicalRelayProjectScope } from "./product_relay_scope.ts";
import { readBoundedJsonObject } from "./request_json.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type Dependencies = Readonly<{
  listTargets?: typeof listCanonicalProductTargets;
  enqueue?: typeof enqueueProductAction;
  now?: () => number;
}>;
type Json = Record<string, unknown>;
const QUEUE_TTL_MS = 5 * 60 * 1000;
const IDEMPOTENCY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const READ_ACTIONS = new Set([
  "project.text_read", "workspace.directory_list",
  "workspace.file_stat", "workspace.text_read",
]);
const json = (value: unknown, status = 200) => Response.json(value,{
  status, headers:{"cache-control":"no-store"},
});
const denied = () => json({ok:false,error:"relay_action_denied"},403);
const unavailable = () => json({ok:false,error:"relay_action_unavailable"},503);
function isRecord(value: unknown): value is Json {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function validRelativePath(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > 512
    || value.startsWith("/") || value.endsWith("/")) return false;
  return value.split("/").every(part => part !== "" && part !== "." && part !== ".."
    && !part.endsWith(" ") && !part.endsWith(".") && part.normalize("NFKC") === part
    && !/[\\:%\x00-\x1f\x7f\u2215\u2044\uFF0F]/u.test(part)
    && !/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i.test(part));
}
function validArguments(action: string, value: unknown): value is Json {
  if (!isRecord(value) || !validRelativePath(value.path)) return false;
  const extra = action === "workspace.directory_list"
    ? ["max_depth","max_entries","include_hidden"]
    : action === "workspace.text_read" ? ["start_line","end_line"] : [];
  if (Object.keys(value).some(key => key !== "path" && !extra.includes(key))) return false;
  for(const [key,item] of Object.entries(value)){
    if(key==="path")continue;
    if(key==="include_hidden" && typeof item==="boolean")continue;
    if(key==="max_depth" && Number.isInteger(item) && (item as number)>=1 && (item as number)<=12)continue;
    if(key==="max_entries" && Number.isInteger(item) && (item as number)>=1 && (item as number)<=5000)continue;
    if((key==="start_line"||key==="end_line") && Number.isInteger(item) && (item as number)>=1
      && (item as number)<=1000000)continue;
    return false;
  }
  if(typeof value.start_line==="number" && typeof value.end_line==="number"
    && value.start_line>value.end_line)return false;
  return true;
}

/**
 * Standalone candidate handler, deliberately not exported as a public Worker
 * route. It can be wired to the existing Product endpoint ONLY after the
 * coordinated D1 -> PostgreSQL cutover is reviewed and enabled.
 */
export function createCanonicalRelayActionSubmitHandler(env: Env, deps: Dependencies = {}) {
  const targets = deps.listTargets ?? listCanonicalProductTargets;
  const enqueue = deps.enqueue ?? enqueueProductAction;
  const now = deps.now ?? Date.now;
  return async function createAction(request: Request): Promise<Response> {
    if(request.method!=="POST")return json({ok:false,error:"method_not_allowed"},405);
    const identity=await authenticateProductMcpClientRequest(request,env);
    if(!identity.ok)return json({ok:false,error:identity.error},identity.status);

    const body=await readBoundedJsonObject(request,16*1024);
    if(!body || Object.keys(body).sort().join(",")!=="action,arguments,device_id,idempotency_key,project_id,space_id"
      || !isCanonicalUuid(body.device_id) || !isCanonicalUuid(body.space_id)
      || !isCanonicalUuid(body.project_id)
      || typeof body.idempotency_key!=="string" || !IDEMPOTENCY.test(body.idempotency_key)
      || typeof body.action!=="string" || !READ_ACTIONS.has(body.action)
      || !validArguments(body.action,body.arguments))return json({ok:false,error:"relay_action_invalid"},400);

    try{
      const catalog=await targets(env,{
        ownerUserId:identity.ownerUserId,clientKind:identity.clientKind,clientId:identity.clientId,
      });
      const scope=selectCanonicalRelayProjectScope(catalog);
      if(!scope
        || scope.deviceId.toLowerCase()!==body.device_id.toLowerCase()
        || scope.spaceId.toLowerCase()!==body.space_id.toLowerCase()
        || scope.projectId.toLowerCase()!==body.project_id.toLowerCase()
        || !scope.allowedActions.includes(body.action))return denied();

      // Exactly the same immutable target, signed client and payload passed to
      // the canonical SECURITY DEFINER RPC. No local queue or fallback.
      const expiresAt=new Date(now()+QUEUE_TTL_MS).toISOString();
      const result=await enqueue(env,{
        ownerUserId:identity.ownerUserId,
        clientKind:identity.clientKind,
        clientId:identity.clientId,
        deviceId:scope.deviceId,
        spaceId:scope.spaceId,
        projectId:scope.projectId,
        capability:body.action,
        accessMode:"read",
        payload:body.arguments,
        idempotencyKey:body.idempotency_key,
        expiresAt,
      });
      if(result?.ok===false){
        if(result.error==="idempotency_conflict")return json({ok:false,error:"idempotency_conflict"},409);
        if(result.error==="product_grant_not_resolved" || result.error==="product_owner_auth_ineligible"){
          return denied();
        }
        return unavailable();
      }
      if(result?.ok!==true || !isCanonicalUuid(result.request_id)
        || !isCanonicalUuid(result.effect_id)
        || typeof result.replayed!=="boolean"
        || !["queued","leased","running","succeeded","failed","cancelled"].includes(result.status??"")){
        return unavailable();
      }
      return json({
        ok:true,request_id:result.request_id,effect_id:result.effect_id,
        status:result.status,replayed:result.replayed,
        device_id:scope.deviceId,project_id:scope.projectId,
      },result.replayed?200:202);
    }catch{
      // A timeout after a committed enqueue is UNKNOWN, not safe to resubmit
      // under a new key. Caller must retry with its exact original key.
      return unavailable();
    }
  };
}
