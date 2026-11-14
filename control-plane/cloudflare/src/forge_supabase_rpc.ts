import type {
  ForgeActionReceipt,ForgeInstanceResolution,claimForgeAction,enqueueForgeAction,
  getForgeAction,registerForgeInstance,renewForgeAction,reportForgeAction,
  startForgeAction,updateForgePresence,
} from "./forge_mcp_store.ts";
import type {ProductAuthEnv} from "./product_auth.ts";

type Json=Record<string,unknown>;
type RegisterInput=Parameters<typeof registerForgeInstance>[1];
type PresenceInput=Parameters<typeof updateForgePresence>[1];
type ResolveInput=Parameters<import("./forge_mcp_store.ts").resolveForgeMcpInstance>[1];
type EnqueueInput=Parameters<typeof enqueueForgeAction>[1];
type ClaimInput=Parameters<typeof claimForgeAction>[1];
type StartInput=Parameters<typeof startForgeAction>[1];
type RenewInput=Parameters<typeof renewForgeAction>[1];
type ReportInput=Parameters<typeof reportForgeAction>[1];
type GetInput=Parameters<typeof getForgeAction>[1];

export type ForgeSupabaseRpcEnv=ProductAuthEnv&Readonly<{
  FORGE_SUPABASE_PUBLISHABLE_KEY?:string;
}>;

const MAX_RESPONSE_BYTES=1024*1024;

function apiOrigin(env:ForgeSupabaseRpcEnv):string|null{
  const issuer=String(env.PRODUCT_AUTH_ISSUER??"").trim();
  const key=String(env.FORGE_SUPABASE_PUBLISHABLE_KEY??"").trim();
  if(!issuer||!key.startsWith("sb_publishable_"))return null;
  let url:URL;
  try{url=new URL(issuer);}catch{return null;}
  if(url.protocol!=="https:"||url.pathname.replace(/\/$/,"")!=="/auth/v1")return null;
  url.pathname="";
  url.search="";
  url.hash="";
  return url.origin;
}

export function forgeSupabaseRpcConfigured(env:ForgeSupabaseRpcEnv):boolean{
  return apiOrigin(env)!==null;
}

function bearer(value:string|null):string{
  const auth=(value??"").trim();
  if(!auth.startsWith("Bearer ")||auth.length>16384)
    throw new Error("forge_supabase_rpc_auth_required");
  return auth;
}

function isJson(value:unknown):value is Json{
  return value!==null&&typeof value==="object"&&!Array.isArray(value);
}

async function rpc(
  env:ForgeSupabaseRpcEnv,authorization:string,operation:string,payload:Json,
  fetchImpl:typeof fetch=fetch,
):Promise<Json>{
  const origin=apiOrigin(env);
  if(!origin)return {ok:false,error:"forge_supabase_rpc_unconfigured"};
  const key=String(env.FORGE_SUPABASE_PUBLISHABLE_KEY);
  let auth:string;
  try{auth=bearer(authorization);}
  catch{return {ok:false,error:"forge_supabase_rpc_auth_required"};}
  let response:Response;
  const controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),12_000);
  try{
    response=await fetchImpl(origin+"/rest/v1/rpc/ordax_forge_http_rpc_v1",{
      method:"POST",
      redirect:"error",
      signal:controller.signal,
      headers:{
        accept:"application/json",
        "content-type":"application/json",
        apikey:key,
        authorization:auth,
      },
      body:JSON.stringify({p_operation:operation,p_payload:payload}),
    });
  }catch(error){
    const name=error instanceof Error?error.name:"";
    return {ok:false,error:name==="AbortError"||name==="TimeoutError"
      ?"forge_supabase_rpc_fetch_timeout"
      :name==="TypeError"?"forge_supabase_rpc_fetch_type_error"
      :"forge_supabase_rpc_fetch_unavailable"};
  }finally{clearTimeout(timeout);}
  const declared=Number(response.headers.get("content-length")??0);
  if(declared>MAX_RESPONSE_BYTES)
    return {ok:false,error:"forge_supabase_rpc_response_too_large"};
  const text=await response.text();
  if(new TextEncoder().encode(text).byteLength>MAX_RESPONSE_BYTES)
    return {ok:false,error:"forge_supabase_rpc_response_too_large"};
  let value:unknown=null;
  try{value=JSON.parse(text);}catch{}
  if(!response.ok)
    return {ok:false,error:"forge_supabase_rpc_http_"+response.status};
  if(!isJson(value))
    return {ok:false,error:"forge_supabase_rpc_invalid_response"};
  return value;
}

export function createForgeSupabaseRpcClient(
  env:ForgeSupabaseRpcEnv,authorization:string,fetchImpl:typeof fetch=fetch,
){
  return Object.freeze({
    async register(input:RegisterInput):Promise<Json>{
      return rpc(env,authorization,"native_register",{
        instance_id:input.instanceId,display_name:input.displayName,
        app_version:input.appVersion,catalog:input.catalog,catalog_digest:input.catalogDigest,
      },fetchImpl);
    },
    async presence(input:PresenceInput):Promise<Json>{
      return rpc(env,authorization,"native_presence",{
        instance_id:input.instanceId,online:input.online,app_version:input.appVersion,
        catalog:input.catalog,catalog_digest:input.catalogDigest,
      },fetchImpl);
    },
    async resolve(_input:ResolveInput):Promise<ForgeInstanceResolution>{
      return await rpc(env,authorization,"mcp_resolve",{},fetchImpl) as ForgeInstanceResolution;
    },
    async enqueue(input:EnqueueInput):Promise<ForgeActionReceipt>{
      return await rpc(env,authorization,"mcp_enqueue",{
        instance_id:input.instanceId,tool_name:input.toolName,access_mode:input.accessMode,
        arguments:input.arguments,idempotency_key:input.idempotencyKey,expires_at:input.expiresAt,
      },fetchImpl) as ForgeActionReceipt;
    },
    async claim(input:ClaimInput):Promise<Json>{
      return rpc(env,authorization,"native_claim",{
        instance_id:input.instanceId,agent_instance_id:input.agentInstanceId,boot_id:input.bootId,
      },fetchImpl);
    },
    async start(input:StartInput):Promise<boolean>{
      const result=await rpc(env,authorization,"native_start",{
        instance_id:input.instanceId,request_id:input.requestId,attempt_id:input.attemptId,
        lease_id:input.leaseId,agent_instance_id:input.agentInstanceId,boot_id:input.bootId,
      },fetchImpl);
      return result.ok===true;
    },
    async renew(input:RenewInput):Promise<string|null>{
      const result=await rpc(env,authorization,"native_renew",{
        instance_id:input.instanceId,request_id:input.requestId,attempt_id:input.attemptId,
        lease_id:input.leaseId,agent_instance_id:input.agentInstanceId,boot_id:input.bootId,
      },fetchImpl);
      return result.ok===true&&typeof result.lease_expires_at==="string"
        ?result.lease_expires_at:null;
    },
    async report(input:ReportInput):Promise<Json>{
      return rpc(env,authorization,"native_report",{
        instance_id:input.instanceId,request_id:input.requestId,attempt_id:input.attemptId,
        lease_id:input.leaseId,agent_instance_id:input.agentInstanceId,boot_id:input.bootId,
        succeeded:input.succeeded,result:input.result??null,error_code:input.errorCode,
      },fetchImpl);
    },
    async getAction(input:GetInput):Promise<ForgeActionReceipt>{
      const result=await rpc(env,authorization,"mcp_get",{request_id:input.requestId},fetchImpl);
      return result as ForgeActionReceipt;
    },
  });
}
