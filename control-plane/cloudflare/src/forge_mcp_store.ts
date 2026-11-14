import {openPostgresSession} from "./data_postgres_driver.ts";
import type {ProductPostgresEnv} from "./product_postgres_store.ts";

type Json=Record<string,unknown>;

function connectionString(env:ProductPostgresEnv):string {
  const raw=(env.POSTGRES?.connectionString??"").trim();
  if(!raw)throw new Error("product_postgres_unconfigured");
  const parsed=new URL(raw);
  if(parsed.protocol!=="postgres:"&&parsed.protocol!=="postgresql:")
    throw new Error("product_postgres_unconfigured");
  return raw;
}

async function rpc<T>(env:ProductPostgresEnv,name:string,args:unknown[]):Promise<T>{
  const client=openPostgresSession(connectionString(env));
  try{
    await client.connect();
    const placeholders=args.map((_,i)=>"$"+(i+1)).join(",");
    const result=await client.query(`select public.${name}(${placeholders}) as result`,args);
    const value=(result.rows[0] as {result?:unknown}|undefined)?.result;
    if(value===undefined)throw new Error("product_postgres_invalid_response");
    return value as T;
  }catch(error){
    if(error instanceof Error&&error.message.startsWith("product_"))throw error;
    throw new Error("product_postgres_unavailable");
  }finally{
    try{await client.end();}catch{}
  }
}

export type ForgeInstanceResolution=Readonly<{
  ok:boolean;
  error?:string;
  candidate_count?:number;
  instance_id?:string;
  display_name?:string;
  app_version?:string;
  catalog?:unknown[];
  catalog_digest?:string;
  online?:boolean;
  last_seen_at?:string|null;
}>;

export type ForgeActionReceipt=Readonly<{
  ok:boolean;
  error?:string;
  replayed?:boolean;
  request_id?:string;
  effect_id?:string;
  status?:string;
  result?:unknown;
  error_code?:string|null;
  created_at?:string;
  started_at?:string|null;
  finished_at?:string|null;
}>;

export async function registerForgeInstance(env:ProductPostgresEnv,input:Readonly<{
  ownerUserId:string;instanceId:string;displayName:string;appVersion:string;
  catalog:unknown[];catalogDigest:string;
}>):Promise<Json>{
  return rpc<Json>(env,"ordax_register_forge_instance_v1",[
    input.ownerUserId,input.instanceId,input.displayName,input.appVersion,
    JSON.stringify(input.catalog),input.catalogDigest,
  ]);
}

export async function updateForgePresence(env:ProductPostgresEnv,input:Readonly<{
  ownerUserId:string;instanceId:string;online:boolean;appVersion:string;
  catalog:unknown[];catalogDigest:string;
}>):Promise<Json>{
  return rpc<Json>(env,"ordax_update_forge_presence_v1",[
    input.ownerUserId,input.instanceId,input.online,input.appVersion,
    JSON.stringify(input.catalog),input.catalogDigest,
  ]);
}

export async function resolveForgeMcpInstance(env:ProductPostgresEnv,input:Readonly<{
  ownerUserId:string;clientId:string;
}>):Promise<ForgeInstanceResolution>{
  return rpc<ForgeInstanceResolution>(env,"ordax_resolve_forge_mcp_instance_v1",[
    input.ownerUserId,input.clientId,
  ]);
}

export async function enqueueForgeAction(env:ProductPostgresEnv,input:Readonly<{
  ownerUserId:string;clientId:string;instanceId:string;toolName:string;
  accessMode:"read"|"write";arguments:Json;idempotencyKey:string;expiresAt:string;
}>):Promise<ForgeActionReceipt>{
  return rpc<ForgeActionReceipt>(env,"ordax_enqueue_forge_action_v1",[
    input.ownerUserId,input.clientId,input.instanceId,input.toolName,input.accessMode,
    JSON.stringify(input.arguments),input.idempotencyKey,input.expiresAt,
  ]);
}

export async function claimForgeAction(env:ProductPostgresEnv,input:Readonly<{
  ownerUserId:string;instanceId:string;agentInstanceId:string;bootId:string;
}>):Promise<Json>{
  return rpc<Json>(env,"ordax_claim_forge_action_v1",[
    input.ownerUserId,input.instanceId,input.agentInstanceId,input.bootId,
  ]);
}

export async function startForgeAction(env:ProductPostgresEnv,input:Readonly<{
  ownerUserId:string;instanceId:string;requestId:string;attemptId:string;leaseId:string;
  agentInstanceId:string;bootId:string;
}>):Promise<boolean>{
  return rpc<boolean>(env,"ordax_start_forge_action_v1",[
    input.ownerUserId,input.instanceId,input.requestId,input.attemptId,input.leaseId,
    input.agentInstanceId,input.bootId,
  ]);
}

export async function renewForgeAction(env:ProductPostgresEnv,input:Readonly<{
  ownerUserId:string;instanceId:string;requestId:string;attemptId:string;leaseId:string;
  agentInstanceId:string;bootId:string;
}>):Promise<string|null>{
  return rpc<string|null>(env,"ordax_renew_forge_action_v1",[
    input.ownerUserId,input.instanceId,input.requestId,input.attemptId,input.leaseId,
    input.agentInstanceId,input.bootId,
  ]);
}

export async function reportForgeAction(env:ProductPostgresEnv,input:Readonly<{
  ownerUserId:string;instanceId:string;requestId:string;attemptId:string;leaseId:string;
  agentInstanceId:string;bootId:string;succeeded:boolean;result:unknown;errorCode:string|null;
}>):Promise<Json>{
  return rpc<Json>(env,"ordax_report_forge_action_v1",[
    input.ownerUserId,input.instanceId,input.requestId,input.attemptId,input.leaseId,
    input.agentInstanceId,input.bootId,input.succeeded,
    input.result===undefined?null:JSON.stringify(input.result),input.errorCode,
  ]);
}

export async function getForgeAction(env:ProductPostgresEnv,input:Readonly<{
  ownerUserId:string;clientId:string;requestId:string;
}>):Promise<ForgeActionReceipt>{
  return rpc<ForgeActionReceipt>(env,"ordax_get_forge_action_v1",[
    input.ownerUserId,input.clientId,input.requestId,
  ]);
}
