import {readBoundedJsonObject} from "./request_json.ts";
import {isCanonicalUuid} from "./product_remote_grant_contract.ts";
import {
  authenticateProductMcpClientRequest,authenticateProductRequest,
  productAuthConfigured,type ProductAuthEnv,type VerifiedProductMcpClient,
} from "./product_auth.ts";
import {verifiedMcpRetryDigest} from "./mcp_http.ts";
import {productPostgresConfigured,type ProductPostgresEnv} from "./product_postgres_store.ts";
import {
  registerForgeInstance,updateForgePresence,resolveForgeMcpInstance,
  enqueueForgeAction,claimForgeAction,startForgeAction,renewForgeAction,
  reportForgeAction,getForgeAction,type ForgeInstanceResolution,type ForgeActionReceipt,
} from "./forge_mcp_store.ts";

type Env=ProductAuthEnv&ProductPostgresEnv&Readonly<{
  /** Public OAuth client for the native Forge app only; never an Owner-wide grant. */
  FORGE_NATIVE_OAUTH_CLIENT_ID?:string;
}>;
type Json=Record<string,unknown>;
type ForgeTool=Readonly<{
  name:string;description:string;inputSchema:Json;
  annotations?:Readonly<Record<string,unknown>>;
}>;

export const FORGE_MCP_HOSTNAME="forge-mcp.ordax.com.br";
export const FORGE_INSTANCE_REGISTER_PATH="/v1/forge/instance/register";
export const FORGE_INSTANCE_PRESENCE_PATH="/v1/forge/instance/presence";
export const FORGE_INSTANCE_CLAIM_PATH="/v1/forge/instance/claim";
export const FORGE_INSTANCE_START_PATH="/v1/forge/instance/start";
export const FORGE_INSTANCE_RENEW_PATH="/v1/forge/instance/renew";
export const FORGE_INSTANCE_REPORT_PATH="/v1/forge/instance/report";
const FORGE_RESOURCE_METADATA_PATH="/.well-known/oauth-protected-resource";
const MAX_BODY=512*1024;
const MAX_RESULT=384*1024;
const ACTION_TTL_MS=2*60*1000;
const DEFAULT_WAIT_MS=8000;
const TERMINAL=new Set(["succeeded","failed","cancelled","expired"]);
const TOOL_NAME=/^forge_[a-z0-9_]{2,112}$/;
const HEX64=/^[0-9a-f]{64}$/;

const CONNECTION_TOOL:ForgeTool=Object.freeze({
  name:"forge_connection_status",
  description:"Inspect the persistent binding between this OAuth client and the user's Forge instance. This does not create a project, run work or grant filesystem authority.",
  inputSchema:{type:"object",properties:{},required:[],additionalProperties:false},
  annotations:{readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false},
});
const ACTION_STATUS_TOOL:ForgeTool=Object.freeze({
  name:"forge_action_status",
  description:"Read the status/result of an existing Forge gateway request_id without re-enqueuing the operation.",
  inputSchema:{type:"object",properties:{request_id:{type:"string",format:"uuid"}},required:["request_id"],additionalProperties:false},
  annotations:{readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false},
});
const META_NAMES=new Set([CONNECTION_TOOL.name,ACTION_STATUS_TOOL.name]);

function json(body:unknown,status=200,headers:Record<string,string>={}):Response{
  return Response.json(body,{status,headers:{
    "cache-control":"no-store","x-content-type-options":"nosniff",...headers,
  }});
}
function rpcResult(id:unknown,result:unknown):Response{
  return json({jsonrpc:"2.0",id,result});
}
function rpcError(id:unknown,code:number,message:string,status=200):Response{
  return json({jsonrpc:"2.0",id,error:{code,message}},status);
}
function toolResult(value:unknown,isError=false):Json{
  return {
    ...(isError?{isError:true}:{}),
    content:[{type:"text",text:JSON.stringify(value)}],
    structuredContent:value,
  };
}
function isRecord(value:unknown):value is Json{
  return value!==null&&typeof value==="object"&&!Array.isArray(value);
}
function exactKeys(value:Json,keys:readonly string[]):boolean{
  const actual=Object.keys(value).sort();
  return actual.length===keys.length&&actual.every((key,i)=>key===([...keys].sort())[i]);
}
function boundedString(value:unknown,min:number,max:number):value is string{
  return typeof value==="string"&&value.length>=min&&value.length<=max
    &&!/[\x00\x7f]/u.test(value);
}
function validCatalogTool(value:unknown):value is ForgeTool{
  if(!isRecord(value)||!TOOL_NAME.test(String(value.name??""))
    ||!boundedString(value.description,1,4000)||!isRecord(value.inputSchema))return false;
  const schema=value.inputSchema;
  if(schema.type!=="object"||!isRecord(schema.properties)
    ||!Array.isArray(schema.required)
    ||schema.required.some(x=>typeof x!=="string")
    ||schema.additionalProperties!==false)return false;
  if(value.annotations!==undefined&&!isRecord(value.annotations))return false;
  return true;
}
export function validForgeCatalog(value:unknown):value is ForgeTool[]{
  if(!Array.isArray(value)||value.length<1||value.length>64)return false;
  const names=new Set<string>();
  for(const tool of value){
    if(!validCatalogTool(tool)||names.has(tool.name))return false;
    names.add(tool.name);
  }
  return !names.has("forge_work_send")&&!names.has("forge_forjador_send");
}
function canonical(value:unknown):unknown{
  if(Array.isArray(value))return value.map(canonical);
  if(isRecord(value)){
    const out:Json={};
    for(const key of Object.keys(value).sort())out[key]=canonical(value[key]);
    return out;
  }
  return value;
}
async function sha256(value:unknown):Promise<string>{
  const bytes=new TextEncoder().encode(JSON.stringify(canonical(value)));
  const digest=await crypto.subtle.digest("SHA-256",bytes);
  return Array.from(new Uint8Array(digest),x=>x.toString(16).padStart(2,"0")).join("");
}
async function validatedCatalog(catalog:unknown,digest:unknown):Promise<ForgeTool[]|null>{
  if(!validForgeCatalog(catalog)||typeof digest!=="string"||!HEX64.test(digest))return null;
  return await sha256(catalog)===digest?catalog:null;
}
function metadata(origin:string,issuer:string):Json{
  return {
    resource:origin+"/mcp",
    authorization_servers:[issuer],
    bearer_methods_supported:["header"],
    scopes_supported:["openid","email","offline_access"],
  };
}
function authChallenge():string{
  return `Bearer resource_metadata="https://${FORGE_MCP_HOSTNAME}${FORGE_RESOURCE_METADATA_PATH}"`;
}
function nativeOwner(identity:Awaited<ReturnType<typeof authenticateProductRequest>>,env:Env):
  {ok:true;ownerUserId:string}|{ok:false;error:string;status:number}{
  if(!identity.ok)return identity;
  if(identity.role!=="authenticated"||!isCanonicalUuid(identity.subjectId))
    return {ok:false,error:"forge_native_identity_invalid",status:403};
  // Legacy normal account sessions stay valid during the cutover. OAuth sessions
  // are accepted only when signed for the one public Forge desktop client. This
  // never widens authorizeProductOwnerIdentity or any /v3/owner/* endpoint.
  if(identity.clientId!==null){
    const pinned=(env.FORGE_NATIVE_OAUTH_CLIENT_ID??"").trim().toLowerCase();
    if(!isCanonicalUuid(pinned)||!isCanonicalUuid(identity.clientId)
      ||identity.clientId.toLowerCase()!==pinned)
      return {ok:false,error:"forge_native_oauth_client_required",status:403};
  }
  return {ok:true,ownerUserId:identity.subjectId};
}
function toolFromCatalog(resolution:ForgeInstanceResolution,name:string):ForgeTool|null{
  if(!resolution.ok||!validForgeCatalog(resolution.catalog))return null;
  return resolution.catalog.find(tool=>tool.name===name)??null;
}
function accessMode(tool:ForgeTool):"read"|"write"{
  return tool.annotations?.readOnlyHint===true?"read":"write";
}
function shallowSchemaAllows(schema:Json,value:unknown):boolean{
  if(!isRecord(value)||schema.type!=="object"||!isRecord(schema.properties))return false;
  const props=schema.properties;
  const required=Array.isArray(schema.required)?schema.required:[];
  if(required.some(k=>typeof k!=="string"||!Object.hasOwn(value,k)))return false;
  if(schema.additionalProperties===false&&Object.keys(value).some(k=>!Object.hasOwn(props,k)))return false;
  for(const [key,raw] of Object.entries(value)){
    const rule=props[key];
    if(!isRecord(rule))continue;
    if(rule.type==="string"){
      if(typeof raw!=="string")return false;
      if(typeof rule.minLength==="number"&&raw.length<rule.minLength)return false;
      if(typeof rule.maxLength==="number"&&raw.length>rule.maxLength)return false;
      if(typeof rule.pattern==="string"){
        try{if(!new RegExp(rule.pattern).test(raw))return false;}catch{return false;}
      }
      if(Array.isArray(rule.enum)&&!rule.enum.includes(raw))return false;
    }else if(rule.type==="integer"){
      if(!Number.isSafeInteger(raw))return false;
      if(typeof rule.minimum==="number"&&Number(raw)<rule.minimum)return false;
      if(typeof rule.maximum==="number"&&Number(raw)>rule.maximum)return false;
    }else if(rule.type==="boolean"){
      if(typeof raw!=="boolean")return false;
    }else if(rule.type==="array"){
      if(!Array.isArray(raw))return false;
      if(typeof rule.minItems==="number"&&raw.length<rule.minItems)return false;
      if(typeof rule.maxItems==="number"&&raw.length>rule.maxItems)return false;
    }else if(rule.type==="object"){
      if(!isRecord(raw))return false;
    }
  }
  return true;
}
function terminalStatus(receipt:ForgeActionReceipt):boolean{
  return receipt.ok===true&&typeof receipt.status==="string"&&TERMINAL.has(receipt.status);
}
function completedToolResult(receipt:ForgeActionReceipt):Json{
  if(receipt.status==="succeeded"){
    if(isRecord(receipt.result)&&Array.isArray(receipt.result.content))return receipt.result;
    return toolResult(receipt.result??{ok:true,request_id:receipt.request_id});
  }
  return toolResult({
    ok:false,request_id:receipt.request_id,status:receipt.status,
    error:receipt.error_code??"forge_action_failed",
  },true);
}

type Dependencies=Readonly<{
  authenticateMcp?:typeof authenticateProductMcpClientRequest;
  authenticateOwner?:typeof authenticateProductRequest;
  register?:typeof registerForgeInstance;
  presence?:typeof updateForgePresence;
  resolve?:typeof resolveForgeMcpInstance;
  enqueue?:typeof enqueueForgeAction;
  claim?:typeof claimForgeAction;
  start?:typeof startForgeAction;
  renew?:typeof renewForgeAction;
  report?:typeof reportForgeAction;
  getAction?:typeof getForgeAction;
  now?:()=>number;
  randomUUID?:()=>string;
  sleep?:(ms:number)=>Promise<void>;
}>;

export function createForgeMcpGateway(env:Env,deps:Dependencies={}){
  const authenticateMcp=deps.authenticateMcp??authenticateProductMcpClientRequest;
  const authenticateOwner=deps.authenticateOwner??authenticateProductRequest;
  const register=deps.register??registerForgeInstance;
  const presence=deps.presence??updateForgePresence;
  const resolve=deps.resolve??resolveForgeMcpInstance;
  const enqueue=deps.enqueue??enqueueForgeAction;
  const claim=deps.claim??claimForgeAction;
  const start=deps.start??startForgeAction;
  const renew=deps.renew??renewForgeAction;
  const report=deps.report??reportForgeAction;
  const getAction=deps.getAction??getForgeAction;
  const now=deps.now??Date.now;
  const randomUUID=deps.randomUUID??(()=>crypto.randomUUID());
  const sleep=deps.sleep??(ms=>new Promise(r=>setTimeout(r,ms)));

  async function owner(request:Request){
    return nativeOwner(await authenticateOwner(request,env),env);
  }
  async function resolveFor(identity:VerifiedProductMcpClient){
    return resolve(env,{ownerUserId:identity.ownerUserId,clientId:identity.clientId});
  }
  async function waitFor(identity:VerifiedProductMcpClient,requestId:string,waitMs=DEFAULT_WAIT_MS){
    let receipt=await getAction(env,{ownerUserId:identity.ownerUserId,
      clientId:identity.clientId,requestId});
    const deadline=now()+waitMs;
    while(receipt.ok&&!terminalStatus(receipt)&&now()<deadline){
      await sleep(Math.min(250,Math.max(1,deadline-now())));
      receipt=await getAction(env,{ownerUserId:identity.ownerUserId,
        clientId:identity.clientId,requestId});
    }
    return receipt;
  }

  return async function handleForge(request:Request):Promise<Response>{
    const url=new URL(request.url);
    if(url.hostname!==FORGE_MCP_HOSTNAME)return json({ok:false,error:"not_found"},404);

    if(request.method==="GET"&&
      (url.pathname===FORGE_RESOURCE_METADATA_PATH||url.pathname===FORGE_RESOURCE_METADATA_PATH+"/mcp")){
      if(!productAuthConfigured(env))return json({ok:false,error:"product_auth_unconfigured"},503);
      return json(metadata(url.origin,String(env.PRODUCT_AUTH_ISSUER)));
    }
    if(request.method==="GET"&&url.pathname==="/health"){
      return json({ok:true,service:"ordax-forge-mcp",gateway:"ordax-platform",
        auth_configured:productAuthConfigured(env),postgres_configured:productPostgresConfigured(env),
        local_tunnel_required:false,model_relay:false});
    }
    if(request.method==="GET"&&url.pathname==="/ready"){
      const ready=productAuthConfigured(env)&&productPostgresConfigured(env);
      return json({ok:ready,service:"ordax-forge-mcp",
        auth_configured:productAuthConfigured(env),postgres_configured:productPostgresConfigured(env),
        local_tunnel_required:false},ready?200:503);
    }

    const nativePaths=new Set([
      FORGE_INSTANCE_REGISTER_PATH,FORGE_INSTANCE_PRESENCE_PATH,FORGE_INSTANCE_CLAIM_PATH,
      FORGE_INSTANCE_START_PATH,FORGE_INSTANCE_RENEW_PATH,FORGE_INSTANCE_REPORT_PATH,
    ]);
    if(nativePaths.has(url.pathname)){
      if(request.method!=="POST")return json({ok:false,error:"method_not_allowed"},405,{allow:"POST"});
      const identity=await owner(request.clone());
      if(!identity.ok)return json({ok:false,error:identity.error},identity.status);
      const body=await readBoundedJsonObject(request,MAX_BODY);
      if(!body)return json({ok:false,error:"forge_instance_request_invalid"},400);

      if(url.pathname===FORGE_INSTANCE_REGISTER_PATH){
        if(!exactKeys(body,["instance_id","display_name","app_version","catalog","catalog_digest"])
          ||!isCanonicalUuid(body.instance_id)||!boundedString(body.display_name,1,160)
          ||!boundedString(body.app_version,1,80)){
          return json({ok:false,error:"forge_instance_registration_invalid"},400);
        }
        const catalog=await validatedCatalog(body.catalog,body.catalog_digest);
        if(!catalog)return json({ok:false,error:"forge_catalog_invalid"},400);
        const result=await register(env,{ownerUserId:identity.ownerUserId,
          instanceId:String(body.instance_id).toLowerCase(),displayName:body.display_name,
          appVersion:body.app_version,catalog,catalogDigest:String(body.catalog_digest)});
        return json(result,result.ok===true?200:400);
      }

      if(url.pathname===FORGE_INSTANCE_PRESENCE_PATH){
        if(!exactKeys(body,["instance_id","online","app_version","catalog","catalog_digest"])
          ||!isCanonicalUuid(body.instance_id)||typeof body.online!=="boolean"
          ||!boundedString(body.app_version,1,80)){
          return json({ok:false,error:"forge_presence_invalid"},400);
        }
        const catalog=await validatedCatalog(body.catalog,body.catalog_digest);
        if(!catalog)return json({ok:false,error:"forge_catalog_invalid"},400);
        const result=await presence(env,{ownerUserId:identity.ownerUserId,
          instanceId:String(body.instance_id).toLowerCase(),online:body.online,
          appVersion:body.app_version,catalog,catalogDigest:String(body.catalog_digest)});
        return json(result,result.ok===true?200:404);
      }

      if(url.pathname===FORGE_INSTANCE_CLAIM_PATH){
        if(!exactKeys(body,["instance_id","agent_instance_id","boot_id","wait_ms"])
          ||!isCanonicalUuid(body.instance_id)||!isCanonicalUuid(body.agent_instance_id)
          ||!boundedString(body.boot_id,1,160)
          ||!Number.isInteger(body.wait_ms)||Number(body.wait_ms)<0||Number(body.wait_ms)>20000){
          return json({ok:false,error:"forge_claim_invalid"},400);
        }
        const deadline=now()+Number(body.wait_ms);
        let result=await claim(env,{ownerUserId:identity.ownerUserId,
          instanceId:String(body.instance_id).toLowerCase(),
          agentInstanceId:String(body.agent_instance_id).toLowerCase(),bootId:body.boot_id});
        while(result.ok===true&&result.job===null&&now()<deadline){
          await sleep(Math.min(500,Math.max(1,deadline-now())));
          result=await claim(env,{ownerUserId:identity.ownerUserId,
            instanceId:String(body.instance_id).toLowerCase(),
            agentInstanceId:String(body.agent_instance_id).toLowerCase(),bootId:body.boot_id});
        }
        return json(result,result.ok===true?200:403);
      }

      const common=["instance_id","request_id","attempt_id","lease_id","agent_instance_id","boot_id"];
      if(url.pathname===FORGE_INSTANCE_START_PATH||url.pathname===FORGE_INSTANCE_RENEW_PATH){
        if(!exactKeys(body,common)
          ||common.slice(0,5).some(key=>!isCanonicalUuid(body[key]))
          ||!boundedString(body.boot_id,1,160)){
          return json({ok:false,error:"forge_action_receipt_invalid"},400);
        }
        const input={ownerUserId:identity.ownerUserId,
          instanceId:String(body.instance_id).toLowerCase(),requestId:String(body.request_id).toLowerCase(),
          attemptId:String(body.attempt_id).toLowerCase(),leaseId:String(body.lease_id).toLowerCase(),
          agentInstanceId:String(body.agent_instance_id).toLowerCase(),bootId:body.boot_id};
        if(url.pathname===FORGE_INSTANCE_START_PATH){
          const started=await start(env,input);
          return json({ok:started},started?200:409);
        }
        const leaseExpiresAt=await renew(env,input);
        return json({ok:leaseExpiresAt!==null,lease_expires_at:leaseExpiresAt},leaseExpiresAt?200:409);
      }

      if(url.pathname===FORGE_INSTANCE_REPORT_PATH){
        const keys=[...common,"succeeded","result","error_code"];
        if(!exactKeys(body,keys)||common.slice(0,5).some(key=>!isCanonicalUuid(body[key]))
          ||!boundedString(body.boot_id,1,160)||typeof body.succeeded!=="boolean"
          ||!(body.error_code===null||boundedString(body.error_code,1,120))){
          return json({ok:false,error:"forge_action_receipt_invalid"},400);
        }
        if(Buffer.byteLength(JSON.stringify(body.result??null))>MAX_RESULT)
          return json({ok:false,error:"forge_action_result_too_large"},413);
        const result=await report(env,{ownerUserId:identity.ownerUserId,
          instanceId:String(body.instance_id).toLowerCase(),requestId:String(body.request_id).toLowerCase(),
          attemptId:String(body.attempt_id).toLowerCase(),leaseId:String(body.lease_id).toLowerCase(),
          agentInstanceId:String(body.agent_instance_id).toLowerCase(),bootId:body.boot_id,
          succeeded:body.succeeded,result:body.result,errorCode:body.error_code as string|null});
        return json(result,result.ok===true?200:409);
      }
    }

    if(url.pathname!=="/mcp")return json({ok:false,error:"not_found"},404);

    const identity=await authenticateMcp(request.clone(),env);
    if(!identity.ok){
      return json({ok:false,error:identity.error},identity.status,{
        "WWW-Authenticate":authChallenge(),
      });
    }
    if(request.method==="GET")return json({ok:false,error:"method_not_allowed"},405,{allow:"POST"});
    if(request.method!=="POST")return json({ok:false,error:"method_not_allowed"},405,{allow:"POST"});

    const message=await readBoundedJsonObject(request,MAX_BODY);
    if(!message||message.jsonrpc!=="2.0"||typeof message.method!=="string")
      return rpcError(null,-32600,"Invalid request",400);
    const id=Object.hasOwn(message,"id")?message.id:null;
    if(message.method==="notifications/initialized")
      return new Response(null,{status:202,headers:{"cache-control":"no-store"}});
    if(message.method==="ping")return rpcResult(id,{});
    if(message.method==="initialize"){
      return rpcResult(id,{
        protocolVersion:"2025-11-25",
        capabilities:{tools:{listChanged:true}},
        serverInfo:{name:"ordax-forge",title:"OrdaX Forge",version:"1"},
        instructions:"Forge MCP controls the user's connected Forge instance. Platform receipts are authoritative for transport; Forge remains authoritative for project, Task, Run, memory and workspace semantics.",
      });
    }

    const resolution=await resolveFor(identity);
    if(message.method==="tools/list"){
      const tools=[CONNECTION_TOOL,ACTION_STATUS_TOOL,
        ...(resolution.ok&&validForgeCatalog(resolution.catalog)?resolution.catalog:[])];
      return rpcResult(id,{tools});
    }
    if(message.method!=="tools/call")return rpcError(id,-32601,"Method not found");
    if(!isRecord(message.params)||typeof message.params.name!=="string")
      return rpcError(id,-32602,"Invalid tool call");
    const name=message.params.name;
    const args=message.params.arguments??{};
    if(!isRecord(args))return rpcError(id,-32602,"Invalid tool arguments");

    if(name===CONNECTION_TOOL.name){
      return rpcResult(id,toolResult({
        ok:resolution.ok,
        ...(resolution.ok?{
          instance_id:resolution.instance_id,display_name:resolution.display_name,
          app_version:resolution.app_version,online:resolution.online,
          last_seen_at:resolution.last_seen_at,catalog_digest:resolution.catalog_digest,
        }:{error:resolution.error,candidate_count:resolution.candidate_count??0}),
      },!resolution.ok));
    }
    if(name===ACTION_STATUS_TOOL.name){
      if(Object.keys(args).length!==1||!isCanonicalUuid(args.request_id))
        return rpcError(id,-32602,"Invalid request_id");
      const receipt=await getAction(env,{ownerUserId:identity.ownerUserId,
        clientId:identity.clientId,requestId:String(args.request_id).toLowerCase()});
      return rpcResult(id,toolResult(receipt,receipt.ok!==true));
    }

    if(!resolution.ok||!isCanonicalUuid(resolution.instance_id)){
      return rpcResult(id,toolResult({ok:false,error:resolution.error??"forge_instance_unavailable"},true));
    }
    const tool=toolFromCatalog(resolution,name);
    if(!tool)return rpcError(id,-32602,"Unknown Forge tool");
    if(!shallowSchemaAllows(tool.inputSchema,args))
      return rpcError(id,-32602,"Invalid Forge tool arguments");

    const mode=accessMode(tool);
    const digest=await verifiedMcpRetryDigest(
      {session:{client_id:identity.clientId}},id as string|number,message.params,
    );
    if(mode==="write"&&digest===null)
      return rpcResult(id,toolResult({ok:false,error:"forge_mcp_retry_correlation_required"},true));
    const opId=mode==="write"?digest!:randomUUID().toLowerCase();
    if(mode==="read"&&!isCanonicalUuid(opId))
      return rpcResult(id,toolResult({ok:false,error:"forge_gateway_unavailable"},true));

    const queued=await enqueue(env,{
      ownerUserId:identity.ownerUserId,clientId:identity.clientId,
      instanceId:resolution.instance_id.toLowerCase(),toolName:name,accessMode:mode,
      arguments:args,idempotencyKey:`forge:${mode}:${opId}`,
      expiresAt:new Date(now()+ACTION_TTL_MS).toISOString(),
    });
    if(!queued.ok||!isCanonicalUuid(queued.request_id))
      return rpcResult(id,toolResult({ok:false,error:queued.error??"forge_action_unavailable"},true));

    const receipt=await waitFor(identity,queued.request_id,DEFAULT_WAIT_MS);
    if(terminalStatus(receipt))return rpcResult(id,completedToolResult(receipt));
    return rpcResult(id,toolResult({
      ok:true,pending:true,request_id:queued.request_id,effect_id:queued.effect_id,
      status:receipt.status??queued.status??"queued",
      message:"Forge accepted the action. Use forge_action_status with this request_id; do not resubmit an uncertain write.",
    }));
  };
}
