import assert from "node:assert/strict";
import test from "node:test";
import {createHash} from "node:crypto";
import {
  createForgeMcpGateway,FORGE_MCP_HOSTNAME,FORGE_INSTANCE_REGISTER_PATH,
  validForgeCatalog,
} from "../cloudflare/src/forge_mcp_gateway.ts";

const OWNER="11111111-1111-4111-8111-111111111111";
const CLIENT="22222222-2222-4222-8222-222222222222";
const INSTANCE="33333333-3333-4333-8333-333333333333";
const REQUEST="44444444-4444-4444-8444-444444444444";
const EFFECT="55555555-5555-4555-8555-555555555555";
const CATALOG=[{
  name:"forge_projects_list",
  description:"List accessible Forge projects.",
  inputSchema:{type:"object",additionalProperties:false,properties:{},required:[]},
  annotations:{readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false},
}];

const FORGE_NATIVE_CLIENT="6a94ae80-a59c-4f48-a32c-2e15da34374f";
const env:any={
  PRODUCT_AUTH_ISSUER:"https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1",
  PRODUCT_AUTH_AUDIENCE:"authenticated",
  PRODUCT_AUTH_JWKS_URL:"https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1/.well-known/jwks.json",
  FORGE_NATIVE_OAUTH_CLIENT_ID:FORGE_NATIVE_CLIENT,
};

function request(body:unknown,path="/mcp"){
  return new Request("https://"+FORGE_MCP_HOSTNAME+path,{
    method:"POST",headers:{authorization:"Bearer test","content-type":"application/json"},
    body:JSON.stringify(body),
  });
}
function mcpIdentity(){
  return Promise.resolve({ok:true as const,ownerUserId:OWNER,clientKind:"product-mcp" as const,
    clientId:CLIENT,expiresAt:4102444800});
}
function ownerIdentity(clientId:string|null=null){
  return Promise.resolve({ok:true as const,subjectId:OWNER,
    issuer:env.PRODUCT_AUTH_ISSUER,audience:"authenticated",expiresAt:4102444800,
    clientId,role:"authenticated"});
}
function resolution(){
  return {ok:true,instance_id:INSTANCE,display_name:"Forge local",app_version:"0.2.0",
    catalog:CATALOG,catalog_digest:"a".repeat(64),online:true,last_seen_at:new Date().toISOString()};
}

test("Forge catalog validator accepts the App-owned MCP projection and rejects direct GPT send",()=>{
  assert.equal(validForgeCatalog(CATALOG),true);
  assert.equal(validForgeCatalog([...CATALOG,{...CATALOG[0],name:"forge_work_send"}]),false);
});

test("Forge MCP tools/list projects the instance catalog without duplicating it in Platform",async()=>{
  const gateway=createForgeMcpGateway(env,{
    authenticateMcp:mcpIdentity as any,
    resolve:async()=>resolution(),
  });
  const response=await gateway(request({
    jsonrpc:"2.0",id:1,method:"tools/list",params:{},
  }));
  assert.equal(response.status,200);
  const body:any=await response.json();
  const names=body.result.tools.map((x:any)=>x.name);
  assert.deepEqual(names,["forge_connection_status","forge_action_status","forge_projects_list"]);
});

test("Forge MCP read call uses a fresh Platform receipt and returns the Forge result",async()=>{
  const enqueued:any[]=[];
  const gateway=createForgeMcpGateway(env,{
    authenticateMcp:mcpIdentity as any,
    resolve:async()=>resolution(),
    randomUUID:()=> "66666666-6666-4666-8666-666666666666",
    enqueue:async(_env,input:any)=>{
      enqueued.push(input);
      return {ok:true,replayed:false,request_id:REQUEST,effect_id:EFFECT,status:"queued"};
    },
    getAction:async()=>({ok:true,request_id:REQUEST,effect_id:EFFECT,status:"succeeded",
      result:{projects:[]},error_code:null}),
  });
  const response=await gateway(request({
    jsonrpc:"2.0",id:7,method:"tools/call",
    params:{name:"forge_projects_list",arguments:{}},
  }));
  const body:any=await response.json();
  assert.equal(body.result.isError,undefined);
  assert.deepEqual(body.result.structuredContent,{projects:[]});
  assert.equal(enqueued.length,1);
  assert.equal(enqueued[0].instanceId,INSTANCE);
  assert.equal(enqueued[0].accessMode,"read");
  assert.equal(enqueued[0].idempotencyKey,"forge:read:66666666-6666-4666-8666-666666666666");
});

test("Forge MCP stays installable when no Forge instance is registered",async()=>{
  const gateway=createForgeMcpGateway(env,{
    authenticateMcp:mcpIdentity as any,
    resolve:async()=>({ok:false,error:"forge_instance_unavailable"}),
  });
  const response=await gateway(request({jsonrpc:"2.0",id:1,method:"tools/list",params:{}}));
  const body:any=await response.json();
  assert.deepEqual(body.result.tools.map((x:any)=>x.name),
    ["forge_connection_status","forge_action_status"]);
});

test("Forge native registration accepts only a catalog whose digest matches exact canonical bytes",async()=>{
  const canonical=(value:any):any=>Array.isArray(value)?value.map(canonical):
    value&&typeof value==="object"?Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])])):value;
  const digest=createHash("sha256").update(JSON.stringify(canonical(CATALOG))).digest("hex");
  let registered:any=null;
  const gateway=createForgeMcpGateway(env,{
    authenticateOwner:(()=>ownerIdentity(FORGE_NATIVE_CLIENT)) as any,
    register:async(_env,input:any)=>{registered=input;return {ok:true,instance_id:INSTANCE};},
  });
  const response=await gateway(request({
    instance_id:INSTANCE,display_name:"Forge local",app_version:"0.2.0",
    catalog:CATALOG,catalog_digest:digest,
  },FORGE_INSTANCE_REGISTER_PATH));
  assert.equal(response.status,200);
  assert.equal(registered.ownerUserId,OWNER);
  assert.equal(registered.catalogDigest,digest);
});

test("Forge native OAuth scope rejects another signed OAuth client without widening Owner authority",async()=>{
  const canonical=(value:any):any=>Array.isArray(value)?value.map(canonical):
    value&&typeof value==="object"?Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])])):value;
  const digest=createHash("sha256").update(JSON.stringify(canonical(CATALOG))).digest("hex");
  let writes=0;
  const gateway=createForgeMcpGateway(env,{
    authenticateOwner:(()=>ownerIdentity(CLIENT)) as any,
    register:async()=>{writes++;return {ok:true,instance_id:INSTANCE};},
  });
  const response=await gateway(request({
    instance_id:INSTANCE,display_name:"Forge local",app_version:"0.2.0",
    catalog:CATALOG,catalog_digest:digest,
  },FORGE_INSTANCE_REGISTER_PATH));
  assert.equal(response.status,403);
  assert.deepEqual(await response.json(),{ok:false,error:"forge_native_oauth_client_required"});
  assert.equal(writes,0);
});

test("Forge native cutover keeps a normal account session compatible",async()=>{
  const canonical=(value:any):any=>Array.isArray(value)?value.map(canonical):
    value&&typeof value==="object"?Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])])):value;
  const digest=createHash("sha256").update(JSON.stringify(canonical(CATALOG))).digest("hex");
  const gateway=createForgeMcpGateway(env,{
    authenticateOwner:(()=>ownerIdentity()) as any,
    register:async()=>({ok:true,instance_id:INSTANCE}),
  });
  const response=await gateway(request({
    instance_id:INSTANCE,display_name:"Forge local",app_version:"0.2.0",
    catalog:CATALOG,catalog_digest:digest,
  },FORGE_INSTANCE_REGISTER_PATH));
  assert.equal(response.status,200);
});

test("Forge MCP unauthenticated requests advertise the shared Supabase OAuth resource",async()=>{
  const gateway=createForgeMcpGateway(env,{
    authenticateMcp:async()=>({ok:false as const,error:"product_auth_required",status:401}),
  });
  const response=await gateway(request({jsonrpc:"2.0",id:1,method:"initialize",params:{}}));
  assert.equal(response.status,401);
  assert.match(response.headers.get("www-authenticate")??"",/oauth-protected-resource/);
});
