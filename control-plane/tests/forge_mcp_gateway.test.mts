import assert from "node:assert/strict";
import test from "node:test";
import {createHash} from "node:crypto";
import {
  createForgeMcpGateway,FORGE_MCP_HOSTNAME,FORGE_INSTANCE_REGISTER_PATH,
  FORGE_INSTANCE_CLAIM_PATH,FORGE_INSTANCE_REPORT_PATH,validForgeCatalog,
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

test("Forge MCP initialize matches the ChatGPT-compatible OrdaX MCP protocol",async()=>{
  const gateway=createForgeMcpGateway(env,{
    authenticateMcp:mcpIdentity as any,
  });
  const response=await gateway(request({jsonrpc:"2.0",id:1,method:"initialize",params:{}}));
  assert.equal(response.status,200);
  const body:any=await response.json();
  assert.equal(body.result.protocolVersion,"2025-06-18");
  assert.deepEqual(body.result.capabilities,{tools:{listChanged:false}});
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

test("Forge native report rejects oversized UTF-8 results before writing a receipt",async()=>{
  let reports=0;
  const gateway=createForgeMcpGateway(env,{
    authenticateOwner:(()=>ownerIdentity(FORGE_NATIVE_CLIENT)) as any,
    report:async()=>{reports++;return {ok:true};},
  });
  const response=await gateway(request({
    instance_id:INSTANCE,request_id:REQUEST,
    attempt_id:"77777777-7777-4777-8777-777777777777",
    lease_id:"88888888-8888-4888-8888-888888888888",
    agent_instance_id:"99999999-9999-4999-8999-999999999999",
    boot_id:"forge-test",succeeded:true,
    result:{content:[{type:"text",text:"é".repeat(200_000)}]},error_code:null,
  },FORGE_INSTANCE_REPORT_PATH));
  assert.equal(response.status,413);
  assert.deepEqual(await response.json(),{ok:false,error:"forge_action_result_too_large"});
  assert.equal(reports,0);
});

test("Forge native routes require OAuth before any store write",async()=>{
  const canonical=(value:any):any=>Array.isArray(value)?value.map(canonical):
    value&&typeof value==="object"?Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])])):value;
  const digest=createHash("sha256").update(JSON.stringify(canonical(CATALOG))).digest("hex");
  let writes=0;
  const gateway=createForgeMcpGateway(env,{
    authenticateOwner:(()=>ownerIdentity()) as any,
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

test("Forge native client SSOT is enforced by the authenticated PostgreSQL RPC",async()=>{
  const canonical=(value:any):any=>Array.isArray(value)?value.map(canonical):
    value&&typeof value==="object"?Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])])):value;
  const digest=createHash("sha256").update(JSON.stringify(canonical(CATALOG))).digest("hex");
  let legacyWrites=0,remoteCalls=0;
  const gateway=createForgeMcpGateway({...env,
    FORGE_SUPABASE_PUBLISHABLE_KEY:"sb_publishable_test"},{
    authenticateOwner:(()=>ownerIdentity(CLIENT)) as any,
    register:async()=>{legacyWrites++;return {ok:true,instance_id:INSTANCE};},
    fetchImpl:(async(_url:any,init:any)=>{
      remoteCalls++;
      const sent=JSON.parse(String(init.body));
      assert.equal(sent.p_operation,"native_register");
      assert.equal(init.headers.authorization,"Bearer test");
      return Response.json({ok:false,error:"forge_native_oauth_client_required"});
    }) as any,
  });
  const response=await gateway(request({
    instance_id:INSTANCE,display_name:"Forge local",app_version:"0.2.0",
    catalog:CATALOG,catalog_digest:digest,
  },FORGE_INSTANCE_REGISTER_PATH));
  assert.equal(response.status,400);
  assert.deepEqual(await response.json(),{ok:false,error:"forge_native_oauth_client_required"});
  assert.equal(remoteCalls,1);
  assert.equal(legacyWrites,0);
});

test("Forge MCP tools/list uses Supabase HTTPS RPC instead of Hyperdrive when configured",async()=>{
  let legacyResolves=0,remoteCalls=0;
  const gateway=createForgeMcpGateway({...env,
    FORGE_SUPABASE_PUBLISHABLE_KEY:"sb_publishable_test"},{
    authenticateMcp:mcpIdentity as any,
    resolve:async()=>{legacyResolves++;return resolution();},
    fetchImpl:(async(_url:any,init:any)=>{
      remoteCalls++;
      const sent=JSON.parse(String(init.body));
      assert.equal(sent.p_operation,"mcp_resolve");
      assert.deepEqual(sent.p_payload,{});
      assert.equal(init.headers.authorization,"Bearer test");
      assert.equal(init.headers.apikey,"sb_publishable_test");
      assert.equal(init.redirect,"manual");
      return Response.json(resolution());
    }) as any,
  });
  const response=await gateway(request({jsonrpc:"2.0",id:1,method:"tools/list",params:{}}));
  assert.equal(response.status,200);
  const body:any=await response.json();
  assert.deepEqual(body.result.tools.map((x:any)=>x.name),
    ["forge_connection_status","forge_action_status","forge_projects_list"]);
  assert.equal(remoteCalls,1);
  assert.equal(legacyResolves,0);
});

test("Forge Supabase transport exposes bounded fetch failure instead of opaque Worker 500",async()=>{
  const canonical=(value:any):any=>Array.isArray(value)?value.map(canonical):
    value&&typeof value==="object"?Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])])):value;
  const digest=createHash("sha256").update(JSON.stringify(canonical(CATALOG))).digest("hex");
  let legacyWrites=0;
  const gateway=createForgeMcpGateway({...env,
    FORGE_SUPABASE_PUBLISHABLE_KEY:"sb_publishable_test"},{
    authenticateOwner:(()=>ownerIdentity(FORGE_NATIVE_CLIENT)) as any,
    register:async()=>{legacyWrites++;return {ok:true,instance_id:INSTANCE};},
    fetchImpl:(async()=>{throw Error("network");}) as any,
  });
  const response=await gateway(request({
    instance_id:INSTANCE,display_name:"Forge local",app_version:"0.2.0",
    catalog:CATALOG,catalog_digest:digest,
  },FORGE_INSTANCE_REGISTER_PATH));
  assert.equal(response.status,400);
  assert.deepEqual(await response.json(),{ok:false,error:"forge_supabase_rpc_fetch_unavailable"});
  assert.equal(legacyWrites,0);
});

test("Forge Supabase transport blocks redirects without forwarding the bearer",async()=>{
  const canonical=(value:any):any=>Array.isArray(value)?value.map(canonical):
    value&&typeof value==="object"?Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])])):value;
  const digest=createHash("sha256").update(JSON.stringify(canonical(CATALOG))).digest("hex");
  let legacyWrites=0;
  const gateway=createForgeMcpGateway({...env,
    FORGE_SUPABASE_PUBLISHABLE_KEY:"sb_publishable_test"},{
    authenticateOwner:(()=>ownerIdentity(FORGE_NATIVE_CLIENT)) as any,
    register:async()=>{legacyWrites++;return {ok:true,instance_id:INSTANCE};},
    fetchImpl:(async(_url:any,init:any)=>{
      assert.equal(init.redirect,"manual");
      return new Response(null,{status:302,headers:{location:"https://example.invalid/"}});
    }) as any,
  });
  const response=await gateway(request({
    instance_id:INSTANCE,display_name:"Forge local",app_version:"0.2.0",
    catalog:CATALOG,catalog_digest:digest,
  },FORGE_INSTANCE_REGISTER_PATH));
  assert.equal(response.status,400);
  assert.deepEqual(await response.json(),{ok:false,error:"forge_supabase_rpc_redirect_forbidden"});
  assert.equal(legacyWrites,0);
});

test("Forge MCP unauthenticated requests advertise the shared Supabase OAuth resource",async()=>{
  const gateway=createForgeMcpGateway(env,{
    authenticateMcp:async()=>({ok:false as const,error:"product_auth_required",status:401}),
  });
  const response=await gateway(request({jsonrpc:"2.0",id:1,method:"initialize",params:{}}));
  assert.equal(response.status,401);
  assert.match(response.headers.get("www-authenticate")??"",/oauth-protected-resource/);
});


test("Forge native claim caps Supabase RPC polling to six empty checks per 20-second wait",async()=>{
  let clock=0;
  const sleeps:number[]=[];
  const operations:string[]=[];
  const gateway=createForgeMcpGateway({...env,
    FORGE_SUPABASE_PUBLISHABLE_KEY:"sb_publishable_test"},{
    authenticateOwner:(()=>ownerIdentity(FORGE_NATIVE_CLIENT)) as any,
    now:()=>clock,
    sleep:async(ms:number)=>{sleeps.push(ms);clock+=ms;},
    fetchImpl:(async(_url:any,init:any)=>{
      operations.push(JSON.parse(String(init.body)).p_operation);
      return Response.json({ok:true,job:null});
    }) as any,
  });
  const response=await gateway(request({
    instance_id:INSTANCE,
    agent_instance_id:"99999999-9999-4999-8999-999999999999",
    boot_id:"forge-test",
    wait_ms:20000,
  },FORGE_INSTANCE_CLAIM_PATH));
  assert.equal(response.status,200);
  assert.deepEqual(await response.json(),{ok:true,job:null});
  assert.deepEqual(operations,Array(6).fill("native_claim"));
  assert.deepEqual(sleeps,[500,1000,2000,4000,8000,4500]);
  assert.equal(clock,20000);
});

test("Forge native claim stays immediate for work and never retries on failure",async()=>{
  for(const expected of [0,3,-1]){
    let clock=0,claims=0;
    const job={request_id:REQUEST};
    const gateway=createForgeMcpGateway(env,{
      authenticateOwner:(()=>ownerIdentity(FORGE_NATIVE_CLIENT)) as any,
      now:()=>clock,
      sleep:async(ms:number)=>{clock+=ms;},
      claim:async()=>{
        claims++;
        if(expected===-1)return {ok:false,error:"forge_native_claim_denied"};
        return {ok:true,job:expected>0&&claims===expected?job:null};
      },
    });
    const response=await gateway(request({
      instance_id:INSTANCE,
      agent_instance_id:"99999999-9999-4999-8999-999999999999",
      boot_id:"forge-test",wait_ms:expected===0?0:20000,
    },FORGE_INSTANCE_CLAIM_PATH));
    assert.equal(response.status,expected===-1?403:200);
    assert.equal(claims,expected>0?expected:1);
    if(expected===3){
      assert.deepEqual((await response.json() as any).job,job);
      assert.equal(clock,1500);
    }
    if(expected===0)assert.equal(clock,0);
    if(expected===-1)assert.equal(clock,0);
  }
});
