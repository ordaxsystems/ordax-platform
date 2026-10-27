import test from "node:test";
import assert from "node:assert/strict";
import {
  handleProductOwnerGrantAdmin, PRODUCT_OWNER_CENTRAL_SESSION_TARGETS_PATH,
} from "../cloudflare/src/product_owner_grant_admin.ts";
import {env, owner, client, token, withIssuer} from "./product_mcp_test_fixtures.mts";

const target="22222222-2222-4222-8222-222222222222";
function query(clientId=client,search="") {
  return "https://mcp.ordax.com.br"+PRODUCT_OWNER_CENTRAL_SESSION_TARGETS_PATH+
    "?client_id="+clientId+search;
}
function request(url:string,jwt?:string,method="GET") {
  return new Request(url,{method,headers:jwt?{authorization:"Bearer "+jwt}:{}});
}

test("Owner target inspection stays default-OFF and never reaches the SQL port",async()=>{
  await withIssuer(async()=>{
    let touched=0;
    const reply=await handleProductOwnerGrantAdmin(request(query(),await token()),env,{
      inspectCentralTargets:async()=>{touched++;throw Error("unreachable");},
    });
    assert.equal(reply.status,404);
    assert.equal(touched,0);
  });
});

test("only a signed Owner can inspect an exact consented client; model device cannot choose target",async()=>{
  await withIssuer(async()=>{
    const active={...env,CENTRAL_OWNER_TARGET_PREFLIGHT_ENABLED:"enabled"};
    let calls=0;
    const inspect=async (_env:unknown,input:{ownerUserId:string;clientId:string})=>{
      calls++;
      assert.deepEqual(input,{ownerUserId:owner,clientId:client});
      assert.equal("deviceId" in input,false);
      return {ok:true,state:"owner_selection_required",eligible_device_count:2,
        targets:[{device_id:target},{device_id:"33333333-3333-4333-8333-333333333333"}],
        attested:false,dispatch_authorized:false,owner_choice_performed:false};
    };
    const absent=await handleProductOwnerGrantAdmin(request(query()),active,{inspectCentralTargets:inspect});
    assert.equal(absent.status,401);
    const jwt=await token();
    for(const suffix of ["&device_id="+target,"&client_id="+client,"&owner_user_id="+owner]) {
      const denied=await handleProductOwnerGrantAdmin(request(query(client,suffix),jwt),active,{inspectCentralTargets:inspect});
      assert.equal(denied.status,400);
    }
    const bad=await handleProductOwnerGrantAdmin(request(query("bad"),jwt),active,{inspectCentralTargets:inspect});
    assert.equal(bad.status,400);
    const write=await handleProductOwnerGrantAdmin(request(query(),jwt,"POST"),active,{inspectCentralTargets:inspect});
    assert.equal(write.status,405);
    assert.equal(calls,0);
    const good=await handleProductOwnerGrantAdmin(request(query(),jwt),active,{inspectCentralTargets:inspect});
    assert.equal(good.status,200);
    assert.equal(calls,1);
    assert.equal((await good.json()).dispatch_authorized,false);
  });
});
test("an unconsented client error cannot mint authority or dispatch",async()=>{
  await withIssuer(async()=>{
    const r=await handleProductOwnerGrantAdmin(request(query(),await token()),
      {...env,CENTRAL_OWNER_TARGET_PREFLIGHT_ENABLED:"enabled"},{
      inspectCentralTargets:async()=>({ok:false,error:"owner_central_client_not_consented"}),
    });
    assert.equal(r.status,403);
    assert.deepEqual(await r.json(),{ok:false,error:"owner_central_client_not_consented"});
  });
});
