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
    const reply=await handleProductOwnerGrantAdmin(request(query(),await token({client_id:null})),env,{
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
      return {ok:true,client_id:client,state:"owner_selection_required",eligible_device_count:2,
        targets:[
          {device_id:target,reported_online:true,runtime_ready:true,token_sha256:"private"},
          {device_id:"33333333-3333-4333-8333-333333333333",
            reported_online:false,runtime_ready:true},
        ],
        attested:false,dispatch_authorized:false,owner_choice_performed:false,
        private_owner_identity:owner};
    };
    const absent=await handleProductOwnerGrantAdmin(request(query()),active,{inspectCentralTargets:inspect});
    assert.equal(absent.status,401);
    const jwt=await token({client_id:null});
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
    assert.deepEqual(await good.json(),{
      ok:true,client_id:client,state:"owner_selection_required",eligible_device_count:2,
      targets:[
        {device_id:target,reported_online:true,runtime_ready:true},
        {device_id:"33333333-3333-4333-8333-333333333333",
          reported_online:false,runtime_ready:true},
      ],
      attested:false,dispatch_authorized:false,owner_choice_performed:false,
    });
  });
});
test("Owner target projection rejects wrong client and false readiness, no leaked SQL fields",async()=>{
  await withIssuer(async()=>{
    const jwt=await token({client_id:null});
    const active={...env,CENTRAL_OWNER_TARGET_PREFLIGHT_ENABLED:"enabled"};
    const normal={
      ok:true,client_id:client,state:"single_granted_target",
      eligible_device_count:1,targets:[{device_id:target,reported_online:true,runtime_ready:true}],
      attested:false,dispatch_authorized:false,owner_choice_performed:false,
    };
    for(const raw of [
      {...normal,client_id:"44444444-4444-4444-8444-444444444444"},
      {...normal,owner_choice_performed:true},
      {...normal,eligible_device_count:2},
      {...normal,state:"owner_selection_required"},
      {...normal,targets:[{device_id:target,reported_online:true,runtime_ready:"true"}]},
      {...normal,targets:[{device_id:target,reported_online:true,runtime_ready:true},
        {device_id:target,reported_online:true,runtime_ready:true}],eligible_device_count:2,
        state:"owner_selection_required"},
    ]){
      const res=await handleProductOwnerGrantAdmin(request(query(),jwt),active,{
        inspectCentralTargets:async()=>raw,
      });
      assert.equal(res.status,502);
      assert.deepEqual(await res.json(),{
        ok:false,error:"owner_central_targets_response_invalid",
      });
    }
    const sqlError=await handleProductOwnerGrantAdmin(request(query(),jwt),active,{
      inspectCentralTargets:async()=>({ok:false,error:"internal_sql_token",private:"value"}),
    });
    assert.equal(sqlError.status,503);
    assert.deepEqual(await sqlError.json(),{
      ok:false,error:"owner_central_response_unavailable",
    });
  });
});

test("an unconsented client error cannot mint authority or dispatch",async()=>{
  await withIssuer(async()=>{
    const r=await handleProductOwnerGrantAdmin(request(query(),await token({client_id:null})),
      {...env,CENTRAL_OWNER_TARGET_PREFLIGHT_ENABLED:"enabled"},{
      inspectCentralTargets:async()=>({ok:false,error:"owner_central_client_not_consented"}),
    });
    assert.equal(r.status,403);
    assert.deepEqual(await r.json(),{ok:false,error:"owner_central_client_not_consented"});
  });
});
