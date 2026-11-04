import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";
import { handleProductOwnerGrantAdmin } from "../cloudflare/src/product_owner_grant_admin.ts";
import { isProductTrustedClientPath } from "../cloudflare/src/product_mcp_entry.ts";
import { env, token, withIssuer } from "./product_mcp_test_fixtures.mts";

const here = path.dirname(fileURLToPath(import.meta.url));
const endpoint = "https://mcp.ordax.com.br/v3/owner/devices";
const device = "11111111-1111-4111-8111-111111111111";
const valid = {
  ok: true, schema: "ordax.owner-mcp-devices/1", count: 1,
  devices: [{device_id:device,name:"DESKTOP-TEST",kind:"desktop",
    channel:"development",state:"active",online:true,
    runtime_ready:true,last_seen_at:"2026-11-03T18:00:00Z"}],
};
const auth = (value:string, method="GET", url=endpoint) =>
  new Request(url,{method,headers:{authorization:"Bearer "+value}});

test("MCP Owner inventory is routed through the canonical trusted ingress", () => {
  assert.equal(isProductTrustedClientPath("/v3/owner/devices"),true);
  assert.equal(isProductTrustedClientPath("/v3/owner/devices/other"),false);
  const src = readFileSync(path.resolve(here,"../cloudflare/src/product_mcp_entry.ts"),"utf8");
  assert.match(src,/url\.pathname === PRODUCT_OWNER_MCP_DEVICES_PATH/);
});

test("Owner inventory rejects unauthenticated and delegated clients before PostgreSQL", async () => {
  let called=0;
  const deps={listDevices:async () => {called++;return valid;}} as any;
  const untrusted=await handleProductOwnerGrantAdmin(new Request(endpoint),env,deps);
  assert.equal(untrusted.status,401);
  await withIssuer(async () => {
    const signedDelegated=await token();
    const response=await handleProductOwnerGrantAdmin(auth(signedDelegated),{
      ...env, PRODUCT_OWNER_OAUTH_CLIENT_ID:"202fd3e1-b058-4531-8750-82c57e4b6ca0",
    } as any,deps);
    assert.equal(response.status,403);
    assert.deepEqual(await response.json(),{ok:false,error:"owner_primary_session_required"});
  });
  assert.equal(called,0);
});

test("A signed primary Owner reads bounded device status, never caller-supplied owner id", async () => {
  await withIssuer(async () => {
    const signed=await token({client_id:null});
    const ids:string[]=[];
    const deps={listDevices:async (_:unknown,owner:string)=>{ids.push(owner);return valid;}} as any;
    const success=await handleProductOwnerGrantAdmin(auth(signed),env,deps);
    assert.equal(success.status,200);
    assert.deepEqual(await success.json(),valid);
    assert.deepEqual(ids,["11111111-1111-4111-8111-111111111111"]);
    for(const suffix of ["?owner_user_id="+device,"?device_id="+device,
                         "?limit=100","?foo=bar","?"]) {
      if(suffix==="?") continue;
      const result=await handleProductOwnerGrantAdmin(auth(signed,"GET",endpoint+suffix),env,deps);
      assert.equal(result.status,400,suffix);
      assert.deepEqual(await result.json(),{ok:false,error:"owner_devices_invalid"});
    }
    assert.equal(ids.length,1);
    for(const method of ["POST","DELETE","PUT"]) {
      const denied=await handleProductOwnerGrantAdmin(auth(signed,method),env,deps);
      assert.equal(denied.status,405,method);
    }
    assert.equal(ids.length,1);
  });
});

test("Malformed owner inventory fails closed rather than displaying another user's devices", async () => {
  await withIssuer(async () => {
    const signed=await token({client_id:null});
    const bad=[
      {...valid,count:2},
      {...valid,schema:"unknown"},
      {...valid,devices:[valid.devices[0],valid.devices[0]],count:2},
      {...valid,devices:[{...valid.devices[0],device_id:"not-a-device"}]},
      {...valid,devices:[{...valid.devices[0],online:"true"}]},
      {...valid,devices:[{...valid.devices[0],last_seen_at:"invalid"}]},
    ];
    for(const record of bad) {
      const response=await handleProductOwnerGrantAdmin(auth(signed),env,{
        listDevices:async()=>record,
      } as any);
      assert.equal(response.status,502);
      assert.deepEqual(await response.json(),{ok:false,error:"owner_devices_response_invalid"});
    }
  });
});

test("Owner inventory source uses only existing identity and presence, no shadow authority", () => {
  const filename=path.resolve(here,"../supabase/migrations/20261104005500_owner_mcp_device_inventory_v1.sql");
  const sql=readFileSync(filename,"utf8").toLowerCase();
  assert.match(sql,/create function public\.ordax_owner_mcp_devices_v1/);
  assert.match(sql,/d\.owner_user_id=p_owner_user_id/g);
  assert.match(sql,/private\.ordax_trusted_actor_auth_eligible_v1/);
  assert.match(sql,/public\.ordax_device_presence/);
  assert.match(sql,/to ordax_edge_executor/);
  for(const role of ["public","anon","authenticated","service_role"])
    assert.match(sql,new RegExp("revoke all on function[\\s\\S]*?from[\\s\\S]*?"+role));
  assert.doesNotMatch(sql,/create table|alter table|grant execute[^;]+to service_role/);
});

test("DEV retirement refuses live/unknown devices and unauthorized calls, then retires only the exact Owner device", async () => {
  const retireUrl=endpoint+"/"+device+"?confirm="+device;
  assert.equal(isProductTrustedClientPath(endpoint.replace("https://mcp.ordax.com.br","")+"/"+device),true);
  assert.equal(isProductTrustedClientPath("/v3/owner/devices/other"),false);
  let calls=0;
  const deps={retireDevice:async (_env:unknown,ownerId:string,deviceId:string)=>{
    calls++;
    assert.equal(ownerId,"11111111-1111-4111-8111-111111111111");
    assert.equal(deviceId,device);
    return {ok:true,retired:true,device_id:device,already_retired:false,grants_revoked:0};
  }} as any;
  const noAuth=await handleProductOwnerGrantAdmin(new Request(retireUrl,{method:"DELETE"}),{
    ...env,OWNER_DEVICE_RETIRE_ENABLED:"enabled",
  } as any,deps);
  assert.equal(noAuth.status,401);
  assert.equal(calls,0);
  await withIssuer(async()=>{
    const signed=await token({client_id:null});
    const signedDelegated=await token();
    const cfg={...env,OWNER_DEVICE_RETIRE_ENABLED:"enabled"} as any;
    const req=(url:string,method="DELETE",bearer=signed)=>new Request(url,{
      method,headers:{authorization:"Bearer "+bearer},
    });
    const noRollout=await handleProductOwnerGrantAdmin(req(retireUrl),env,deps);
    assert.equal(noRollout.status,404);
    const delegated=await handleProductOwnerGrantAdmin(req(retireUrl,"DELETE",signedDelegated),cfg,deps);
    assert.equal(delegated.status,403);
    const noMutationGet=await handleProductOwnerGrantAdmin(req(retireUrl,"GET"),cfg,deps);
    assert.equal(noMutationGet.status,405);
    for(const invalid of [
      endpoint+"/"+device,
      endpoint+"/"+device+"?confirm=retire",
      endpoint+"/"+device+"?confirm="+device+"&extra=1",
      endpoint+"/"+device+"?confirm="+device+"&confirm="+device,
      endpoint+"/other?confirm=other",
    ]){
      const rejected=await handleProductOwnerGrantAdmin(req(invalid),cfg,deps);
      assert.equal(rejected.status,400,invalid);
    }
    assert.equal(calls,0);
    const success=await handleProductOwnerGrantAdmin(req(retireUrl),cfg,deps);
    assert.equal(success.status,200);
    assert.equal((await success.json()).device_id,device);
    assert.equal(calls,1);
  });
});

test("DEV retirement SQL is offline-only, owner-scoped, credential-revoking and never deletes user files",()=>{
  const sql=readFileSync(path.resolve(here,
    "../supabase/candidates/20261104040000_owner_product_device_retirement_v1.sql"),"utf8");
  assert.match(sql,/private\.ordax_trusted_actor_auth_eligible_v1/);
  assert.match(sql,/d\.state='active'|v_device\.state<>'active'/);
  assert.match(sql,/v_device\.channel<>'development'/);
  assert.match(sql,/private\.ordax_product_presence_online_v1/);
  assert.match(sql,/owner_device_still_online/);
  assert.match(sql,/owner_device_active_actions/);
  assert.match(sql,/update private\.ordax_product_device_credentials/);
  assert.match(sql,/update public\.ordax_remote_capability_grants/);
  assert.match(sql,/set state='revoked'/);
  assert.match(sql,/d\.owner_user_id=p_owner_user_id and d\.state='active'/);
  assert.match(sql,/to ordax_edge_executor/);
  assert.match(sql,/from public,anon,authenticated,service_role/);
  assert.doesNotMatch(sql,/delete from public\.ordax_product_devices/i);
});
