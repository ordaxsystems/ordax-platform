import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(new URL("../cloudflare/package.json", import.meta.url));
const { PGlite } = require("@electric-sql/pglite");
const migration=fs.readFileSync(new URL(
  "../supabase/migrations/20261104005500_owner_mcp_device_inventory_v1.sql",
  import.meta.url,
),"utf8");

test("Owner inventory SQL is scoped, fresh, bounded, read-only and gated by edge role",async()=>{
  const db=new PGlite();
  const owner=randomUUID(), other=randomUUID();
  const first=randomUUID(), second=randomUUID(), foreign=randomUUID();
  try {
    await db.exec(`
      create schema private;
      create role anon;
      create role authenticated;
      create role service_role;
      create role ordax_edge_executor;
      create table public.owner_eligibility(
        owner_user_id uuid primary key, eligible boolean not null
      );
      create table public.ordax_product_devices(
        device_id uuid primary key, owner_user_id uuid not null,
        display_name text not null, device_kind text not null,
        channel text not null, state text not null
      );
      create table public.ordax_device_presence(
        device_id uuid primary key, online boolean,
        last_seen_at timestamptz, agent_version text, capability_digest text
      );
      create function private.ordax_trusted_actor_auth_eligible_v1(
        p_owner_user_id uuid
      ) returns boolean language sql stable security definer set search_path=''
      as $f$
        select coalesce((select x.eligible from public.owner_eligibility x
          where x.owner_user_id=p_owner_user_id),false);
      $f$;
      create function private.ordax_product_presence_online_v1(
        p_online boolean,p_seen timestamptz,p_now timestamptz
      ) returns boolean language sql stable set search_path=''
      as $f$
        select coalesce(p_online,false) and p_seen is not null
          and p_seen >= p_now - interval '10 minutes';
      $f$;
    `);
    await db.exec(migration);
    const permitted=await db.query(`
      select
        has_function_privilege('anon','public.ordax_owner_mcp_devices_v1(uuid)','EXECUTE') as anon,
        has_function_privilege('authenticated','public.ordax_owner_mcp_devices_v1(uuid)','EXECUTE') as user_role,
        has_function_privilege('service_role','public.ordax_owner_mcp_devices_v1(uuid)','EXECUTE') as service,
        has_function_privilege('ordax_edge_executor','public.ordax_owner_mcp_devices_v1(uuid)','EXECUTE') as edge
    `);
    assert.deepEqual(permitted.rows[0],{anon:false,user_role:false,service:false,edge:true});
    await db.query("insert into public.owner_eligibility values($1,true),($2,true)",[owner,other]);
    await db.query(`insert into public.ordax_product_devices values
      ($1,$2,'Desktop A','desktop','development','active'),
      ($3,$2,'Notebook B','laptop','development','active'),
      ($4,$5,'Outro usuário','desktop','stable','active')
    `,[first,owner,second,foreign,other]);
    const digest="a".repeat(64);
    await db.query(`insert into public.ordax_device_presence values
      ($1,true,now(),'1.31.0',$2),
      ($3,true,now()-interval '2 hours','1.30.0',$2),
      ($4,true,now(),'1.31.0',$2)
    `,[first,digest,second,foreign]);
    const inventory=async(id:string)=>(await db.query(
      "select public.ordax_owner_mcp_devices_v1($1) as value",[id],
    )).rows[0].value;
    const result=await inventory(owner);
    assert.equal(result.ok,true);
    assert.equal(result.schema,"ordax.owner-mcp-devices/1");
    assert.equal(result.count,2);
    assert.deepEqual(result.devices.map((v:any)=>v.device_id).sort(),[first,second].sort());
    assert.equal(result.devices[0].name,"Desktop A");
    assert.equal(result.devices[0].online,true);
    assert.equal(result.devices[0].runtime_ready,true);
    assert.equal(result.devices[1].online,false);
    assert.equal(result.devices[1].runtime_ready,false);
    assert.equal(Object.hasOwn(result.devices[0],"grant_group_id"),false);
    assert.equal((await inventory(other)).count,1);
    await db.query("update public.owner_eligibility set eligible=false where owner_user_id=$1",[owner]);
    assert.equal((await inventory(owner)).error,"owner_auth_ineligible");
    await db.query("update public.owner_eligibility set eligible=true where owner_user_id=$1",[owner]);
    // The guard rejects pathological accounts instead of doing a giant export.
    await db.query(`insert into public.ordax_product_devices
      select gen_random_uuid(),$1,'Extra','other','development','active'
      from generate_series(1,199)`,[owner]);
    assert.equal((await inventory(owner)).error,"owner_devices_limit_exceeded");
  } finally {await db.close();}
});
