import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import { createRequire } from "node:module";
const {PGlite}=createRequire(new URL("../cloudflare/package.json",import.meta.url))("@electric-sql/pglite");
const migration=fs.readFileSync(new URL("../supabase/migrations/20261121071000_product_authenticated_lease_progress_v1.sql",import.meta.url),"utf8");
const id="11111111-1111-4111-8111-111111111111";
const token="a".repeat(64);
test("authenticated lease and progress preserve fencing and deny invalid or revoked credentials",async()=>{
  const db=new PGlite();
  try {
    await db.exec(`
      create role anon; create role authenticated; create role service_role; create role ordax_edge_executor;
      create table fixture (revoked boolean default false, fenced boolean default false, leases integer default 0, events integer default 0);
      insert into fixture default values;
      create function public.ordax_authenticate_product_device_v1(uuid,text) returns boolean language sql as $$ select not revoked and $1='11111111-1111-4111-8111-111111111111'::uuid and $2=repeat('a',64) from public.fixture $$;
      create function public.ordax_renew_product_action_lease_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,integer) returns timestamptz language plpgsql as $$
      begin update public.fixture set leases=leases+1 where not fenced and $6=1 and $9 between 30 and 300;
      if found then return '2026-11-21T12:00:00Z'::timestamptz; end if; return null; end $$;
      create function public.ordax_progress_product_action_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,text,text,smallint) returns boolean language plpgsql as $$
      begin update public.fixture set events=events+1 where not fenced and $6=1 and $11 between 0 and 100; return found; end $$;
    `);
    await db.exec(migration);
    const lease=(t:string|null=token,epoch=1)=>db.query("select public.ordax_authenticated_renew_product_action_lease_v1($1::uuid,$2::text,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7::bigint,$8::uuid,$9::text,$10::integer) result",[id,t,id,id,id,id,epoch,id,"boot-id",120]).then(r=>r.rows[0].result);
    const progress=(t:string|null=token,epoch=1)=>db.query("select public.ordax_authenticated_progress_product_action_v1($1::uuid,$2::text,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7::bigint,$8::uuid,$9::text,$10::text,$11::text,$12::smallint) result",[id,t,id,id,id,id,epoch,id,"boot-id","run",null,50]).then(r=>r.rows[0].result);
    for(const invalid of [null,"invalid","b".repeat(64)]) for(const call of [lease,progress])
      assert.deepEqual(await call(invalid),{ok:false,error:"invalid_device_token"});
    await db.exec("update public.fixture set revoked=true");
    for(const call of [lease,progress]) assert.deepEqual(await call(),{ok:false,error:"invalid_device_token"});
    await db.exec("update public.fixture set revoked=false");
    assert.equal((await lease(token,2)).ok,false);
    assert.equal((await progress(token,2)).ok,false);
    assert.equal((await lease()).ok,true);
    assert.equal((await progress()).ok,true);
    await db.exec("update public.fixture set fenced=true");
    assert.equal((await lease()).ok,false);
    assert.equal((await progress()).ok,false);
    assert.deepEqual((await db.query("select leases,events from public.fixture")).rows[0],{leases:1,events:1});
    const perms=await db.query("select proname,has_function_privilege('anon',oid,'execute') anon_exec,has_function_privilege('authenticated',oid,'execute') auth_exec,has_function_privilege('service_role',oid,'execute') service_exec,has_function_privilege('ordax_edge_executor',oid,'execute') edge_exec from pg_proc where proname in ('ordax_authenticated_renew_product_action_lease_v1','ordax_authenticated_progress_product_action_v1')");
    assert.equal(perms.rows.length,2);
    for(const row of perms.rows) assert.deepEqual([row.anon_exec,row.auth_exec,row.service_exec,row.edge_exec],[false,false,false,true]);
  } finally {await db.close();}
});
