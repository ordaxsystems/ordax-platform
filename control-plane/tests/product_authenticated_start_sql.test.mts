import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import {createRequire} from "node:module";

const require=createRequire(new URL("../cloudflare/package.json",import.meta.url));
const {PGlite}=require("@electric-sql/pglite");
const atomicMigration=fs.readFileSync(new URL(
  "../supabase/migrations/20261121004000_product_atomic_action_start_v1.sql",import.meta.url,
),"utf8");
const authenticatedMigration=fs.readFileSync(new URL(
  "../supabase/migrations/20261121041000_product_authenticated_start_v1.sql",import.meta.url,
),"utf8");

const DEVICE="11111111-1111-4111-8111-111111111111";
const REQUEST="22222222-2222-4222-8222-222222222222";
const EFFECT="33333333-3333-4333-8333-333333333333";
const ATTEMPT="44444444-4444-4444-8444-444444444444";
const LEASE="55555555-5555-4555-8555-555555555555";
const AGENT="66666666-6666-4666-8666-666666666666";
const TOKEN="a".repeat(64);

test("authenticated atomic /start validates revocation before lease and keeps provenance rollback",async()=>{
  const db=new PGlite();
  try{
    // Only the existing lower-level authorities are stubbed. Execute the
    // canonical migration unchanged with real Postgres transaction semantics.
    await db.exec(`
      create role anon;
      create role authenticated;
      create role service_role;
      create role ordax_edge_executor;
      create table public.test_device_credentials(
        device_id uuid primary key,
        token_sha256 text not null,
        active boolean not null default true,
        revoked boolean not null default false
      );
      create function public.ordax_authenticate_product_device_v1(
        p_device_id uuid,p_token_sha256 text
      ) returns boolean language sql stable as $stub$
        select exists(select 1 from public.test_device_credentials
          where device_id=p_device_id and token_sha256=p_token_sha256
            and active=true and revoked=false);
      $stub$;
      create table public.test_action_start(
        request_id uuid primary key,
        status text not null default 'leased',
        lease_active boolean not null default true,
        grant_current boolean not null default true,
        runtime_kind text,
        agent_version text
      );
      create function public.ordax_start_product_action_v1(
        p_device_id uuid,p_request_id uuid,p_effect_id uuid,
        p_attempt_id uuid,p_lease_id uuid,p_execution_epoch bigint,
        p_agent_instance_id uuid,p_boot_id text
      ) returns boolean language plpgsql as $stub$
      begin
        update public.test_action_start set status='running'
          where request_id=p_request_id and status in ('leased','running')
            and lease_active=true and grant_current=true;
        return found;
      end;
      $stub$;
      create function public.ordax_bind_product_action_runtime_provenance_v1(
        p_device_id uuid,p_request_id uuid,p_effect_id uuid,
        p_attempt_id uuid,p_lease_id uuid,p_execution_epoch bigint,
        p_agent_instance_id uuid,p_boot_id text,p_runtime_kind text,
        p_agent_version text
      ) returns boolean language plpgsql as $stub$
      declare v public.test_action_start%rowtype;
      begin
        select * into v from public.test_action_start
          where request_id=p_request_id for update;
        if not found or v.status not in ('leased','running','succeeded','failed','cancelled')
          or p_runtime_kind not in ('ordax-os','desktop-agent','mobile-client','other')
          or p_agent_version is null or length(p_agent_version) not between 1 and 80 then
          return false;
        end if;
        if v.runtime_kind is not null then
          return v.runtime_kind=p_runtime_kind and v.agent_version=p_agent_version;
        end if;
        update public.test_action_start set runtime_kind=p_runtime_kind,
          agent_version=p_agent_version where request_id=p_request_id;
        return true;
      end;
      $stub$;
    `);
    await db.exec(atomicMigration);
    await db.exec(authenticatedMigration);
    await db.query("insert into public.test_device_credentials(device_id,token_sha256) values($1,$2)",
      [DEVICE,TOKEN]);
    await db.query("insert into public.test_action_start(request_id,runtime_kind,agent_version) values($1,$2,$3)",
      [REQUEST,"desktop-agent","1.31.0"]);
    const submit=async(kind:string|null,version:string|null,token:string|null=TOKEN,device:string|null=DEVICE)=>
      (await db.query("select public.ordax_authenticated_start_product_action_v1("+
        "$1::uuid,$2::text,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7::bigint,"+
        "$8::uuid,$9::text,$10::text,$11::text) as result",
        [device,token,REQUEST,EFFECT,ATTEMPT,LEASE,1,AGENT,"boot-identity",kind,version],
      )).rows[0].result;
    const read=async()=>(await db.query(
      "select status,runtime_kind,agent_version from public.test_action_start where request_id=$1",[REQUEST],
    )).rows[0];
    for(const token of [null,"not-a-sha","b".repeat(64)]){
      assert.deepEqual(await submit("desktop-agent","1.31.0",token),
        {ok:false,error:"invalid_device_token"});
    }
    assert.deepEqual(await submit("desktop-agent","1.31.0",TOKEN,
      "99999999-9999-4999-8999-999999999999"),{ok:false,error:"invalid_device_token"});
    await db.query("update public.test_device_credentials set revoked=true where device_id=$1",[DEVICE]);
    assert.deepEqual(await submit("desktop-agent","1.31.0"),{ok:false,error:"invalid_device_token"});
    await db.query("update public.test_device_credentials set revoked=false,active=false where device_id=$1",[DEVICE]);
    assert.deepEqual(await submit("desktop-agent","1.31.0"),{ok:false,error:"invalid_device_token"});
    await db.query("update public.test_device_credentials set active=true where device_id=$1",[DEVICE]);
    assert.deepEqual(await submit("desktop-agent","1.30.0"),
      {ok:false,error:"runtime_provenance_conflict"});
    assert.deepEqual(await read(),
      {status:"leased",runtime_kind:"desktop-agent",agent_version:"1.31.0"},
      "provenance mismatch must undo an already-applied running transition");
    assert.deepEqual(await submit(null,"1.31.0"),
      {ok:false,error:"runtime_provenance_conflict"});
    assert.equal((await read()).status,"leased");
    assert.deepEqual(await submit("desktop-agent","1.31.0"),{ok:true});
    assert.deepEqual(await submit("desktop-agent","1.31.0"),{ok:true},
      "replay of same lease must return success");
    assert.deepEqual(await read(),
      {status:"running",runtime_kind:"desktop-agent",agent_version:"1.31.0"});
    await db.query("update public.test_action_start set status='leased', grant_current=false where request_id=$1",[REQUEST]);
    assert.deepEqual(await submit("desktop-agent","1.31.0"),
      {ok:false,error:"lease_not_active"});
    assert.equal((await read()).status,"leased");
    await db.query("update public.test_action_start set grant_current=true, lease_active=false where request_id=$1",[REQUEST]);
    assert.deepEqual(await submit("desktop-agent","1.31.0"),
      {ok:false,error:"lease_not_active"});
    assert.equal((await read()).status,"leased");
    const perms=await db.query(
      "select has_function_privilege('anon',$1,'EXECUTE') anon_exec,"+
      "has_function_privilege('authenticated',$1,'EXECUTE') auth_exec,"+
      "has_function_privilege('service_role',$1,'EXECUTE') service_exec,"+
      "has_function_privilege('ordax_edge_executor',$1,'EXECUTE') edge_exec",
      ["public.ordax_authenticated_start_product_action_v1("+
        "uuid,text,uuid,uuid,uuid,uuid,bigint,uuid,text,text,text)"],
    );
    assert.deepEqual(perms.rows[0],{anon_exec:false,auth_exec:false,service_exec:false,edge_exec:true});
  } finally {await db.close();}
});
