import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {createRequire} from "node:module";
import {randomUUID} from "node:crypto";

const require=createRequire(new URL("../cloudflare/package.json",import.meta.url));
const {PGlite}=require("@electric-sql/pglite");
const migration=(name:string)=>fs.readFileSync(
  new URL("../supabase/migrations/"+name,import.meta.url),"utf8");
const proposed=fs.readFileSync(new URL(
  "../supabase/proposals/owner_central_session_targets_v1.sql",import.meta.url),"utf8");
const findFunction=(source:string,name:string)=>{
  const escaped=name.replaceAll(".","\\.");
  const found=source.match(new RegExp(
    "create or replace function "+escaped+"\\([\\s\\S]*?\\n\\$\\$;","i"));
  assert.ok(found,name);
  return found[0];
};
test("Owner preflight uses real canonical grant eligibility SQL (PGlite), never selects online PC",async()=>{
  const db=new PGlite();
  const [owner,other,client,desktop,notebook,discovery,first,second]=
    Array.from({length:8},()=>randomUUID());
  const inspect=async(id=owner,oauth=client)=>{
    const result=await db.query(
      "select public.ordax_owner_central_session_targets_v1($1::uuid,$2::text) as result",
      [id,oauth]);
    return result.rows[0].result as any;
  };
  try{
    await db.exec(`create schema private;create schema auth;
      create role anon;create role authenticated;create role service_role;
      create role ordax_edge_executor;
      create table auth.users(id uuid primary key);
      create table auth.oauth_clients(id uuid primary key, deleted_at timestamptz);
      create table auth.oauth_consents(user_id uuid,client_id uuid,revoked_at timestamptz);
      create table public.ordax_product_devices(
        device_id uuid primary key,owner_user_id uuid,state text);
      create table public.ordax_device_presence(
        device_id uuid primary key,online boolean,last_seen_at timestamptz,
        agent_version text,capability_digest text);
      create table public.ordax_remote_capability_grants(
        grant_id uuid primary key,owner_user_id uuid,device_id uuid,
        client_kind text,client_id text,scope_kind text,profile_key text,
        capability text,space_id uuid,project_id uuid,state text,valid_until timestamptz);`);
    await db.exec(`create function private.ordax_trusted_actor_auth_eligible_v1(id uuid)
      returns boolean language sql stable security definer set search_path = ''
      as $$ select exists(select 1 from auth.users where auth.users.id=id) $$;`);
    await db.exec(findFunction(migration(
      "20261021032000_central_session_operational_device_selection_v1.sql"),
      "private.ordax_central_device_grant_eligible_v1"));
    await db.exec(findFunction(migration(
      "20261022014630_product_presence_freshness_v1.sql"),
      "private.ordax_product_presence_online_v1"));
    await db.exec(proposed);
    await db.query("insert into auth.users(id) values($1)",[owner]);
    await db.query("insert into auth.oauth_clients(id) values($1)",[client]);
    await db.query("insert into auth.oauth_consents values($1,$2,null)",[owner,client]);
    for(const device of [desktop,notebook]){
      await db.query("insert into public.ordax_product_devices values($1,$2,'active')",
        [device,owner]);
      await db.query("insert into public.ordax_device_presence values($1,$2,now(),$3,$4)",
        [device,device===desktop,"1.0.0","c".repeat(64)]);
    }
    assert.equal((await inspect()).state,"no_action_grant");
    await db.query("insert into public.ordax_remote_capability_grants values($1,$2,$3,'product-mcp',$4,'device','mcp-discovery','product.target.read',null,null,'active',null)",
      [discovery,owner,desktop,client]);
    assert.equal((await inspect()).eligible_device_count,0,
      "discovery must not elect the desktop");
    await db.query("insert into public.ordax_remote_capability_grants values($1,$2,$3,'product-mcp',$4,'device','computer-observe','computer.windows',null,null,'active',now()+interval '1 day')",
      [first,owner,notebook,client]);
    let result=await inspect();
    assert.equal(result.state,"single_granted_target");
    assert.equal(result.targets[0].device_id,notebook);
    assert.equal(result.targets[0].reported_online,false);
    assert.equal(result.dispatch_authorized,false);
    await db.query("insert into public.ordax_remote_capability_grants values($1,$2,$3,'product-mcp',$4,'device','computer-observe','computer.windows',null,null,'active',now()+interval '1 day')",
      [second,owner,desktop,client]);
    result=await inspect();
    assert.equal(result.state,"owner_selection_required",
      "online desktop MUST NOT win over offline notebook");
    assert.equal(result.eligible_device_count,2);
    assert.equal(result.owner_choice_performed,false);
    assert.equal(result.attested,false);
    assert.equal((await inspect(other)).ok,false,"other owner");
    assert.equal((await inspect(owner,other)).ok,false,"other client");
    await db.exec("update auth.oauth_consents set revoked_at=now()");
    assert.equal((await inspect()).error,"owner_central_client_not_consented");
    await db.exec("update auth.oauth_consents set revoked_at=null");
    await db.query("update public.ordax_remote_capability_grants set state='revoked' where grant_id=$1",[first]);
    result=await inspect();
    assert.equal(result.eligible_device_count,1);
    assert.equal(result.targets[0].device_id,desktop);
    await db.query("delete from public.ordax_device_presence where device_id=$1",[desktop]);
    result=await inspect();
    assert.equal(result.targets[0].reported_online,false);
    assert.equal(result.targets[0].runtime_ready,false,
      "missing heartbeat is false, never a nullable permission/readiness hint");
    const sig="public.ordax_owner_central_session_targets_v1(uuid,text)";
    for(const role of ["anon","authenticated","service_role"]){
      assert.equal((await db.query("select has_function_privilege($1,$2,'EXECUTE') as allowed",
        [role,sig])).rows[0].allowed,false,role);
    }
    assert.equal((await db.query("select has_function_privilege('ordax_edge_executor',$1,'EXECUTE') as allowed",
      [sig])).rows[0].allowed,true);
  }finally{await db.close();}
});
