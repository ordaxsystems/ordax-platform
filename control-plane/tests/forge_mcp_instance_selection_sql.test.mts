import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import path from "node:path";
import {createRequire} from "node:module";
import {fileURLToPath} from "node:url";

const require=createRequire(new URL("../cloudflare/package.json",import.meta.url));
const {PGlite}=require("@electric-sql/pglite");
const folder=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"../supabase/migrations");
const migration=fs.readFileSync(path.join(folder,
  "20261123100000_forge_mcp_explicit_instance_selection_v1.sql"),"utf8");
const original=fs.readFileSync(path.join(folder,
  "20261114210500_forge_https_rpc_transport_v1.sql"),"utf8");
const OWNER="11111111-1111-4111-8111-111111111111";
const OTHER="99999999-9999-4999-8999-999999999999";
const CLIENT="22222222-2222-4222-8222-222222222222";
const OLD="33333333-3333-4333-8333-333333333333";
const TARGET="77777777-7777-4777-8777-777777777777";
const FOREIGN="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const REQUEST="44444444-4444-4444-8444-444444444444";

test("PostgreSQL enforces explicit owner/client CAS and disallows switching with outstanding actions",async t=>{
  const db=new PGlite();
  t.after(()=>db.close());
  await db.exec([
    "create schema auth; create schema private;",
    "create role anon;create role authenticated;create role service_role;",
    "create role ordax_edge_runtime;create role ordax_edge_executor;",
    "create table auth.users(id uuid primary key);",
    "create table private.ordax_forge_instances(instance_id uuid primary key,owner_user_id uuid not null,display_name text not null,app_version text not null,reported_online boolean not null,last_seen_at timestamptz,revoked_at timestamptz);",
    "create table private.ordax_forge_mcp_bindings(owner_user_id uuid not null,client_id text not null,instance_id uuid not null,bound_at timestamptz default now(),revoked_at timestamptz,primary key(owner_user_id,client_id));",
    "create table private.ordax_forge_action_requests(request_id uuid primary key,owner_user_id uuid not null,client_id text not null,instance_id uuid not null,status text not null,expires_at timestamptz not null);",
    "create function private.ordax_trusted_actor_auth_eligible_v1(p_owner uuid) returns boolean language sql stable as $$ select p_owner='"+OWNER+"'::uuid; $$;",
    "create function private.ordax_forge_oauth_client_authorized_v1(p_owner uuid,p_client text) returns boolean language sql stable as $$ select p_owner='"+OWNER+"'::uuid and p_client='"+CLIENT+"'::text; $$;",
  ].join("\n"));
  const start=migration.indexOf("create or replace function public.ordax_list_forge_mcp_instances_v1(");
  const helperEnd=migration.indexOf("create or replace function public.ordax_forge_http_rpc_v1(");
  assert.ok(start>0&&helperEnd>start);
  await db.exec(migration.slice(start,helperEnd));
  const read=async(name:string,args:unknown[]=[]):Promise<any>=>{
    const result=await db.query("select public."+name+"($1::uuid,$2::text) as result",args);
    return result.rows[0]?.result;
  };
  const list=(owner=OWNER,client=CLIENT)=>read("ordax_list_forge_mcp_instances_v1",[owner,client]);
  const select=async(target=TARGET,expected:string|null=OLD,owner=OWNER,client=CLIENT)=>{
    const result=await db.query("select public.ordax_select_forge_mcp_instance_v1($1::uuid,$2::text,$3::uuid,$4::uuid) as result",
      [owner,client,target,expected]);
    return (result.rows[0] as any).result;
  };
  await db.query("insert into auth.users(id) values ($1::uuid),($2::uuid)",[OWNER,OTHER]);
  await db.query("insert into private.ordax_forge_instances(instance_id,owner_user_id,display_name,app_version,reported_online,last_seen_at) values ($1::uuid,$4::uuid,'OrdaX Forge','v1',false,now()-interval '1 day'),($2::uuid,$4::uuid,'Forge Achegue-se','v1',true,now()),($3::uuid,$5::uuid,'Outra conta','v1',true,now())",
    [OLD,TARGET,FOREIGN,OWNER,OTHER]);
  await db.query("insert into private.ordax_forge_mcp_bindings(owner_user_id,client_id,instance_id) values ($1::uuid,$2::text,$3::uuid)",[OWNER,CLIENT,OLD]);

  const listed=await list();
  assert.equal(listed.ok,true);
  assert.equal(listed.candidate_count,2);
  assert.equal(listed.bound_instance_id,OLD);
  assert.equal(listed.instances.length,2);
  assert.ok(listed.instances.some((x:any)=>x.instance_id===TARGET&&x.online===true));
  assert.ok(!listed.instances.some((x:any)=>x.instance_id===FOREIGN));
  assert.equal((await list(OTHER,CLIENT)).error,"forge_mcp_authorization_required");
  assert.equal((await list(OWNER,"88888888-8888-4888-8888-888888888888")).error,"forge_mcp_authorization_required");
  assert.equal((await select(FOREIGN,OLD)).error,"forge_instance_target_unavailable");
  assert.equal((await select(TARGET,TARGET)).error,"forge_instance_binding_conflict");
  assert.equal((await select(OLD,OLD)).error,"forge_instance_target_unavailable");
  await db.query("insert into private.ordax_forge_action_requests(request_id,owner_user_id,client_id,instance_id,status,expires_at) values ($1::uuid,$2::uuid,$3::text,$4::uuid,'leased',now()+interval '2 minutes')",
    [REQUEST,OWNER,CLIENT,OLD]);
  assert.equal((await select()).error,"forge_instance_selection_pending_actions");
  await db.query("delete from private.ordax_forge_action_requests where request_id=$1::uuid",[REQUEST]);
  assert.deepEqual(await select(),{
    ok:true,instance_id:TARGET,previous_instance_id:OLD,changed:true});
  assert.equal((await list()).bound_instance_id,TARGET);
  assert.deepEqual(await select(TARGET,TARGET),{
    ok:true,instance_id:TARGET,previous_instance_id:TARGET,changed:false});
  assert.equal((await select(TARGET,OLD)).error,"forge_instance_binding_conflict");
  assert.equal((await select(TARGET,TARGET,OTHER,CLIENT)).error,"forge_mcp_authorization_required");
  const row=await db.query("select instance_id from private.ordax_forge_mcp_bindings where client_id=$1",[CLIENT]);
  assert.equal((row.rows[0] as any).instance_id,TARGET);

  // A bound instance may be revoked later. Its old UUID remains visible to
  // this same client for exact CAS recovery, but never appears as a choice.
  const fresh="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  await db.query("insert into private.ordax_forge_instances(instance_id,owner_user_id,display_name,app_version,reported_online,last_seen_at) values ($1::uuid,$2::uuid,'Forge New','v1',true,now())",[fresh,OWNER]);
  await db.query("update private.ordax_forge_instances set revoked_at=now() where instance_id=$1::uuid",[TARGET]);
  const revoked=await list();
  assert.equal(revoked.bound_instance_id,TARGET);
  assert.ok(!revoked.instances.some((x:any)=>x.instance_id===TARGET));
  assert.deepEqual(await select(fresh,TARGET),{
    ok:true,instance_id:fresh,previous_instance_id:TARGET,changed:true});

  // The actual versioned HTTPS RPC dispatch verifies JWT claims itself.
  const identityStart=original.indexOf("create or replace function private.ordax_forge_native_oauth_client_id_v1()");
  const wrapperStart=original.indexOf("create or replace function public.ordax_forge_http_rpc_v1(");
  assert.ok(identityStart>0&&wrapperStart>identityStart);
  await db.exec(original.slice(identityStart,wrapperStart));
  const end=migration.lastIndexOf("commit;");
  await db.exec(migration.slice(helperEnd,end));
  await db.query("select set_config('request.jwt.claims',$1,false)",[
    JSON.stringify({sub:OWNER,client_id:CLIENT,role:"authenticated"})]);
  const http=await db.query("select public.ordax_forge_http_rpc_v1('mcp_instances_list','{}'::jsonb) as result");
  assert.equal((http.rows[0] as any).result.bound_instance_id,fresh);
  await db.query("select set_config('request.jwt.claims',$1,false)",[
    JSON.stringify({sub:OTHER,client_id:CLIENT,role:"authenticated"})]);
  const denied=await db.query("select public.ordax_forge_http_rpc_v1('mcp_instance_select',$1::jsonb) as result",
    [JSON.stringify({target_instance_id:TARGET,expected_instance_id:TARGET})]);
  assert.equal((denied.rows[0] as any).result.ok,false);
});
