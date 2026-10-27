import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {randomUUID} from "node:crypto";
import {createRequire} from "node:module";

const require=createRequire(new URL("../cloudflare/package.json",import.meta.url));
const {PGlite}=require("@electric-sql/pglite");
const read=(name:string)=>fs.readFileSync(
  new URL("../supabase/migrations/"+name,import.meta.url),"utf8");
const proposal=fs.readFileSync(
  new URL("../supabase/proposals/central_owner_device_selection_v1.sql",import.meta.url),"utf8");
function extract(source:string,name:string) {
  const f=source.match(new RegExp(
    "(?:create or replace|create) function "+name.replaceAll(".","\\.")+
    "\\([\\s\\S]*?\\n\\$\\$;","i"));
  assert.ok(f,"source function: "+name);
  return f[0];
}

test("signed Owner choice is bound to the SAME canonical challenge; only exact device confirms",async()=>{
  const db=new PGlite();
  const [owner,other,client,otherClient,desktop,notebook,grantDesk,grantNote,
    challengeWrong,credentialDesk,credentialNote]=Array.from({length:11},()=>randomUUID());
  const hash="a".repeat(64),secondHash="b".repeat(64);
  const tokenDesk="d".repeat(64),tokenNote="e".repeat(64);
  const open=async(session=hash)=>(await db.query(
    "select public.ordax_open_central_device_session_v1($1::uuid,$2::text,$3::text) as result",
    [owner,client,session])).rows[0].result as any;
  const list=async(user=owner,oauth=client)=>(await db.query(
    "select public.ordax_owner_list_central_selections_v1($1::uuid,$2::text) as result",
    [user,oauth])).rows[0].result as any;
  const choose=async(user=owner,oauth=client,id=challengeWrong,device=desktop)=>(await db.query(
    "select public.ordax_owner_select_central_device_v1($1::uuid,$2::text,$3::uuid,$4::uuid) as result",
    [user,oauth,id,device])).rows[0].result as any;
  const poll=async(device=desktop,token=tokenDesk)=>(await db.query(
    "select public.ordax_poll_central_device_session_v1($1::uuid,$2::text) as result",
    [device,token])).rows[0].result as any;
  const confirm=async(device=desktop,token=tokenDesk,id=challengeWrong)=>(await db.query(
    "select public.ordax_confirm_central_device_session_v1($1::uuid,$2::text,$3::uuid) as result",
    [device,token,id])).rows[0].result as any;
  const resolve=async()=> (await db.query(
    "select public.ordax_resolve_central_device_session_v1($1::uuid,$2::text,$3::text) as result",
    [owner,client,hash])).rows[0].result as any;
  try{
    await db.exec(`create schema private;create schema auth;create schema extensions;
      create role anon;create role authenticated;create role service_role;
      create role ordax_edge_executor;
      create function extensions.gen_random_uuid() returns uuid language sql
        as $$ select pg_catalog.gen_random_uuid() $$;
      create table auth.users(id uuid primary key);
      create table auth.oauth_clients(id uuid primary key,deleted_at timestamptz);
      create table auth.oauth_consents(user_id uuid,client_id uuid,revoked_at timestamptz);
      create table public.ordax_product_devices(device_id uuid primary key,owner_user_id uuid,state text);
      create table public.ordax_device_presence(
        device_id uuid primary key,online boolean,last_seen_at timestamptz,
        agent_version text,capability_digest text);
      create table public.ordax_remote_capability_grants(
        grant_id uuid primary key,owner_user_id uuid,device_id uuid,
        client_kind text,client_id text,scope_kind text,profile_key text,
        capability text,space_id uuid,project_id uuid,state text,valid_until timestamptz);
      create table private.ordax_product_device_credentials(
        device_id uuid,token_sha256 text,revoked_at timestamptz);
      create table private.ordax_central_conversation_bindings(
        request_id uuid primary key,owner_user_id uuid,client_id text,device_id uuid,
        space_id uuid,project_id uuid,conversation_id text,session_sha256 text,
        state text,expires_at timestamptz);
      create table private.ordax_central_device_session_challenges(
        challenge_id uuid primary key,owner_user_id uuid not null,client_id text not null,
        device_id uuid not null references public.ordax_product_devices(device_id) on delete cascade,
        session_sha256 text not null,
        state text not null default 'pending'
          constraint ordax_central_device_session_challenges_state_check
          check(state in ('pending','confirmed','expired')),
        binding_request_id uuid,expires_at timestamptz not null,
        binding_expires_at timestamptz not null,
        created_at timestamptz not null default clock_timestamp(),
        confirmed_at timestamptz,
        constraint central_device_session_confirmation_shape check (
          (state='pending' and confirmed_at is null and binding_request_id is null)
          or (state='expired' and confirmed_at is null and binding_request_id is null)
          or (state='confirmed' and confirmed_at is not null and binding_request_id is not null)),
        constraint central_device_session_expiry_shape check(binding_expires_at>expires_at));
      create unique index central_device_session_pending_unique
        on private.ordax_central_device_session_challenges(owner_user_id,client_id,session_sha256)
        where state='pending';
    `);
    await db.exec(`create function private.ordax_trusted_actor_auth_eligible_v1(id uuid)
      returns boolean language sql stable security definer set search_path = ''
      as $$ select exists(select 1 from auth.users where auth.users.id=id) $$;`);
    const operational=read("20261021032000_central_session_operational_device_selection_v1.sql");
    await db.exec(extract(operational,"private.ordax_central_device_grant_eligible_v1"));
    await db.exec(extract(read("20261022014630_product_presence_freshness_v1.sql"),
      "private.ordax_product_presence_online_v1"));
    const attested=read("20261015133000_central_device_attested_session_v1.sql");
    for (const name of ["ordax_poll_central_device_session_v1",
      "ordax_confirm_central_device_session_v1",
      "ordax_resolve_central_device_session_v1"]) {
      await db.exec(extract(attested,"public."+name));
    }
    await db.exec(proposal);

    await db.query("insert into auth.users values($1)",[owner]);
    await db.query("insert into auth.oauth_clients values($1,null),($2,null)",[client,otherClient]);
    await db.query("insert into auth.oauth_consents values($1,$2,null)",[owner,client]);
    for(const device of [desktop,notebook]){
      await db.query("insert into public.ordax_product_devices values($1,$2,'active')",[device,owner]);
      await db.query("insert into public.ordax_device_presence values($1,$2,now(),'1.0.0',$3)",
        [device,device===desktop,"f".repeat(64)]);
    }
    await db.query("insert into private.ordax_product_device_credentials values($1,$2,null),($3,$4,null)",
      [desktop,tokenDesk,notebook,tokenNote]);
    // Two current action grants; online Desktop must NOT be picked implicitly.
    for(const [grant,device] of [[grantDesk,desktop],[grantNote,notebook]]) {
      await db.query(`insert into public.ordax_remote_capability_grants
        values($1,$2,$3,'product-mcp',$4,'device','computer-observe','computer.windows',
          null,null,'active',now()+interval '1 day')`,[grant,owner,device,client]);
    }
    assert.equal((await poll()).pending,false,"unselected ticket is not sent to device");
    const waiting=await open();
    assert.equal(waiting.ok,true);
    assert.equal(waiting.status,"awaiting_owner");
    assert.equal(waiting.device_id,undefined);
    assert.equal((await open()).challenge_id,waiting.challenge_id,"same session idempotent");
    assert.equal((await list()).pending_selections.length,1);
    assert.equal((await list(other)).ok,false);
    assert.equal((await list(owner,otherClient)).error,"owner_central_client_not_consented");
    assert.equal((await choose(other,client,waiting.challenge_id)).ok,false);
    assert.equal((await choose(owner,otherClient,waiting.challenge_id)).ok,false);
    assert.equal((await choose(owner,client,challengeWrong)).ok,false);
    assert.equal((await choose(owner,client,waiting.challenge_id,notebook)).error,
      "central_device_runtime_not_ready","offline Notebook cannot be selected");
    assert.equal((await poll()).pending,false,"Owner choice must precede device poll");
    assert.equal((await confirm(desktop,tokenDesk,waiting.challenge_id)).ok,false,
      "unselected challenge has no device and cannot confirm");

    let chosen=await choose(owner,client,waiting.challenge_id,desktop);
    assert.equal(chosen.ok,true);
    assert.equal(chosen.status,"pending");
    assert.equal(chosen.attested,false);
    assert.equal(chosen.dispatch_authorized,false);
    assert.equal((await choose(owner,client,waiting.challenge_id,notebook)).ok,false,
      "second Owner choice cannot replace selected device");
    assert.equal((await poll(notebook,tokenNote)).pending,false);
    assert.equal((await poll()).challenge_id,waiting.challenge_id);
    assert.equal((await confirm(notebook,tokenNote,waiting.challenge_id)).ok,false,
      "Notebook credential cannot confirm Desktop");
    const confirmed=await confirm(desktop,tokenDesk,waiting.challenge_id);
    assert.equal(confirmed.ok,true);
    assert.equal(confirmed.status,"bound");
    assert.equal((await resolve()).device_id,desktop);
    assert.equal((await open()).device_id,desktop,
      "previous attested binding prevails over subsequent multiple grants");
    assert.equal((await list()).count,0);

    await db.query("update public.ordax_remote_capability_grants set state='revoked' where grant_id=$1",
      [grantDesk]);
    assert.equal((await resolve()).error,"central_device_grant_revoked");
    assert.equal((await db.query("select count(*)::int as total from public.ordax_remote_capability_grants")).rows[0].total,2,
      "session selection never modifies grant ledger");

    // A DIFFERENT provider session with two grants cannot reuse a prior ticket.
    await db.query("update public.ordax_remote_capability_grants set state='active' where grant_id=$1",
      [grantDesk]);
    await db.query("update public.ordax_device_presence set online=true,last_seen_at=now() where device_id=$1",
      [notebook]);
    const waiting2=await open(secondHash);
    assert.equal(waiting2.status,"awaiting_owner");
    assert.notEqual(waiting2.challenge_id,waiting.challenge_id);
    const selections=await Promise.all([
      choose(owner,client,waiting2.challenge_id,desktop),
      choose(owner,client,waiting2.challenge_id,notebook),
    ]);
    assert.equal(selections.filter(x=>x.ok).length,1,"concurrent Owner choices have one winner");
    assert.equal((await db.query("select count(*)::int as total from private.ordax_central_device_session_challenges where state='pending' and session_sha256=$1",[secondHash])).rows[0].total,1);
    const sig="public.ordax_owner_select_central_device_v1(uuid,text,uuid,uuid)";
    for(const role of ["anon","authenticated","service_role"]) {
      assert.equal((await db.query("select has_function_privilege($1,$2,'EXECUTE') as allowed",[role,sig])).rows[0].allowed,false,role);
    }
    assert.equal((await db.query("select has_function_privilege('ordax_edge_executor',$1,'EXECUTE') as allowed",[sig])).rows[0].allowed,true);
  }finally{await db.close();}
});
