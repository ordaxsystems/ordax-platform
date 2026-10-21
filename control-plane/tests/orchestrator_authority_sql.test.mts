import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createRequire} from 'node:module';
import {randomUUID} from 'node:crypto';
const require=createRequire(new URL('../cloudflare/package.json',import.meta.url));
const {PGlite}=require('@electric-sql/pglite');
const migrations=new URL('../supabase/migrations/',import.meta.url);
const migration='20261021183531_orchestrator_read_authorization_v1.sql';
const read=(name:string)=>fs.readFileSync(new URL(name,migrations),'utf8');

test('actual PostgreSQL resolver fences live App reads, grant/consent revocation and role access',async()=>{
  const db=new PGlite();
  const [owner,client,device,grant,request,effect,attempt,lease,agent]=Array.from({length:9},()=>randomUUID());
  try {
    await db.exec(`
      create schema private; create schema auth;
      create role anon; create role authenticated; create role service_role;
      create role ordax_edge_executor; create role ordax_edge_runtime;
      create table auth.users(id uuid primary key,deleted_at timestamptz,is_anonymous boolean default false,
        confirmed_at timestamptz default now(),banned_until timestamptz);
      create table public.ordax_accounts(user_id uuid primary key);
      create table auth.oauth_clients(id uuid primary key,deleted_at timestamptz);
      create table auth.oauth_consents(user_id uuid,client_id uuid,revoked_at timestamptz);
      create table public.ordax_product_devices(device_id uuid primary key,owner_user_id uuid,state text);
      create table public.ordax_space_devices(space_id uuid,device_id uuid,state text,access_mode text);
      create table public.ordax_projects(project_id uuid,space_id uuid);
      create table public.ordax_device_project_bindings(project_id uuid,device_id uuid,state text,allowed_capabilities text[]);
      create table public.ordax_remote_capability_grants(grant_id uuid primary key,owner_user_id uuid,
        device_id uuid,client_kind text,client_id text,capability text,access_mode text,state text,
        space_id uuid,project_id uuid,scope_kind text,valid_until timestamptz,created_at timestamptz default now(),profile_key text);
      create table private.ordax_product_action_requests(request_id uuid primary key,device_id uuid,
        effect_id uuid,attempt_id uuid,lease_id uuid,execution_epoch bigint,agent_instance_id uuid,boot_id text,
        status text,lease_expires_at timestamptz,expires_at timestamptz,capability text,access_mode text,
        client_kind text,client_id text,space_id uuid,project_id uuid,owner_user_id uuid,grant_id uuid);
    `);
    // Execute the existing canonical functions, not a reimplementation of their predicates.
    const eligible=read('20261007212000_trusted_actor_auth_eligibility_v1.sql')
      .match(/create function private\.ordax_trusted_actor_auth_eligible_v1\([\s\S]*?\$function\$;/)![0];
    const resolver=read('20261007203000_product_client_grant_isolation_v1.sql')
      .match(/create or replace function private\.ordax_resolve_product_remote_grant_v1\([\s\S]*?\$\$;/)![0];
    await db.exec(eligible); await db.exec(resolver); await db.exec(read(migration));
    await db.query('insert into auth.users(id) values ($1)',[owner]);
    await db.query('insert into public.ordax_accounts values ($1)',[owner]);
    await db.query('insert into auth.oauth_clients(id) values ($1)',[client]);
    await db.query('insert into auth.oauth_consents values ($1,$2,null)',[owner,client]);
    await db.query("insert into public.ordax_product_devices values ($1,$2,'active')",[device,owner]);
    await db.query(`insert into public.ordax_remote_capability_grants(grant_id,owner_user_id,device_id,
      client_kind,client_id,capability,access_mode,state,scope_kind,profile_key)
      values ($1,$2,$3,'product-mcp',$4,'orchestrator.app_read','read','active','device','orchestrator-app-read')`,[grant,owner,device,client]);
    await db.query(`insert into private.ordax_product_action_requests values
      ($1,$2,$3,$4,$5,1,$6,'fixture-boot','running',now()+interval '2 minutes',now()+interval '10 minutes',
       'orchestrator.app_read','read','product-mcp',$7,null,null,$8,$9)`,[request,device,effect,attempt,lease,agent,client,owner,grant]);
    const args=[device,request,effect,attempt,lease,1,agent,'fixture-boot'];
    const sql='select public.ordax_orchestrator_read_authorization_v1($1,$2,$3,$4,$5,$6,$7,$8) as result';
    const call=async(values=args)=>(await db.query(sql,values)).rows[0].result;
    const result=await call();
    assert.equal(result.ok,true);assert.equal(result.authorization.subject_id,owner);
    assert.equal(result.authorization.client_id,client);assert.equal(result.authorization.grant_id,grant);
    assert.equal(result.authorization.app_id,'br.com.ordax.orchestrator.lab');
    assert.ok(result.authorization.expires_at_ms>Date.now());
    assert.ok(result.authorization.expires_at_ms<=Date.now()+120000);
    for(let index=0;index<args.length;index++){
      const wrong=[...args];wrong[index]=index===5?2:index===7?'other-boot':randomUUID();
      assert.equal((await call(wrong)).ok,false,`fence ${index}`);
    }
    const mutations=[
      "update auth.oauth_consents set revoked_at=now()",
      "update auth.oauth_clients set deleted_at=now()",
      "update auth.users set banned_until=now()+interval '1 hour'",
      "update auth.users set deleted_at=now()",
      "update public.ordax_product_devices set state='revoked'",
      "update public.ordax_remote_capability_grants set state='revoked'",
      "update public.ordax_remote_capability_grants set valid_until=now()-interval '1 second'",
      "update public.ordax_remote_capability_grants set client_id='different-client'",
      "update public.ordax_remote_capability_grants set capability='computer.screenshot'",
      "update public.ordax_remote_capability_grants set access_mode='write'",
      "update public.ordax_remote_capability_grants set profile_key='full-computer-control'",
      "update private.ordax_product_action_requests set status='succeeded'",
      "update private.ordax_product_action_requests set lease_expires_at=now()-interval '1 second'",
      "update private.ordax_product_action_requests set expires_at=now()-interval '1 second'",
      "update private.ordax_product_action_requests set capability='computer.screenshot'",
      "update private.ordax_product_action_requests set access_mode='write'",
      "update private.ordax_product_action_requests set space_id=gen_random_uuid()",
    ];
    for(const mutation of mutations){
      await db.exec('begin');await db.exec(mutation);
      assert.equal((await call()).ok,false,mutation);await db.exec('rollback');
    }
    const signature='public.ordax_orchestrator_read_authorization_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text)';
    for(const role of ['anon','authenticated','service_role','ordax_edge_runtime']){
      const r=await db.query('select has_function_privilege($1,$2,\'EXECUTE\') as allowed',[role,signature]);
      assert.equal(r.rows[0].allowed,false,role);
    }
    await db.exec('set role ordax_edge_executor');
    assert.equal((await call()).ok,true);await db.exec('reset role');
    await db.exec(fs.readFileSync(new URL('../supabase/tests/orchestrator_read_authorization_postflight.sql',import.meta.url),'utf8'));
  } finally {await db.close();}
});
