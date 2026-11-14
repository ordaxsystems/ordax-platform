import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";

const require=createRequire(new URL("../cloudflare/package.json",import.meta.url));
const {PGlite}=require("@electric-sql/pglite");
const providerMigration=fs.readFileSync(
  new URL("../supabase/migrations/20261114002500_github_authority_revocation_webhook_v1.sql",import.meta.url),
  "utf8",
);
const userMigration=fs.readFileSync(
  new URL("../supabase/migrations/20261114004000_github_user_authorization_revocation_v1.sql",import.meta.url),
  "utf8",
);

test("GitHub webhook migration is fail-closed and never touches Space/device execute authority",()=>{
  const combined=providerMigration+"\n"+userMigration;
  assert.match(combined,/ordax_github_webhook_executor/);
  assert.match(combined,/ordax_github_authority_revocations/);
  assert.match(combined,/ordax_github_webhook_deliveries/);
  assert.match(combined,/github_repository_authority_revoked/);
  assert.match(combined,/verified_github_user_id/);
  assert.match(combined,/github_app_authorization/);
  assert.match(combined,/pg_advisory_xact_lock/);
  assert.match(combined,/status = 'cancelled'/);
  assert.match(combined,/error_code = 'github_authority_revoked'/);
  assert.match(userMigration,/drop function public\.ordax_apply_github_authority_revocation_v1/);
  assert.doesNotMatch(combined,/update\s+public\.ordax_space_devices/i,
    "provider revocation must not remove a Space/device relation shared by other Projects");
  assert.doesNotMatch(combined,/delete\s+from\s+public\.ordax_project_connections/i,
    "provider history remains auditable; authority changes state instead of deleting identity");
});

test("signed provider revocation cascades through connection, binding, grants, intents and nonterminal actions",async()=>{
  const db=new PGlite();
  const owner=randomUUID(),space=randomUUID(),project=randomUUID(),device=randomUUID();
  const connection=randomUUID(),binding=randomUUID(),grant=randomUUID(),intent=randomUUID();
  const delivery=randomUUID(),staleChallenge=randomUUID(),freshChallenge=randomUUID();
  const userDelivery=randomUUID(),staleUserChallenge=randomUUID(),freshUserChallenge=randomUUID();
  const installation="123456789", repository="987654321", githubUser="555";
  try{
    await db.exec(`
      create schema private;
      create schema auth;
      create schema extensions;
      create role anon;
      create role authenticated;
      create role service_role;
      create role ordax_edge_executor;
      create role ordax_edge_runtime;
      create role ordax_owner_project_onboarding_executor;
      grant usage on schema public to ordax_edge_runtime, ordax_owner_project_onboarding_executor;

      create function extensions.gen_random_uuid()
      returns uuid language sql volatile as $$ select gen_random_uuid() $$;

      create table public.ordax_projects(
        project_id uuid primary key,
        space_id uuid not null,
        state text not null,
        unique(project_id,space_id)
      );
      create table public.ordax_project_connections(
        connection_id uuid primary key default gen_random_uuid(),
        space_id uuid not null,
        owner_user_id uuid not null,
        provider text not null,
        external_account_id text,
        installation_id bigint,
        repository_id bigint,
        repository_full_name text,
        default_branch text,
        access_mode text not null default 'read',
        state text not null,
        metadata jsonb not null default '{}'::jsonb,
        created_at timestamptz not null default clock_timestamp(),
        updated_at timestamptz not null default clock_timestamp(),
        project_id uuid not null
      );
      create table public.ordax_device_project_bindings(
        binding_id uuid primary key,
        project_id uuid not null,
        device_id uuid not null,
        local_project_ref text not null,
        state text not null,
        allowed_capabilities text[] not null default '{}'::text[],
        created_at timestamptz not null default clock_timestamp(),
        updated_at timestamptz not null default clock_timestamp()
      );
      create table public.ordax_remote_capability_grants(
        grant_id uuid primary key,
        project_id uuid,
        state text not null,
        updated_at timestamptz not null default clock_timestamp()
      );
      create table private.ordax_owner_project_device_binding_intents(
        intent_id uuid primary key,
        project_id uuid not null,
        consumed_at timestamptz
      );
      create table private.ordax_product_action_requests(
        request_id uuid primary key default gen_random_uuid(),
        project_id uuid,
        status text not null,
        lease_expires_at timestamptz,
        finished_at timestamptz,
        error_code text
      );
      create table private.ordax_owner_github_authorization_challenges(
        challenge_id uuid primary key,
        owner_user_id uuid not null,
        project_id uuid not null,
        space_id uuid not null,
        status text not null,
        github_user_id bigint,
        github_user_login text,
        expires_at timestamptz not null,
        verified_at timestamptz,
        consumed_at timestamptz,
        updated_at timestamptz not null default clock_timestamp()
      );
      create table private.ordax_owner_github_repository_candidates(
        challenge_id uuid not null,
        installation_id bigint not null,
        installation_account_id bigint not null,
        repository_id bigint not null,
        repository_full_name text not null,
        default_branch text,
        expires_at timestamptz not null,
        primary key(challenge_id,repository_id)
      );

      create function private.ordax_subject_can_admin_space_v1(uuid,uuid)
      returns boolean language sql stable security definer set search_path=''
      as $$ select true $$;

      create function public.ordax_owner_select_github_repository_v1(uuid,uuid,text)
      returns jsonb language sql as $$ select '{"ok":false}'::jsonb $$;
      revoke all on function public.ordax_owner_select_github_repository_v1(uuid,uuid,text)
        from public, anon, authenticated, service_role, ordax_edge_executor,
             ordax_edge_runtime, ordax_owner_project_onboarding_executor;
    `);

    await db.query(
      "insert into public.ordax_projects(project_id,space_id,state) values($1,$2,'active')",
      [project,space],
    );
    await db.query(
      `insert into public.ordax_project_connections(
        connection_id,space_id,owner_user_id,provider,external_account_id,
        installation_id,repository_id,repository_full_name,default_branch,
        access_mode,state,metadata,project_id
      ) values($1,$2,$3,'github','444',$4::bigint,$5::bigint,
        'ordaxsystems/ordax-platform','main','read','active',
        jsonb_build_object(
          'authority','github_app_user_authorization_v1',
          'verified_at',(clock_timestamp()-interval '1 minute'),
          'verified_github_user_id',$7::text
        ),$6)`,
      [connection,space,owner,installation,repository,project,githubUser],
    );
    await db.query(
      `insert into public.ordax_device_project_bindings(
        binding_id,project_id,device_id,local_project_ref,state,allowed_capabilities
      ) values($1,$2,$3,'project-1','active',array['terminal.exec'])`,
      [binding,project,device],
    );
    await db.query(
      "insert into public.ordax_remote_capability_grants(grant_id,project_id,state) values($1,$2,'active')",
      [grant,project],
    );
    await db.query(
      "insert into private.ordax_owner_project_device_binding_intents(intent_id,project_id) values($1,$2)",
      [intent,project],
    );
    for(const status of ["queued","leased","running","succeeded"]){
      await db.query(
        "insert into private.ordax_product_action_requests(project_id,status,lease_expires_at) values($1,$2,clock_timestamp()+interval '5 minutes')",
        [project,status],
      );
    }

    await db.exec(providerMigration);
    await db.exec(userMigration);

    const apply=async(
      deliveryId:string,
      payloadHash="a".repeat(64),
      event="repository",
      action="renamed",
      installationId:string|null=installation,
      githubUserId:string|null=null,
      repositoryIds=`{${repository}}`,
    )=>
      (await db.query(
        "select public.ordax_apply_github_authority_revocation_v2($1::uuid,$2::text,$3::text,$4::bigint,$5::bigint,$6::bigint[],$7::text) as result",
        [deliveryId,event,action,installationId,githubUserId,repositoryIds,payloadHash],
      )).rows[0].result as any;

    const revoked=await apply(delivery);
    assert.deepEqual(revoked,{
      ok:true,replayed:false,delivery_id:delivery,
      connection_count:1,binding_count:1,grant_count:1,action_count:3,intent_count:1,
    });
    assert.equal((await db.query(
      "select state from public.ordax_project_connections where connection_id=$1",[connection],
    )).rows[0].state,"revoked");
    assert.equal((await db.query(
      "select state from public.ordax_device_project_bindings where binding_id=$1",[binding],
    )).rows[0].state,"revoked");
    assert.equal((await db.query(
      "select state from public.ordax_remote_capability_grants where grant_id=$1",[grant],
    )).rows[0].state,"revoked");
    assert.ok((await db.query(
      "select consumed_at from private.ordax_owner_project_device_binding_intents where intent_id=$1",[intent],
    )).rows[0].consumed_at);
    const states=(await db.query(
      "select status,error_code from private.ordax_product_action_requests order by status,error_code nulls first",
    )).rows as any[];
    assert.equal(states.filter(row=>row.status==="cancelled").length,3);
    assert.ok(states.filter(row=>row.status==="cancelled")
      .every(row=>row.error_code==="github_authority_revoked"));
    assert.equal(states.filter(row=>row.status==="succeeded").length,1);

    const replay=await apply(delivery);
    assert.equal(replay.ok,true);
    assert.equal(replay.replayed,true);
    assert.equal(replay.connection_count,1);
    assert.equal((await apply(delivery,"b".repeat(64))).error,"github_webhook_delivery_conflict");

    const marker=(await db.query(
      "select scope_kind,installation_id,repository_id,github_user_id from private.ordax_github_authority_revocations where scope_kind='repository'",
    )).rows[0] as any;
    assert.deepEqual(marker,{
      scope_kind:"repository",installation_id:Number(installation),
      repository_id:Number(repository),github_user_id:null,
    });

    await assert.rejects(()=>db.query(
      `insert into public.ordax_project_connections(
        space_id,owner_user_id,provider,external_account_id,installation_id,repository_id,
        repository_full_name,access_mode,state,metadata,project_id
      ) values($1,$2,'github','444',$3::bigint,$4::bigint,'ordaxsystems/other',
        'read','active','{}'::jsonb,$5)`,
      [space,owner,installation,repository,project],
    ),"guard must reject active GitHub authority without verified_at");

    const revokedAt=(await db.query(
      "select revoked_at from private.ordax_github_authority_revocations limit 1",
    )).rows[0].revoked_at as Date;
    const staleVerified=new Date(revokedAt.getTime()-1000).toISOString();
    const freshVerified=new Date(revokedAt.getTime()+1000).toISOString();
    const expires=new Date(Date.now()+10*60*1000).toISOString();

    const addCandidate=async(challengeId:string,verifiedAt:string)=>{
      await db.query(
        `insert into private.ordax_owner_github_authorization_challenges(
          challenge_id,owner_user_id,project_id,space_id,status,github_user_id,
          github_user_login,expires_at,verified_at
        ) values($1,$2,$3,$4,'verified',$5::bigint,'owner-login',$6,$7)`,
        [challengeId,owner,project,space,githubUser,expires,verifiedAt],
      );
      await db.query(
        `insert into private.ordax_owner_github_repository_candidates(
          challenge_id,installation_id,installation_account_id,repository_id,
          repository_full_name,default_branch,expires_at
        ) values($1,$2::bigint,444,$3::bigint,'ordaxsystems/ordax-platform','main',$4)`,
        [challengeId,installation,repository,expires],
      );
    };

    await addCandidate(staleChallenge,staleVerified);
    const stale=(await db.query(
      "select public.ordax_owner_select_github_repository_v1($1::uuid,$2::uuid,$3::text) as result",
      [owner,staleChallenge,repository],
    )).rows[0].result as any;
    assert.deepEqual(stale,{ok:false,error:"github_repository_authority_revoked"});

    await addCandidate(freshChallenge,freshVerified);
    const fresh=(await db.query(
      "select public.ordax_owner_select_github_repository_v1($1::uuid,$2::uuid,$3::text) as result",
      [owner,freshChallenge,repository],
    )).rows[0].result as any;
    assert.equal(fresh.ok,true);
    assert.equal(fresh.state,"active");
    const freshConnection=(await db.query(
      "select state,metadata->>'verified_at' as verified_at,metadata->>'verified_github_user_id' as github_user_id from public.ordax_project_connections where connection_id=$1",
      [connection],
    )).rows[0] as any;
    assert.equal(freshConnection.state,"active");
    assert.equal(freshConnection.github_user_id,githubUser);

    const binding2=randomUUID(),grant2=randomUUID(),intent2=randomUUID();
    await db.query(
      `insert into public.ordax_device_project_bindings(
        binding_id,project_id,device_id,local_project_ref,state,allowed_capabilities
      ) values($1,$2,$3,'project-2','active',array['terminal.exec'])`,
      [binding2,project,device],
    );
    await db.query(
      "insert into public.ordax_remote_capability_grants(grant_id,project_id,state) values($1,$2,'active')",
      [grant2,project],
    );
    await db.query(
      "insert into private.ordax_owner_project_device_binding_intents(intent_id,project_id) values($1,$2)",
      [intent2,project],
    );
    await db.query(
      "insert into private.ordax_product_action_requests(project_id,status,lease_expires_at) values($1,'queued',clock_timestamp()+interval '5 minutes')",
      [project],
    );

    const userRevoked=await apply(
      userDelivery,"c".repeat(64),"github_app_authorization","revoked",null,githubUser,"{}",
    );
    assert.deepEqual(userRevoked,{
      ok:true,replayed:false,delivery_id:userDelivery,
      connection_count:1,binding_count:1,grant_count:1,action_count:1,intent_count:1,
    });
    const userMarker=(await db.query(
      "select scope_kind,installation_id,repository_id,github_user_id,revoked_at from private.ordax_github_authority_revocations where scope_kind='user'",
    )).rows[0] as any;
    assert.equal(userMarker.scope_kind,"user");
    assert.equal(userMarker.installation_id,null);
    assert.equal(userMarker.repository_id,null);
    assert.equal(userMarker.github_user_id,Number(githubUser));

    const userRevokedAt=userMarker.revoked_at as Date;
    await addCandidate(
      staleUserChallenge,new Date(userRevokedAt.getTime()-1000).toISOString(),
    );
    const staleUser=(await db.query(
      "select public.ordax_owner_select_github_repository_v1($1::uuid,$2::uuid,$3::text) as result",
      [owner,staleUserChallenge,repository],
    )).rows[0].result as any;
    assert.deepEqual(staleUser,{ok:false,error:"github_repository_authority_revoked"});

    await addCandidate(
      freshUserChallenge,new Date(userRevokedAt.getTime()+1000).toISOString(),
    );
    const freshUser=(await db.query(
      "select public.ordax_owner_select_github_repository_v1($1::uuid,$2::uuid,$3::text) as result",
      [owner,freshUserChallenge,repository],
    )).rows[0].result as any;
    assert.equal(freshUser.ok,true);
    assert.equal(freshUser.state,"active");

    const signature="public.ordax_apply_github_authority_revocation_v2(uuid,text,text,bigint,bigint,bigint[],text)";
    assert.equal((await db.query(
      "select to_regprocedure('public.ordax_apply_github_authority_revocation_v1(uuid,text,text,bigint,bigint[],text)') is null as gone",
    )).rows[0].gone,true);
    for(const role of ["anon","authenticated","service_role","ordax_edge_executor"]){
      assert.equal((await db.query(
        "select has_function_privilege($1,$2,'EXECUTE') as allowed",[role,signature],
      )).rows[0].allowed,false,role);
    }
    assert.equal((await db.query(
      "select has_function_privilege('ordax_edge_runtime',$1,'EXECUTE') as allowed",[signature],
    )).rows[0].allowed,true);
    for(const table of [
      "private.ordax_github_webhook_deliveries",
      "private.ordax_github_authority_revocations",
    ]){
      for(const role of ["anon","authenticated","service_role","ordax_edge_runtime"]){
        assert.equal((await db.query(
          "select has_table_privilege($1,$2,'SELECT') as allowed",[role,table],
        )).rows[0].allowed,false,role+" "+table);
      }
    }
  }finally{
    await db.close();
  }
});
