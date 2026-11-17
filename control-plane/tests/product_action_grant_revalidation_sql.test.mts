import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(new URL("../cloudflare/package.json", import.meta.url));
const { PGlite } = require("@electric-sql/pglite");
const migration = fs.readFileSync(
  new URL("../supabase/migrations/20261117150000_product_action_grant_revalidation_v1.sql", import.meta.url),
  "utf8",
);
const queuedRevocation = fs.readFileSync(
  new URL("../supabase/migrations/20261117164000_product_queued_revocation_terminal_v1.sql", import.meta.url),
  "utf8",
);

test("Product claim/start/renew recheck original grant, OAuth and owner; terminal receipts stay independent", async () => {
  const db = new PGlite();
  const [owner, client, device, grant, requestId, secondId, agent, otherGrant] =
    Array.from({length: 8}, () => randomUUID());
  const token = "f".repeat(64);
  const boot = "test-boot-20261117";
  const claim = async () => (await db.query(
    "select public.ordax_claim_product_action_v1($1::uuid,$2::uuid,$3::text,120) as result",
    [device,agent,boot],
  )).rows[0].result as any;
  const start = async (job: any) => (await db.query(
    `select public.ordax_start_product_action_v1(
      $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::bigint,$7::uuid,$8::text
    ) as result`,
    [device,job.request_id,job.effect_id,job.attempt_id,job.lease_id,
      job.execution_epoch,agent,boot],
  )).rows[0].result;
  const renew = async (job: any) => (await db.query(
    `select public.ordax_renew_product_action_lease_v1(
      $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::bigint,$7::uuid,$8::text,120
    ) as result`,
    [device,job.request_id,job.effect_id,job.attempt_id,job.lease_id,
      job.execution_epoch,agent,boot],
  )).rows[0].result;
  const status = async (id: string) => (await db.query(
    "select public.ordax_get_product_action_v1($1::uuid,'product-mcp',$2::text,$3::uuid) as result",
    [owner,client,id],
  )).rows[0].result as any;
  const countAudits = async () => (await db.query(
    "select count(*)::int as total from private.ordax_product_action_audit where reason='action_authority_revoked'",
  )).rows[0].total;
  try {
    await db.exec(`
      create schema private; create schema auth; create schema extensions;
      create role anon; create role authenticated; create role service_role;
      create role ordax_edge_executor;
      create function extensions.gen_random_uuid() returns uuid language sql
        as $$ select pg_catalog.gen_random_uuid() $$;
      create table auth.users(id uuid primary key);
      create table auth.oauth_clients(id uuid primary key, deleted_at timestamptz);
      create table auth.oauth_consents(user_id uuid, client_id uuid, revoked_at timestamptz);
      create table public.ordax_remote_capability_grants(
        grant_id uuid primary key, owner_user_id uuid, space_id uuid, project_id uuid,
        device_id uuid, client_kind text, client_id text, capability text,
        access_mode text, scope_kind text, state text, valid_until timestamptz);
      create table private.ordax_product_action_requests(
        request_id uuid primary key, owner_user_id uuid, space_id uuid, project_id uuid,
        device_id uuid, grant_id uuid, client_kind text, client_id text, capability text,
        access_mode text, payload jsonb default '{}'::jsonb, payload_sha256 text,
        effect_id uuid, status text default 'queued', expires_at timestamptz,
        created_at timestamptz default now(), attempt_id uuid, lease_id uuid,
        execution_epoch bigint default 0, agent_instance_id uuid, boot_id text,
        lease_expires_at timestamptz, report_id uuid, started_at timestamptz,
        error_code text, finished_at timestamptz, result jsonb, result_sha256 text,
        execution_runtime_kind text, execution_agent_version text);
      create table private.ordax_product_action_audit(
        request_id uuid,owner_user_id uuid,space_id uuid,project_id uuid,
        device_id uuid,grant_id uuid,client_kind text,client_id text,
        capability text,access_mode text,phase text,decision text,
        reason text,result_ok boolean);
      create function private.ordax_trusted_actor_auth_eligible_v1(subject uuid)
        returns boolean language sql volatile security definer set search_path = ''
        as $$ select exists(select 1 from auth.users u where u.id=subject) $$;
      create function private.ordax_resolve_product_remote_grant_v1(
        subject uuid, sp uuid, project uuid, pc uuid, kind text, client text,
        action text, mode text
      ) returns uuid language sql stable security definer set search_path = ''
        as $$ select g.grant_id from public.ordax_remote_capability_grants g
          where g.owner_user_id=subject and g.space_id is not distinct from sp
            and g.project_id is not distinct from project and g.device_id=pc
            and g.client_kind=kind and g.client_id=client
            and g.capability=action and g.access_mode=mode
            and g.state='active' and (g.valid_until is null or g.valid_until>now())
          limit 1 $$;
      create function private.ordax_expire_queued_product_actions_v1(uuid,uuid)
        returns integer language sql as $$ select 0 $$;
      create function private.ordax_retire_orphaned_running_product_actions_v1(uuid,uuid)
        returns integer language sql as $$ select 0 $$;
      create function public.ordax_claim_product_action_v1(uuid,uuid,text,integer)
        returns jsonb language sql as $$ select '{}'::jsonb $$;
      create function public.ordax_start_product_action_v1(
        uuid,uuid,uuid,uuid,uuid,bigint,uuid,text)
        returns boolean language sql as $$ select false $$;
      create function public.ordax_renew_product_action_lease_v1(
        uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,integer)
        returns timestamptz language sql as $ select null::timestamptz $;
      create function public.ordax_get_product_action_v1(uuid,text,text,uuid)
        returns jsonb language sql as $ select null::jsonb $;
    `);
    await db.exec(migration);
    await db.exec(queuedRevocation);
    await db.query("insert into auth.users values($1)",[owner]);
    await db.query("insert into auth.oauth_clients values($1,null)",[client]);
    await db.query("insert into auth.oauth_consents values($1,$2,null)",[owner,client]);
    await db.query(`insert into public.ordax_remote_capability_grants
      values($1,$2,null,null,$3,'product-mcp',$4,'computer.windows','read',
        'device','active',now()+interval '1 hour')`,[grant,owner,device,client]);
    for(const request of [requestId,secondId]){
      await db.query(`insert into private.ordax_product_action_requests(
        request_id,owner_user_id,device_id,grant_id,client_kind,client_id,capability,
        access_mode,payload_sha256,effect_id,expires_at)
        values($1,$2,$3,$4,'product-mcp',$5,'computer.windows','read',$6,$7,
          now()+interval '5 minutes')`,
        [request,owner,device,grant,client,token,randomUUID()]);
    }
    // A queued command cannot be delivered after its original grant is revoked.
    // The exact Owner/client status read retires only its own request.
    await db.query("update public.ordax_remote_capability_grants set state='revoked' where grant_id=$1",[grant]);
    const retiredByRead = await status(requestId);
    assert.equal(retiredByRead.status,"cancelled");
    assert.equal(retiredByRead.error_code,"action_authority_revoked");
    assert.ok(retiredByRead.finished_at);
    assert.equal(retiredByRead.started_at,null);
    assert.equal(await countAudits(),1,"status read emits one authoritative denial audit");
    assert.equal((await status(requestId)).status,"cancelled");
    assert.equal(await countAudits(),1,"repeated reads must not duplicate the denial audit");
    assert.equal((await claim()).job,null);
    assert.equal((await status(secondId)).status,"cancelled",
      "device claim retires the other undeliverable queued action");
    assert.equal(await countAudits(),2);
    await db.query("update public.ordax_remote_capability_grants set state='active' where grant_id=$1",[grant]);
    const liveId=randomUUID(),nextId=randomUUID();
    for (const id of [liveId,nextId]) {
      await db.query(`insert into private.ordax_product_action_requests(
        request_id,owner_user_id,device_id,grant_id,client_kind,client_id,capability,
        access_mode,payload_sha256,effect_id,expires_at)
        values($1,$2,$3,$4,'product-mcp',$5,'computer.windows','read',$6,$7,
          now()+interval '5 minutes')`,
        [id,owner,device,grant,client,token,randomUUID()]);
    }
    const job = (await claim()).job;
    assert.equal(job.request_id,liveId);
    // Revocation after claim but before start prevents new side effects.
    await db.exec("update auth.oauth_consents set revoked_at=now()");
    assert.equal((await status(liveId)).status,"leased",
      "an already-issued lease must not be falsely reported as safely cancelled");
    assert.equal(await start(job),false,"revoked OAuth denies start");
    assert.equal(await renew(job),null,"revoked OAuth denies lease renewal");
    await db.exec("update auth.oauth_consents set revoked_at=null");
    assert.equal(await start(job),true);
    assert.ok(await renew(job),"an authorized running action can renew");
    await db.query("update public.ordax_remote_capability_grants set state='revoked' where grant_id=$1",[grant]);
    assert.equal((await status(liveId)).status,"running",
      "running work retains truthful execution state after revocation");
    assert.equal(await renew(job),null,"grant revocation halts new lease authority");
    await db.query("update public.ordax_remote_capability_grants set state='active' where grant_id=$1",[grant]);
    await db.query("update auth.users set id=$1 where id=$2",[randomUUID(),owner]);
    assert.equal(await renew(job),null,"ineligible owner cannot renew action");
    // Restore the test owner and revoke the ORIGINAL grant while introducing
    // a different eligible grant. The old queued command cannot inherit it.
    await db.query("update auth.users set id=$1",[owner]);
    await db.query("update public.ordax_remote_capability_grants set state='revoked' where grant_id=$1",[grant]);
    await db.query(`insert into public.ordax_remote_capability_grants
      values($1,$2,null,null,$3,'product-mcp',$4,'computer.windows','read',
        'device','active',now()+interval '1 hour')`,[otherGrant,owner,device,client]);
    assert.equal((await claim()).job,null,
      "replacing an old grant must not authorize its queued request");
    assert.equal((await status(nextId)).status,"cancelled",
      "replacement grant cannot resurrect a queued command bound to a revoked grant");
    assert.equal((await status(nextId)).error_code,"action_authority_revoked");
    assert.equal(await renew(job),null,
      "new grant must not resurrect the original running lease");
    // The reporting RPC is deliberately not redefined. Already-executed
    // effects preserve fenced, late terminal receipt/recovery semantics.
    assert.doesNotMatch(queuedRevocation,/create or replace function public\.ordax_report_product_action_v1/i);
    assert.match(queuedRevocation,/r\.status = 'queued'/);
    assert.match(queuedRevocation,/r\.attempt_id is null/);
    assert.match(queuedRevocation,/r\.started_at is null/);
    assert.match(queuedRevocation,/r\.expires_at > pg_catalog\.clock_timestamp\(\)/);
    assert.equal((await db.query(
      "select has_function_privilege('ordax_edge_executor','private.ordax_retire_unauthorized_queued_product_actions_v1(uuid,uuid)','EXECUTE') as allowed",
    )).rows[0].allowed,false,"internal helper is not a new public executor");
    for(const signature of [
      "public.ordax_get_product_action_v1(uuid,text,text,uuid)",
      "public.ordax_claim_product_action_v1(uuid,uuid,text,integer)",
      "public.ordax_start_product_action_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text)",
      "public.ordax_renew_product_action_lease_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,integer)",
    ]){
      for(const role of ["anon","authenticated","service_role"]){
        assert.equal((await db.query(
          "select has_function_privilege($1,$2,'EXECUTE') as allowed",[role,signature],
        )).rows[0].allowed,false,role + " must not execute " + signature);
      }
      assert.equal((await db.query(
        "select has_function_privilege('ordax_edge_executor',$1,'EXECUTE') as allowed",
        [signature],
      )).rows[0].allowed,true);
    }
  } finally {
    await db.close();
  }
});
