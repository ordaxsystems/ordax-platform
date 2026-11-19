-- Device-attested capacity: old runtimes remain on their actual 4 workers.
-- New runtimes advertise up to 32 independent worker slots via the existing
-- authenticated device heartbeat. Claim and enqueue share one SQL authority.
begin;

alter table public.ordax_device_presence
  add column max_concurrent_jobs integer,
  add column remote_capacity_reported_at timestamptz;
alter table public.ordax_device_presence
  add constraint ordax_device_presence_remote_capacity_check
  check (max_concurrent_jobs is null or max_concurrent_jobs between 1 and 32);

create or replace function private.ordax_product_remote_capacity_v1(p_device_id uuid)
returns integer
language sql stable security invoker set search_path to ''
as $capacity$
 select coalesce((
   select p.max_concurrent_jobs from public.ordax_device_presence p
   where p.device_id = p_device_id
     and private.ordax_product_presence_online_v1(
       p.online, p.last_seen_at, pg_catalog.clock_timestamp()
     )
     and p.max_concurrent_jobs between 1 and 32
     and p.remote_capacity_reported_at >
       pg_catalog.statement_timestamp() - interval '6 minutes'
 ), private.ordax_product_remote_capacity_v1());
$capacity$;
revoke all on function private.ordax_product_remote_capacity_v1(uuid)
 from public, anon, authenticated, service_role, ordax_edge_executor;

-- This RPC is callable only by the existing authenticated Device Worker
-- transport; it uses the same short per-device claim/admission transaction lock.
create or replace function public.ordax_record_product_capacity_v1(
 p_device_id uuid, p_max_concurrent_jobs integer
) returns boolean
language plpgsql security definer set search_path to ''
as $function$
declare
 v_count integer;
begin
 if p_device_id is null or p_max_concurrent_jobs is null
    or p_max_concurrent_jobs not between 1 and 32 then return false; end if;
 perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext(p_device_id::text));
 update public.ordax_device_presence p
    set max_concurrent_jobs = p_max_concurrent_jobs,
        remote_capacity_reported_at = pg_catalog.clock_timestamp()
  where p.device_id = p_device_id
    and private.ordax_product_presence_online_v1(
      p.online, p.last_seen_at, pg_catalog.clock_timestamp());
 get diagnostics v_count = row_count;
 return v_count=1;
end;
$function$;
revoke all on function public.ordax_record_product_capacity_v1(uuid,integer)
 from public, anon, authenticated, service_role, ordax_edge_executor;
grant execute on function public.ordax_record_product_capacity_v1(uuid,integer)
 to ordax_edge_executor;

CREATE OR REPLACE FUNCTION public.ordax_enqueue_product_action_v1(p_owner_user_id uuid, p_space_id uuid, p_project_id uuid, p_device_id uuid, p_client_kind text, p_client_id text, p_capability text, p_access_mode text, p_payload jsonb, p_idempotency_key text, p_expires_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_grant_id uuid;
  v_payload_sha256 text;
  v_existing private.ordax_product_action_requests%rowtype;
  v_request_id uuid;
  v_effect_id uuid;
  v_device_online boolean;
  v_pending_count integer := 0;
  v_admission_now timestamptz;
begin
  if p_owner_user_id is null
     or p_device_id is null
     or p_client_kind not in ('ordax-web','ordax-mobile','product-mcp')
     or p_client_id is null
     or char_length(p_client_id) not between 8 and 160
     or p_client_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
     or p_access_mode not in ('read','write')
     or p_capability is null
     or char_length(p_capability) not between 2 and 120
     or not private.ordax_product_capability_name_valid(p_capability)
     or p_payload is null
     or jsonb_typeof(p_payload) <> 'object'
     or pg_catalog.octet_length(p_payload::text) > 131072
     or p_idempotency_key is null
     or char_length(p_idempotency_key) not between 8 and 128
     or p_idempotency_key !~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
     or p_expires_at is null
     or p_expires_at <= v_now
     or p_expires_at > v_now + interval '24 hours'
  then
    return jsonb_build_object('ok', false, 'error', 'product_action_invalid');
  end if;

  -- The service is responsible for actor-to-caller proof. This DB guard
  -- confirms account eligibility and locks the Auth identity before the
  -- first replay, device enrollment or remote authority mutation.
  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','product_owner_auth_ineligible');
  end if;

  v_payload_sha256 := pg_catalog.encode(
    extensions.digest(pg_catalog.convert_to(p_payload::text, 'UTF8'), 'sha256'),
    'hex'
  );

  select *
    into v_existing
    from private.ordax_product_action_requests
   where owner_user_id = p_owner_user_id
     and idempotency_key = p_idempotency_key
   limit 1;

  if found then
    if v_existing.space_id is not distinct from p_space_id
       and v_existing.project_id is not distinct from p_project_id
       and v_existing.device_id = p_device_id
       and v_existing.client_kind = p_client_kind
       and v_existing.client_id = p_client_id
       and v_existing.capability = p_capability
       and v_existing.access_mode = p_access_mode
       and v_existing.payload_sha256 = v_payload_sha256
    then
      return jsonb_build_object(
        'ok', true,
        'replayed', true,
        'request_id', v_existing.request_id,
        'effect_id', v_existing.effect_id,
        'status', v_existing.status
      );
    end if;

    insert into private.ordax_product_action_audit(
      request_id, owner_user_id, space_id, project_id, device_id, grant_id,
      client_kind, client_id, capability, access_mode, phase, decision, reason
    ) values (
      v_existing.request_id, p_owner_user_id, p_space_id, p_project_id, p_device_id,
      v_existing.grant_id, p_client_kind, p_client_id, p_capability, p_access_mode,
      'decision', 'deny', 'idempotency_conflict'
    );

    return jsonb_build_object('ok', false, 'error', 'idempotency_conflict');
  end if;

  v_grant_id := private.ordax_resolve_product_remote_grant_v1(
    p_owner_user_id,
    p_space_id,
    p_project_id,
    p_device_id,
    p_client_kind,
    p_client_id,
    p_capability,
    p_access_mode
  );

  if v_grant_id is null then
    insert into private.ordax_product_action_audit(
      owner_user_id, space_id, project_id, device_id, client_kind,
      client_id, capability, access_mode, phase, decision, reason
    ) values (
      p_owner_user_id, p_space_id, p_project_id, p_device_id, p_client_kind,
      p_client_id, p_capability, p_access_mode, 'decision', 'deny', 'product_grant_not_resolved'
    );

    return jsonb_build_object('ok', false, 'error', 'product_grant_not_resolved');
  end if;

  -- Admission uses the same canonical freshness predicate as target discovery.
  -- New actions fail fast when their actual executor is offline. Existing
  -- idempotent requests were already returned above, so a write retry can
  -- still retrieve its original receipt without creating another effect.
  select private.ordax_product_presence_online_v1(
           p.online, p.last_seen_at, pg_catalog.clock_timestamp()
         )
    into v_device_online
    from public.ordax_device_presence p
   where p.device_id = p_device_id;

  if not coalesce(v_device_online, false) then
    insert into private.ordax_product_action_audit(
      owner_user_id, space_id, project_id, device_id, grant_id,
      client_kind, client_id, capability, access_mode, phase, decision, reason
    ) values (
      p_owner_user_id, p_space_id, p_project_id, p_device_id, v_grant_id,
      p_client_kind, p_client_id, p_capability, p_access_mode,
      'decision', 'deny', 'product_device_offline'
    );
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'product_device_offline'
    );
  end if;

  -- The canonical claim RPC takes this same short per-device advisory lock.
  -- Count ALL outstanding work (including not-yet-claimed requests) while
  -- holding it, so parallel independent clients cannot silently overbook the
  -- four remote workers. The lock is released at transaction end; actual
  -- device execution remains parallel and never holds it.
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext(p_device_id::text));
  v_admission_now := pg_catalog.clock_timestamp();
  perform private.ordax_expire_queued_product_actions_v1(p_device_id, null);
  -- Reclaim never-started requests whose grants were revoked before
  -- calculating capacity. The claim RPC already invokes this same helper;
  -- admission must not report busy while unauthorized queued work holds slots.
  perform private.ordax_retire_unauthorized_queued_product_actions_v1(p_device_id, null);
  perform private.ordax_retire_orphaned_running_product_actions_v1(p_device_id, null);
  select pg_catalog.count(*)::integer
    into v_pending_count
    from private.ordax_product_action_requests r
   where r.device_id = p_device_id
     and (
       (r.status = 'queued' and r.expires_at > v_admission_now)
       or (
         r.status = 'leased'
         and (
           r.expires_at > v_admission_now
           or r.lease_expires_at >= v_admission_now
         )
       )
       or (r.status = 'running' and r.lease_expires_at >= v_admission_now)
     );

  if v_pending_count >= private.ordax_product_remote_capacity_v1(p_device_id) then
    insert into private.ordax_product_action_audit(
      owner_user_id, space_id, project_id, device_id, grant_id,
      client_kind, client_id, capability, access_mode, phase, decision, reason
    ) values (
      p_owner_user_id, p_space_id, p_project_id, p_device_id, v_grant_id,
      p_client_kind, p_client_id, p_capability, p_access_mode,
      'decision', 'deny', 'product_device_busy'
    );
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'product_device_busy'
    );
  end if;

  v_request_id := extensions.gen_random_uuid();
  v_effect_id := extensions.gen_random_uuid();

  insert into private.ordax_product_action_requests(
    request_id, owner_user_id, space_id, project_id, device_id, grant_id,
    client_kind, client_id, capability, access_mode, payload, payload_sha256,
    idempotency_key, effect_id, status, expires_at
  ) values (
    v_request_id, p_owner_user_id, p_space_id, p_project_id, p_device_id, v_grant_id,
    p_client_kind, p_client_id, p_capability, p_access_mode, p_payload, v_payload_sha256,
    p_idempotency_key, v_effect_id, 'queued', p_expires_at
  );

  insert into private.ordax_product_action_audit(
    request_id, owner_user_id, space_id, project_id, device_id, grant_id,
    client_kind, client_id, capability, access_mode, phase, decision, reason
  ) values (
    v_request_id, p_owner_user_id, p_space_id, p_project_id, p_device_id, v_grant_id,
    p_client_kind, p_client_id, p_capability, p_access_mode, 'decision', 'allow', 'grant_resolved'
  );

  return jsonb_build_object(
    'ok', true,
    'replayed', false,
    'request_id', v_request_id,
    'effect_id', v_effect_id,
    'status', 'queued'
  );
end;
$function$

;
revoke all on function public.ordax_enqueue_product_action_v1(uuid,uuid,uuid,uuid,text,text,text,text,jsonb,text,timestamptz)
 from public, anon, authenticated, service_role, ordax_edge_executor;
grant execute on function public.ordax_enqueue_product_action_v1(uuid,uuid,uuid,uuid,text,text,text,text,jsonb,text,timestamptz)
 to ordax_edge_executor;

CREATE OR REPLACE FUNCTION public.ordax_claim_product_action_v1(p_device_id uuid, p_agent_instance_id uuid, p_boot_id text, p_lease_seconds integer DEFAULT 120)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_now timestamptz;
  v_job private.ordax_product_action_requests%rowtype;
  v_attempt_id uuid;
  v_lease_id uuid;
  v_lease_expires_at timestamptz;
  v_active_count integer := 0;
  v_max_concurrent integer := private.ordax_product_remote_capacity_v1(p_device_id);
begin
  if p_device_id is null
     or p_agent_instance_id is null
     or p_boot_id is null
     or char_length(p_boot_id) not between 8 and 160
     or p_lease_seconds not between 30 and 300
  then
    return pg_catalog.jsonb_build_object('ok', false, 'error', 'claim_invalid');
  end if;

  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext(p_device_id::text));
  v_now := pg_catalog.clock_timestamp();

  perform private.ordax_expire_queued_product_actions_v1(p_device_id, null);
  perform private.ordax_retire_unauthorized_queued_product_actions_v1(p_device_id, null);
  perform private.ordax_retire_orphaned_running_product_actions_v1(p_device_id, null);

  select pg_catalog.count(*)::integer
    into v_active_count
    from private.ordax_product_action_requests r
   where r.device_id = p_device_id
     and (
       r.status = 'running'
       or (r.status = 'leased' and r.lease_expires_at >= v_now)
     );

  if v_active_count >= v_max_concurrent then
    return pg_catalog.jsonb_build_object('ok', true, 'job', null);
  end if;

  select * into v_job
    from private.ordax_product_action_requests r
   where r.device_id = p_device_id
     and r.expires_at > pg_catalog.clock_timestamp()
     and private.ordax_product_action_grant_current_v1(r.request_id)
     and (
       r.status = 'queued'
       or (r.status = 'leased' and r.lease_expires_at < v_now)
     )
   order by r.created_at asc
   for update skip locked
   limit 1;

  if not found then
    return pg_catalog.jsonb_build_object('ok', true, 'job', null);
  end if;

  v_attempt_id := extensions.gen_random_uuid();
  v_lease_id := extensions.gen_random_uuid();
  v_lease_expires_at := pg_catalog.clock_timestamp()
    + pg_catalog.make_interval(secs => p_lease_seconds);

  update private.ordax_product_action_requests
     set status = 'leased',
         attempt_id = v_attempt_id,
         lease_id = v_lease_id,
         execution_epoch = execution_epoch + 1,
         agent_instance_id = p_agent_instance_id,
         boot_id = p_boot_id,
         lease_expires_at = v_lease_expires_at
   where request_id = v_job.request_id
     and status in ('queued','leased')
     and expires_at > pg_catalog.clock_timestamp()
   returning * into v_job;

  if not found then
    return pg_catalog.jsonb_build_object('ok', true, 'job', null);
  end if;

  return pg_catalog.jsonb_build_object(
    'ok', true,
    'job', pg_catalog.jsonb_build_object(
      'request_id', v_job.request_id,
      'device_id', v_job.device_id,
      'project_id', v_job.project_id,
      'capability', v_job.capability,
      'payload', v_job.payload,
      'payload_sha256', v_job.payload_sha256,
      'effect_id', v_job.effect_id,
      'attempt_id', v_job.attempt_id,
      'lease_id', v_job.lease_id,
      'execution_epoch', v_job.execution_epoch,
      'agent_instance_id', v_job.agent_instance_id,
      'boot_id', v_job.boot_id,
      'lease_expires_at', v_job.lease_expires_at
    )
  );
end;
$function$

;
revoke all on function public.ordax_claim_product_action_v1(uuid,uuid,text,integer)
 from public, anon, authenticated, service_role, ordax_edge_executor;
grant execute on function public.ordax_claim_product_action_v1(uuid,uuid,text,integer)
 to ordax_edge_executor;

commit;
