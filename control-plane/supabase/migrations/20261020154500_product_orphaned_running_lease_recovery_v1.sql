-- Recover orphaned already-running Product MCP jobs, preserving exactly-once
-- dispatch fencing and allowing a late report for the original attempt only.
-- No timer/second queue/alternate executor. Same Product PostgreSQL RPCs.
begin;

create or replace function private.ordax_retire_orphaned_running_product_actions_v1(
  p_device_id uuid,
  p_request_id uuid default null
)
returns integer
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_count integer := 0;
begin
  if p_device_id is null then return 0; end if;
  -- Five minutes AFTER the original lease deadline, not five minutes
  -- after execution began. An active agent can renew its fenced lease.
  -- A crashed agent must not reserve the whole device indefinitely.
  with retired as (
    update private.ordax_product_action_requests r
       set status = 'failed',
           error_code = 'execution_outcome_unconfirmed',
           finished_at = pg_catalog.clock_timestamp(),
           lease_expires_at = null
     where r.device_id = p_device_id
       and (p_request_id is null or r.request_id = p_request_id)
       and r.status = 'running'
       and r.report_id is null
       and r.lease_expires_at is not null
       and r.lease_expires_at < pg_catalog.clock_timestamp() - interval '5 minutes'
     returning r.*
  )
  insert into private.ordax_product_action_audit(
    request_id, owner_user_id, space_id, project_id, device_id, grant_id,
    client_kind, capability, access_mode, phase, decision, reason, result_ok
  )
  select
    r.request_id, r.owner_user_id, r.space_id, r.project_id,
    r.device_id, r.grant_id, r.client_kind, r.capability,
    r.access_mode, 'result', 'deny', 'execution_outcome_unconfirmed', false
    from retired r;
  get diagnostics v_count = row_count;
  return v_count;
end;
$function$;
revoke all on function private.ordax_retire_orphaned_running_product_actions_v1(uuid,uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;

CREATE OR REPLACE FUNCTION public.ordax_get_product_action_v1(p_owner_user_id uuid, p_client_kind text, p_client_id text, p_request_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_device_id uuid;
  v_response jsonb;
begin
  -- Never mutate or reveal an action until all existing owner and exact
  -- OAuth client checks pass. No arbitrary-ID expiry side channel.
  if p_owner_user_id is null
     or p_request_id is null
     or p_client_kind not in ('ordax-web','ordax-mobile','product-mcp')
     or p_client_id is null
     or char_length(p_client_id) not between 8 and 160
     or p_client_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
  then
    return null;
  end if;

  select r.device_id into v_device_id
    from private.ordax_product_action_requests r
   where r.owner_user_id = p_owner_user_id
     and r.client_kind = p_client_kind
     and r.client_id = p_client_id
     and r.request_id = p_request_id;

  if not found then return null; end if;

  perform private.ordax_expire_queued_product_actions_v1(v_device_id, p_request_id);
  perform private.ordax_retire_orphaned_running_product_actions_v1(v_device_id, p_request_id);

  select pg_catalog.jsonb_build_object(
    'ok', true,
    'request_id', r.request_id,
    'device_id', r.device_id,
    'project_id', r.project_id,
    'capability', r.capability,
    'status', r.status,
    'effect_id', r.effect_id,
    'result', r.result,
    'error_code', r.error_code,
    'execution_runtime_kind', r.execution_runtime_kind,
    'execution_agent_version', r.execution_agent_version,
    'created_at', r.created_at,
    'started_at', r.started_at,
    'finished_at', r.finished_at
  ) into v_response
    from private.ordax_product_action_requests r
   where r.owner_user_id = p_owner_user_id
     and r.client_kind = p_client_kind
     and r.client_id = p_client_id
     and r.request_id = p_request_id;

  return v_response;
end;
$function$;

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

  -- Clear only never-leased actions, never running/leased work: the latter
  -- requires lease/fencing rules to avoid duplicate side effects.
  perform private.ordax_expire_queued_product_actions_v1(p_device_id, null);
  perform private.ordax_retire_orphaned_running_product_actions_v1(p_device_id, null);

  if exists (
    select 1
      from private.ordax_product_action_requests r
     where r.device_id = p_device_id
       and (
         r.status = 'running'
         or (r.status = 'leased' and r.lease_expires_at >= v_now)
       )
  ) then
    return pg_catalog.jsonb_build_object('ok', true, 'job', null);
  end if;

  select * into v_job
    from private.ordax_product_action_requests r
   where r.device_id = p_device_id
     and r.expires_at > pg_catalog.clock_timestamp()
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
$function$;

CREATE OR REPLACE FUNCTION public.ordax_report_product_action_v1(p_device_id uuid, p_request_id uuid, p_effect_id uuid, p_attempt_id uuid, p_lease_id uuid, p_execution_epoch bigint, p_agent_instance_id uuid, p_boot_id text, p_report_id uuid, p_status text, p_result jsonb, p_result_sha256 text, p_error_code text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_row private.ordax_product_action_requests%rowtype;
  v_late_original_report boolean := false;
begin
  if p_status not in ('succeeded','failed','cancelled')
     or p_result is null
     or pg_catalog.octet_length(p_result::text) > 524288
     or p_result_sha256 is null
     or p_result_sha256 !~ '^[0-9a-f]{64}$'
     or (p_error_code is not null and char_length(p_error_code) > 120)
  then
    return jsonb_build_object('ok', false, 'error', 'report_invalid');
  end if;

  select *
    into v_row
    from private.ordax_product_action_requests
   where request_id = p_request_id
     and device_id = p_device_id
   for update;

  if not found then
    return jsonb_build_object('ok', false, 'error', 'product_action_not_found');
  end if;

  -- A lost Runtime can recover a persisted terminal report after the five-
  -- minute orphan grace. Reconcile ONLY the original fenced attempt; never
  -- reclaim or re-execute that command on another agent.
  v_late_original_report := coalesce(
    v_row.status = 'failed'
    and v_row.error_code = 'execution_outcome_unconfirmed'
    and v_row.report_id is null
    and v_row.effect_id = p_effect_id
    and v_row.attempt_id = p_attempt_id
    and v_row.lease_id = p_lease_id
    and v_row.execution_epoch = p_execution_epoch
    and v_row.agent_instance_id = p_agent_instance_id
    and v_row.boot_id = p_boot_id, false);

  if v_row.status in ('succeeded','failed','cancelled') and not v_late_original_report then
    if v_row.effect_id = p_effect_id
       and v_row.attempt_id = p_attempt_id
       and v_row.lease_id = p_lease_id
       and v_row.execution_epoch = p_execution_epoch
       and v_row.agent_instance_id = p_agent_instance_id
       and v_row.boot_id = p_boot_id
       and v_row.report_id = p_report_id
       and v_row.status = p_status
       and v_row.result_sha256 = pg_catalog.lower(p_result_sha256)
       and v_row.result = p_result
       and v_row.error_code is not distinct from p_error_code
    then
      return jsonb_build_object('ok', true, 'replayed', true, 'status', v_row.status);
    end if;
    return jsonb_build_object('ok', false, 'error', 'terminal_report_conflict');
  end if;

  if v_row.effect_id <> p_effect_id
     or v_row.attempt_id <> p_attempt_id
     or v_row.lease_id <> p_lease_id
     or v_row.execution_epoch <> p_execution_epoch
     or v_row.agent_instance_id <> p_agent_instance_id
     or v_row.boot_id <> p_boot_id
     or (v_row.status not in ('leased','running') and not v_late_original_report)
     or v_row.report_id is not null
  then
    return jsonb_build_object('ok', false, 'error', 'lease_not_active');
  end if;

  update private.ordax_product_action_requests
     set status = p_status,
         report_id = p_report_id,
         result = p_result,
         result_sha256 = pg_catalog.lower(p_result_sha256),
         error_code = p_error_code,
         finished_at = v_now,
         lease_expires_at = null
   where request_id = p_request_id;

  insert into private.ordax_product_action_audit(
    request_id, owner_user_id, space_id, project_id, device_id, grant_id,
    client_kind, capability, access_mode, phase, decision, reason, result_ok
  ) values (
    v_row.request_id, v_row.owner_user_id, v_row.space_id, v_row.project_id,
    v_row.device_id, v_row.grant_id, v_row.client_kind, v_row.capability,
    v_row.access_mode, 'result', 'allow', 'terminal_report_committed',
    p_status = 'succeeded'
  );

  return jsonb_build_object(
    'ok', true,
    'replayed', false,
    'status', p_status,
    'result_sha256', pg_catalog.lower(p_result_sha256)
  );
end;
$function$;

revoke all on function public.ordax_get_product_action_v1(uuid,text,text,uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;
grant execute on function public.ordax_get_product_action_v1(uuid,text,text,uuid)
  to ordax_edge_executor;
revoke all on function public.ordax_claim_product_action_v1(uuid,uuid,text,integer)
  from public, anon, authenticated, service_role, ordax_edge_executor;
grant execute on function public.ordax_claim_product_action_v1(uuid,uuid,text,integer)
  to ordax_edge_executor;
revoke all on function public.ordax_report_product_action_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid,text,jsonb,text,text)
  from public, anon, authenticated, service_role, ordax_edge_executor;
grant execute on function public.ordax_report_product_action_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid,text,jsonb,text,text)
  to ordax_edge_executor;

commit;
