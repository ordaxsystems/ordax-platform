-- Terminalize Product actions whose queue deadline elapsed before any lease.
-- A claim already refuses expired queued actions, but without a lifecycle
-- transition status polling advertises "queued" indefinitely.
-- This is the existing Product PostgreSQL authority; no new queue or worker.
begin;

create or replace function private.ordax_expire_queued_product_actions_v1(
  p_device_id uuid,
  p_request_id uuid default null
)
returns integer
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_count integer;
begin
  if p_device_id is null then return 0; end if;

  with expired as (
    update private.ordax_product_action_requests r
       set status = 'failed',
           error_code = 'action_expired',
           finished_at = pg_catalog.clock_timestamp()
     where r.device_id = p_device_id
       and (p_request_id is null or r.request_id = p_request_id)
       and r.status = 'queued'
       and r.expires_at <= pg_catalog.clock_timestamp()
     returning r.request_id
  )
  select count(*) into v_count from expired;

  return v_count;
end;
$function$;

-- The helper is only used inside the existing security-definer RPCs.
revoke all on function private.ordax_expire_queued_product_actions_v1(uuid,uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;

create or replace function public.ordax_get_product_action_v1(
  p_owner_user_id uuid,
  p_client_kind text,
  p_client_id text,
  p_request_id uuid
)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $function$
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

-- Preserve exact client-scoped read authority. SECURITY DEFINER must not
-- become an anonymous or general authenticated API.
revoke all on function public.ordax_get_product_action_v1(uuid,text,text,uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;
grant execute on function public.ordax_get_product_action_v1(uuid,text,text,uuid)
  to ordax_edge_executor;

create or replace function public.ordax_claim_product_action_v1(
  p_device_id uuid,
  p_agent_instance_id uuid,
  p_boot_id text,
  p_lease_seconds integer default 120
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
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

revoke all on function public.ordax_claim_product_action_v1(uuid,uuid,text,integer)
  from public, anon, authenticated, service_role, ordax_edge_executor;
grant execute on function public.ordax_claim_product_action_v1(uuid,uuid,text,integer)
  to ordax_edge_executor;

commit;
