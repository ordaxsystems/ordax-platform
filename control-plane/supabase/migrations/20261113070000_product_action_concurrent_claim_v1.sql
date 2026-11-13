begin;

-- The Native Runtime owns resource-level conflict serialization. The Product
-- transport must not collapse the whole device back to a single execution lane.
-- Keep claim atomic per device and bounded, while every action retains its
-- independent attempt/lease/execution-epoch fencing.
create or replace function public.ordax_claim_product_action_v1(
  p_device_id uuid,
  p_agent_instance_id uuid,
  p_boot_id text,
  p_lease_seconds integer default 120
)
returns jsonb
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_now timestamptz;
  v_job private.ordax_product_action_requests%rowtype;
  v_attempt_id uuid;
  v_lease_id uuid;
  v_lease_expires_at timestamptz;
  v_active_count integer := 0;
  v_max_concurrent integer := 4;
begin
  if p_device_id is null
     or p_agent_instance_id is null
     or p_boot_id is null
     or char_length(p_boot_id) not between 8 and 160
     or p_lease_seconds not between 30 and 300
  then
    return pg_catalog.jsonb_build_object('ok', false, 'error', 'claim_invalid');
  end if;

  -- Serialize only the short claim transaction. Running work never owns this
  -- lock, so later claims can select other rows immediately.
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext(p_device_id::text));
  v_now := pg_catalog.clock_timestamp();

  perform private.ordax_expire_queued_product_actions_v1(p_device_id, null);
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
