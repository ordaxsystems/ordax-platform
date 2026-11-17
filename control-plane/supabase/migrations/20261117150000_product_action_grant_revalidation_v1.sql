-- Keep Product action dispatch and lease authority current after grant,
-- OAuth, account or project-binding revocation. Never change terminal report:
-- a previously executed fenced attempt can still reconcile its original receipt.
begin;
do $preflight$
begin
 if to_regprocedure('public.ordax_claim_product_action_v1(uuid,uuid,text,integer)') is null
    or to_regprocedure('public.ordax_start_product_action_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text)') is null
    or to_regprocedure('public.ordax_renew_product_action_lease_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,integer)') is null
    or to_regprocedure('private.ordax_resolve_product_remote_grant_v1(uuid,uuid,uuid,uuid,text,text,text,text)') is null
    or to_regprocedure('private.ordax_trusted_actor_auth_eligible_v1(uuid)') is null
    or to_regclass('private.ordax_product_action_requests') is null
    or not exists(select 1 from pg_roles where rolname='ordax_edge_executor')
 then raise exception 'product_action_grant_revalidation_preflight_failed'; end if;
end;
$preflight$;

create or replace function private.ordax_product_action_grant_current_v1(p_request_id uuid)
returns boolean language sql volatile security invoker set search_path = ''
as $function$
 select exists(
   select 1 from private.ordax_product_action_requests r
   join public.ordax_remote_capability_grants g
     on g.grant_id=r.grant_id
    and g.owner_user_id=r.owner_user_id
    and g.device_id=r.device_id
    and g.client_kind=r.client_kind
    and g.client_id is not distinct from r.client_id
    and g.space_id is not distinct from r.space_id
    and g.project_id is not distinct from r.project_id
    and g.capability=r.capability
    and g.access_mode=r.access_mode
    and g.scope_kind=case when r.project_id is null then 'device' else 'project' end
    and g.state='active'
    and (g.valid_until is null or g.valid_until>pg_catalog.clock_timestamp())
   where r.request_id=p_request_id
     and private.ordax_trusted_actor_auth_eligible_v1(r.owner_user_id)
     and (r.client_kind <> 'product-mcp' or exists(
       select 1 from auth.oauth_consents c
       join auth.oauth_clients client on client.id=c.client_id and client.deleted_at is null
       where c.user_id=r.owner_user_id and c.client_id::text=r.client_id and c.revoked_at is null
     ))
     -- SSOT: the original Product resolver checks current project/device binding.
     and private.ordax_resolve_product_remote_grant_v1(
       r.owner_user_id,r.space_id,r.project_id,r.device_id,
       r.client_kind,r.client_id,r.capability,r.access_mode
     ) is not null
 );
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
$function$;

CREATE OR REPLACE FUNCTION public.ordax_start_product_action_v1(p_device_id uuid, p_request_id uuid, p_effect_id uuid, p_attempt_id uuid, p_lease_id uuid, p_execution_epoch bigint, p_agent_instance_id uuid, p_boot_id text)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
  update private.ordax_product_action_requests
     set status = 'running',
         started_at = coalesce(started_at, pg_catalog.clock_timestamp())
   where request_id = p_request_id
     and device_id = p_device_id
     and effect_id = p_effect_id
     and attempt_id = p_attempt_id
     and lease_id = p_lease_id
     and execution_epoch = p_execution_epoch
     and agent_instance_id = p_agent_instance_id
     and boot_id = p_boot_id
     and status in ('leased','running')
     and report_id is null
     and lease_expires_at >= pg_catalog.clock_timestamp()
     and private.ordax_product_action_grant_current_v1(p_request_id);

  return found;
end;
$function$;

CREATE OR REPLACE FUNCTION public.ordax_renew_product_action_lease_v1(p_device_id uuid, p_request_id uuid, p_effect_id uuid, p_attempt_id uuid, p_lease_id uuid, p_execution_epoch bigint, p_agent_instance_id uuid, p_boot_id text, p_lease_seconds integer DEFAULT 120)
 RETURNS timestamp with time zone
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_until timestamptz;
begin
  if p_lease_seconds not between 30 and 300 then
    return null;
  end if;

  v_until := pg_catalog.clock_timestamp() + pg_catalog.make_interval(secs => p_lease_seconds);

  update private.ordax_product_action_requests
     set lease_expires_at = v_until
   where request_id = p_request_id
     and device_id = p_device_id
     and effect_id = p_effect_id
     and attempt_id = p_attempt_id
     and lease_id = p_lease_id
     and execution_epoch = p_execution_epoch
     and agent_instance_id = p_agent_instance_id
     and boot_id = p_boot_id
     and status in ('leased','running')
     and report_id is null
     and private.ordax_product_action_grant_current_v1(p_request_id);

  if not found then
    return null;
  end if;
  return v_until;
end;
$function$;

revoke all on function private.ordax_product_action_grant_current_v1(uuid)
 from public,anon,authenticated,service_role,ordax_edge_executor;

revoke all on function public.ordax_claim_product_action_v1(uuid,uuid,text,integer) from public,anon,authenticated,service_role;
grant execute on function public.ordax_claim_product_action_v1(uuid,uuid,text,integer) to ordax_edge_executor;
revoke all on function public.ordax_start_product_action_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text) from public,anon,authenticated,service_role;
grant execute on function public.ordax_start_product_action_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text) to ordax_edge_executor;
revoke all on function public.ordax_renew_product_action_lease_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,integer) from public,anon,authenticated,service_role;
grant execute on function public.ordax_renew_product_action_lease_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,integer) to ordax_edge_executor;

commit;

