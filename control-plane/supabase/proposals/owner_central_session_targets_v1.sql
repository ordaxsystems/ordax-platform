-- Candidate only: read-only Owner visibility into the existing Central grant authority.
-- This is NOT a migration and MUST NOT be deployed before review/approval.
-- Runtime attestation and signed MCP session marker remain the only binding path.
begin;

do $preflight$ begin
  if to_regprocedure('private.ordax_central_device_grant_eligible_v1(uuid,text,uuid)') is null
    or to_regprocedure('private.ordax_product_presence_online_v1(boolean,timestamptz,timestamptz)') is null
    or to_regclass('public.ordax_product_devices') is null
    or to_regclass('public.ordax_device_presence') is null
    or not exists(select 1 from pg_roles where rolname='ordax_edge_executor')
  then raise exception 'owner_central_preflight_dependencies_missing'; end if;
end; $preflight$;

create function public.ordax_owner_central_session_targets_v1(
  p_owner_user_id uuid, p_client_id text
)
returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_count bigint;
  v_targets jsonb;
begin
  if p_owner_user_id is null or p_client_id is null
    or p_client_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    or not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
  then return jsonb_build_object('ok',false,'error','owner_central_targets_invalid'); end if;

  -- The Owner signed in, but may inspect ONLY an explicitly consented OAuth client.
  if not exists (
    select 1 from auth.oauth_consents c
    join auth.oauth_clients client on client.id=c.client_id and client.deleted_at is null
    where c.user_id=p_owner_user_id and c.client_id=p_client_id::uuid
      and c.revoked_at is null
  ) then return jsonb_build_object('ok',false,'error','owner_central_client_not_consented'); end if;

  -- No second grant predicate. Opening and resolving sessions still own authority.
  select count(*),coalesce(jsonb_agg(jsonb_build_object(
    'device_id',d.device_id,
    'reported_online',coalesce(private.ordax_product_presence_online_v1(
      p.online,p.last_seen_at,v_now),false),
    'runtime_ready',coalesce(private.ordax_product_presence_online_v1(
      p.online,p.last_seen_at,v_now),false)
      and p.agent_version is not null
      and p.capability_digest ~ '^[0-9a-f]{64}$'
  ) order by d.device_id),'[]'::jsonb)
  into v_count,v_targets
  from public.ordax_product_devices d
  left join public.ordax_device_presence p on p.device_id=d.device_id
  where d.owner_user_id=p_owner_user_id and d.state='active'
    and private.ordax_central_device_grant_eligible_v1(
      p_owner_user_id,p_client_id,d.device_id);

  -- A bounded response; never truncate a candidate set into a false single selection.
  if v_count>25 then
    return jsonb_build_object('ok',false,'error','owner_central_target_list_too_large');
  end if;
  return jsonb_build_object(
    'ok',true,'client_id',p_client_id,
    'eligible_device_count',v_count,
    'state',case when v_count=0 then 'no_action_grant'
      when v_count=1 then 'single_granted_target' else 'owner_selection_required' end,
    'targets',v_targets,
    'attested',false,'dispatch_authorized',false,
    'owner_choice_performed',false
  );
end;
$$;

revoke all on function public.ordax_owner_central_session_targets_v1(uuid,text)
  from public,anon,authenticated,service_role;
grant execute on function public.ordax_owner_central_session_targets_v1(uuid,text)
  to ordax_edge_executor;
commit;
