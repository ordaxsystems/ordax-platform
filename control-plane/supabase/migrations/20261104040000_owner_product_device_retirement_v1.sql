-- Exact Owner DEV device retirement. No shadow registry or credential storage.
-- Disabled at the HTTP boundary until the Owner explicitly approves rollout.
begin;

do $guard$
begin
  if to_regclass('public.ordax_product_devices') is null
     or to_regclass('public.ordax_device_presence') is null
     or to_regclass('public.ordax_remote_capability_grants') is null
     or to_regclass('private.ordax_product_device_credentials') is null
     or to_regclass('private.ordax_product_action_requests') is null
     or to_regprocedure('private.ordax_trusted_actor_auth_eligible_v1(uuid)') is null
     or to_regprocedure('private.ordax_product_presence_online_v1(boolean,timestamptz,timestamptz)') is null
     or to_regprocedure('public.ordax_owner_mcp_devices_v1(uuid)') is null
     or not exists (select 1 from pg_roles where rolname='ordax_edge_executor')
  then raise exception 'owner_product_device_retirement_preflight_failed'; end if;
end;
$guard$;

create function public.ordax_retire_owner_product_device_v1(
  p_owner_user_id uuid,
  p_device_id uuid
) returns jsonb
language plpgsql security definer set search_path = ''
as $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_device public.ordax_product_devices%rowtype;
  v_grants integer := 0;
begin
  if p_owner_user_id is null or p_device_id is null
      or not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return pg_catalog.jsonb_build_object('ok',false,'error','owner_auth_ineligible');
  end if;

  -- Lock the exact device; caller never supplies an Owner ID on the HTTP route.
  select * into v_device from public.ordax_product_devices
    where device_id=p_device_id and owner_user_id=p_owner_user_id
    for update;
  if not found then
    return pg_catalog.jsonb_build_object('ok',false,'error','owner_device_not_found');
  end if;
  if v_device.state='revoked' then
    return pg_catalog.jsonb_build_object('ok',true,'retired',true,
      'already_retired',true,'device_id',p_device_id);
  end if;
  -- No production/stable retirement through this DEV operation.
  if v_device.state<>'active' or v_device.channel<>'development' then
    return pg_catalog.jsonb_build_object('ok',false,'error','owner_device_retire_forbidden');
  end if;

  -- A recently present computer must never be erased by bulk cleanup.
  if exists (
    select 1 from public.ordax_device_presence p where p.device_id=p_device_id
      and private.ordax_product_presence_online_v1(p.online,p.last_seen_at,v_now)
  ) then
    return pg_catalog.jsonb_build_object('ok',false,'error','owner_device_still_online');
  end if;
  if exists (
    select 1 from private.ordax_product_action_requests a
      where a.device_id=p_device_id and a.status in ('queued','leased','running')
        and a.expires_at>v_now
  ) then
    return pg_catalog.jsonb_build_object('ok',false,'error','owner_device_active_actions');
  end if;

  -- A single transaction invalidates EVERY OAuth client's access only to
  -- this device, plus the device's own credential. Other devices are untouched.
  update public.ordax_remote_capability_grants
    set state='revoked',updated_at=v_now
    where device_id=p_device_id and owner_user_id=p_owner_user_id
      and state='active';
  get diagnostics v_grants = row_count;

  update private.ordax_product_device_credentials
    set revoked_at=v_now where device_id=p_device_id;

  update public.ordax_product_devices
    set state='revoked',updated_at=v_now
    where device_id=p_device_id and owner_user_id=p_owner_user_id;

  update public.ordax_device_presence
    set online=false, observed_at=v_now where device_id=p_device_id;

  return pg_catalog.jsonb_build_object(
    'ok',true,'retired',true,'already_retired',false,
    'device_id',p_device_id,'grants_revoked',v_grants
  );
end;
$function$;

revoke all on function public.ordax_retire_owner_product_device_v1(uuid,uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.ordax_retire_owner_product_device_v1(uuid,uuid)
  to ordax_edge_executor;

-- The registry's public Owner inventory is active devices only. Revocation
-- is canonical (state+credential+grants), not a UI-only hidden-device filter.
create or replace function public.ordax_owner_mcp_devices_v1(
  p_owner_user_id uuid
) returns jsonb
language plpgsql stable security definer set search_path = ''
as $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_count integer;
  v_devices jsonb;
begin
  if p_owner_user_id is null
      or not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return pg_catalog.jsonb_build_object('ok',false,'error','owner_auth_ineligible');
  end if;
  select count(*) into v_count from (
    select 1 from public.ordax_product_devices d
      where d.owner_user_id=p_owner_user_id and d.state='active' limit 201
  ) limited;
  if v_count>200 then
    return pg_catalog.jsonb_build_object('ok',false,'error','owner_devices_limit_exceeded');
  end if;
  select coalesce(pg_catalog.jsonb_agg(
    pg_catalog.jsonb_build_object(
      'device_id',d.device_id,'name',d.display_name,'kind',d.device_kind,
      'channel',d.channel,'state',d.state,
      'online',coalesce(private.ordax_product_presence_online_v1(
        p.online,p.last_seen_at,v_now),false),
      'last_seen_at',p.last_seen_at,
      'runtime_ready',coalesce(private.ordax_product_presence_online_v1(
        p.online,p.last_seen_at,v_now)
        and p.agent_version is not null
        and p.capability_digest ~ '^[0-9a-f]{64}$',false)
    ) order by d.display_name,d.device_id
  ),'[]'::jsonb)
  into v_devices
  from public.ordax_product_devices d
  left join public.ordax_device_presence p on p.device_id=d.device_id
  where d.owner_user_id=p_owner_user_id and d.state='active';

  return pg_catalog.jsonb_build_object(
    'ok',true,'schema','ordax.owner-mcp-devices/1',
    'devices',v_devices,'count',v_count
  );
end;
$function$;
revoke all on function public.ordax_owner_mcp_devices_v1(uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.ordax_owner_mcp_devices_v1(uuid)
  to ordax_edge_executor;

commit;
