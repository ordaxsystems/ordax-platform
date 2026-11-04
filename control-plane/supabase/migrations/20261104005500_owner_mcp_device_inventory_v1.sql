-- Owner-only device inventory for the existing MCP authorization panel.
-- Reuses canonical device identity/presence; NEVER creates a shadow device or grant table.
-- Only the already-trusted Worker/edge actor can execute this function.
begin;

do $guard$
begin
  if to_regclass('public.ordax_product_devices') is null
     or to_regclass('public.ordax_device_presence') is null
     or to_regprocedure('private.ordax_trusted_actor_auth_eligible_v1(uuid)') is null
     or to_regprocedure('private.ordax_product_presence_online_v1(boolean,timestamptz,timestamptz)') is null
     or not exists (select 1 from pg_roles where rolname='ordax_edge_executor')
     or to_regprocedure('public.ordax_owner_mcp_devices_v1(uuid)') is not null
  then raise exception 'owner_mcp_device_inventory_preflight_failed'; end if;
end;
$guard$;

create function public.ordax_owner_mcp_devices_v1(
  p_owner_user_id uuid
) returns jsonb
language plpgsql stable security definer set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_count integer;
  v_devices jsonb;
begin
  -- The signed Owner subject is provided by the canonical Worker; SQL
  -- independently verifies eligibility and filters *every* row by owner.
  if p_owner_user_id is null
    or not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
  then
    return jsonb_build_object('ok',false,'error','owner_auth_ineligible');
  end if;

  -- This is an administrative page, not an unbounded account export.
  select count(*) into v_count
  from (
    select 1 from public.ordax_product_devices d
    where d.owner_user_id=p_owner_user_id
    limit 201
  ) limited;
  if v_count>200 then
    return jsonb_build_object('ok',false,'error','owner_devices_limit_exceeded');
  end if;

  select coalesce(pg_catalog.jsonb_agg(
    pg_catalog.jsonb_build_object(
      'device_id',d.device_id,
      'name',d.display_name,
      'kind',d.device_kind,
      'channel',d.channel,
      'state',d.state,
      'online',coalesce(
        private.ordax_product_presence_online_v1(p.online,p.last_seen_at,v_now),false
      ),
      'last_seen_at',p.last_seen_at,
      'runtime_ready',coalesce(
        private.ordax_product_presence_online_v1(p.online,p.last_seen_at,v_now)
          and p.agent_version is not null
          and p.capability_digest ~ '^[0-9a-f]{64}$',
        false
      )
    ) order by d.display_name,d.device_id
  ), '[]'::jsonb)
  into v_devices
  from public.ordax_product_devices d
  left join public.ordax_device_presence p on p.device_id=d.device_id
  where d.owner_user_id=p_owner_user_id;

  return pg_catalog.jsonb_build_object(
    'ok',true,'schema','ordax.owner-mcp-devices/1',
    'devices',v_devices,'count',v_count
  );
end;
$$;

revoke all on function public.ordax_owner_mcp_devices_v1(uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.ordax_owner_mcp_devices_v1(uuid)
  to ordax_edge_executor;

commit;
