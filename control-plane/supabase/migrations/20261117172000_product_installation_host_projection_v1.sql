-- Product device targets are Runtime endpoints, not necessarily distinct PCs.
-- Link the Desktop installation to its physical Windows agent using the
-- existing cryptographic machine-binding relation without adding SSOT tables.
-- Physical grouping only improves discovery. Owner selection, OAuth/consent,
-- grants and the exact attested Runtime device_id remain unchanged.
begin;
do $preflight$
begin
  if to_regprocedure('public.ordax_list_product_targets_v1(uuid,text,text)') is null
     or to_regclass('public.ordax_product_devices') is null
     or to_regclass('private.ordax_product_device_credentials') is null
     or to_regprocedure('private.ordax_trusted_actor_auth_eligible_v1(uuid)') is null
     or not exists (select 1 from pg_roles where rolname='ordax_edge_executor')
  then raise exception 'product_installation_host_projection_preflight_failed'; end if;
end;
$preflight$;

create or replace function private.ordax_desktop_installation_host_v1(
  p_device_id uuid
)
returns uuid
language sql
stable
security invoker
set search_path = ''
as $function$
  -- Exact relation already derived by the canonical Runtime device binder.
  -- Never compare names/hostnames, infer from online status, or merge tokens.
  -- Returns a host only for currently active devices owned by the same Owner,
  -- with both existing device credentials still valid.
  select physical.device_id
    from public.ordax_product_devices installed
    join private.ordax_product_device_credentials app_credential
      on app_credential.device_id = installed.device_id
     and app_credential.revoked_at is null
    join public.ordax_product_devices physical
      on physical.owner_user_id = installed.owner_user_id
     and physical.device_id <> installed.device_id
     and physical.state = 'active'
    join private.ordax_product_device_credentials physical_credential
      on physical_credential.device_id = physical.device_id
     and physical_credential.revoked_at is null
   where installed.device_id = p_device_id
     and installed.state = 'active'
     and app_credential.machine_binding_sha256 =
       pg_catalog.encode(extensions.digest(
         pg_catalog.decode('6f726461782e70726f647563742e6465766963652d62696e64696e672f31006f726461782d6465736b746f7000', 'hex')
         || pg_catalog.convert_to(physical_credential.machine_binding_sha256, 'UTF8'),
         'sha256'
       ), 'hex')
   order by physical.device_id
   limit 1;
$function$;

CREATE OR REPLACE FUNCTION public.ordax_list_product_targets_v1(p_owner_user_id uuid, p_client_kind text, p_client_id text)
 RETURNS jsonb
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select case
    -- Auth is owned by Supabase; the Worker must separately authenticate
    -- and bind this service-supplied owner ID to the verified caller.
    when not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
      then pg_catalog.jsonb_build_object(
        'ok',false,'error','product_owner_auth_ineligible')
    else (
      with active as (
          select
            g.grant_group_id,
            g.profile_key,
            g.device_id,
            g.space_id,
            g.project_id,
            g.capability,
            g.access_mode,
            g.valid_until
          from public.ordax_remote_capability_grants g
          join public.ordax_product_devices d
            on d.device_id = g.device_id
           and d.state = 'active'
          where g.owner_user_id = p_owner_user_id
            and g.client_kind = p_client_kind
            and g.client_id is not distinct from p_client_id
            and g.state = 'active'
            and (g.valid_until is null or g.valid_until > pg_catalog.statement_timestamp())
        ),
        grant_groups as (
          select
            a.device_id,
            a.grant_group_id,
            a.profile_key,
            a.space_id,
            a.project_id,
            max(a.valid_until) as valid_until,
            jsonb_agg(
              jsonb_build_object(
                'capability', a.capability,
                'access_mode', a.access_mode
              )
              order by a.capability
            ) as capabilities
          from active a
          group by
            a.device_id,
            a.grant_group_id,
            a.profile_key,
            a.space_id,
            a.project_id
        ),
        targets as (
          select
            d.device_id,
            d.display_name,
            d.device_kind,
            d.channel,
            private.ordax_product_presence_online_v1(p.online, p.last_seen_at, pg_catalog.statement_timestamp()) as online,
            p.last_seen_at,
            jsonb_agg(
              jsonb_build_object(
                'grant_group_id', gg.grant_group_id,
                'profile_key', gg.profile_key,
                'space_id', gg.space_id,
                'project_id', gg.project_id,
                'valid_until', gg.valid_until,
                'capabilities', gg.capabilities
              )
              order by gg.profile_key, gg.grant_group_id
            ) as grant_groups
          from grant_groups gg
          join public.ordax_product_devices d on d.device_id = gg.device_id
          left join public.ordax_device_presence p on p.device_id = d.device_id
          group by
            d.device_id,
            d.display_name,
            d.device_kind,
            d.channel,
            p.online,
            p.last_seen_at
        )
        ,host_resolved as (
          select t.*, private.ordax_desktop_installation_host_v1(t.device_id) as host_device_id
          from targets t
        ),
        described as (
          select t.*,
            case when t.host_device_id is not null then 'OrdaX Desktop'
                 else t.display_name end as presented_name,
            case when t.host_device_id is not null then 'ordax_desktop_installation'
                 when exists (select 1 from host_resolved app where app.host_device_id = t.device_id)
                   then 'physical_computer'
                 else 'standalone_runtime_endpoint' end as endpoint_role,
            case when t.host_device_id is not null
                   and exists (select 1 from host_resolved host where host.device_id = t.host_device_id)
                   then t.host_device_id
                 when exists (select 1 from host_resolved app where app.host_device_id = t.device_id)
                   then t.device_id
                 else null::uuid end as physical_host_device_id
          from host_resolved t
        )
        select jsonb_build_object(
          'ok', true,
          'targets', coalesce(
            jsonb_agg(
              jsonb_build_object(
                'device_id', t.device_id,
                'device_name', t.presented_name,
                'device_kind', t.device_kind,
                'channel', t.channel,
                'online', t.online,
                'last_seen_at', t.last_seen_at,
                'grant_groups', t.grant_groups,
                'endpoint_role', t.endpoint_role,
                'physical_host_device_id', t.physical_host_device_id
              )
              order by t.presented_name, t.device_id
            ),
            '[]'::jsonb
          )
        )
        from described t
    )
  end;
$function$;

revoke all on function private.ordax_desktop_installation_host_v1(uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function public.ordax_list_product_targets_v1(uuid,text,text)
  from public, anon, authenticated, service_role;
grant execute on function public.ordax_list_product_targets_v1(uuid,text,text)
  to ordax_edge_executor;
commit;
