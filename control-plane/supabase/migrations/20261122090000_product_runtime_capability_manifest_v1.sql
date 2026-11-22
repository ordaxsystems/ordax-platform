-- Device-authenticated ActionRegistry availability, never a grant source.
-- Owner, remote grants, device identities and the heartbeat queue remain unchanged.
-- The manifest is co-located with canonical presence; no duplicate inventory table.
begin;

alter table public.ordax_device_presence
  add column capability_manifest text[],
  add column capability_manifest_digest text;
alter table public.ordax_device_presence
  add constraint ordax_device_presence_manifest_pair_check
  check ((capability_manifest is null) = (capability_manifest_digest is null));

-- New Runtime packages report the immutable-per-process registry on startup or
-- when changed. Existing devices keep using the authenticated v1 heartbeat.
-- One SQL statement authenticates, updates presence/capacity, and records the
-- same digest's registry snapshot atomically. No per-action availability query.
create function public.ordax_authenticated_product_heartbeat_v2(
  p_device_id uuid,
  p_token_sha256 text,
  p_online boolean,
  p_runtime_kind text,
  p_agent_version text,
  p_capability_digest text,
  p_force boolean,
  p_max_concurrent_jobs integer,
  p_actions text[]
) returns jsonb language plpgsql security definer set search_path to ''
as $function$
declare
  v_result jsonb;
begin
  if p_device_id is null or p_token_sha256 is null
     or p_token_sha256 !~ '^[0-9a-f]{64}$'
     or not coalesce(public.ordax_authenticate_product_device_v1(
       p_device_id, p_token_sha256), false)
  then
    return pg_catalog.jsonb_build_object('ok',false,'error','invalid_device_token');
  end if;

  -- Runtime has no authority to nominate devices, clients, grants or projects.
  -- The Worker independently checks SHA256(JSON UTF-8 canonical action names).
  if p_capability_digest is null or p_capability_digest !~ '^[0-9a-f]{64}$'
    or p_actions is null or pg_catalog.cardinality(p_actions) not between 1 and 1024
    or exists (
      select 1 from pg_catalog.unnest(p_actions) as item(name)
      where item.name is null or pg_catalog.char_length(item.name) not between 1 and 160
        or item.name !~ '^[a-z][a-z0-9._-]*$'
    )
    or p_actions is distinct from array(
      select distinct_names.name
      from (select distinct item.name from pg_catalog.unnest(p_actions) as item(name))
        as distinct_names
      order by distinct_names.name collate "C"
    )
  then
    return pg_catalog.jsonb_build_object('ok',false,'error','product_capability_manifest_invalid');
  end if;

  v_result := public.ordax_record_product_heartbeat_v1(
    p_device_id, p_online, p_runtime_kind, p_agent_version,
    p_capability_digest, p_force, p_max_concurrent_jobs
  );
  if v_result->>'ok' is distinct from 'true' then return v_result; end if;

  -- Stale/offline or another process's digest must never overwrite the active
  -- Runtime's reported capabilities, even on a valid Owner-enrolled device.
  update public.ordax_device_presence p
     set capability_manifest = p_actions,
         capability_manifest_digest = p_capability_digest
   where p.device_id = p_device_id and p.online = true
     and p.capability_digest = p_capability_digest
     and p.last_seen_at > pg_catalog.statement_timestamp() - interval '6 minutes';
  if not found then
    raise exception 'Runtime manifest state changed during heartbeat'
      using errcode='P4121';
  end if;
  return v_result;
end;
$function$;

revoke all on function public.ordax_authenticated_product_heartbeat_v2(
  uuid,text,boolean,text,text,text,boolean,integer,text[]
) from public,anon,authenticated,service_role,ordax_edge_executor;
grant execute on function public.ordax_authenticated_product_heartbeat_v2(
  uuid,text,boolean,text,text,text,boolean,integer,text[]
) to ordax_edge_executor;
comment on function public.ordax_authenticated_product_heartbeat_v2(
  uuid,text,boolean,text,text,text,boolean,integer,text[]
) is 'One device-authenticated statement for presence, capacity and Runtime ActionRegistry availability; not grants.';

-- Extend the SAME canonical Owner/OAuth targets projection. The manifest is
-- exposed only while the Runtime is online and its current digest matches.
-- Empty/unknown manifests remain NULL, never inferred from a grant.

CREATE OR REPLACE FUNCTION public.ordax_list_product_targets_v1(p_owner_user_id uuid, p_client_kind text, p_client_id text)
 RETURNS jsonb
 LANGUAGE sql
 VOLATILE SECURITY DEFINER
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
            case when private.ordax_product_presence_online_v1(
                p.online, p.last_seen_at, pg_catalog.statement_timestamp())
                and p.capability_manifest_digest = p.capability_digest
              then p.capability_manifest else null end as runtime_capabilities,
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
            p.last_seen_at,
            p.capability_manifest,
            p.capability_manifest_digest,
            p.capability_digest
        )
        select jsonb_build_object(
          'ok', true,
          'targets', coalesce(
            jsonb_agg(
              jsonb_build_object(
                'device_id', t.device_id,
                'device_name', t.display_name,
                'device_kind', t.device_kind,
                'channel', t.channel,
                'online', t.online,
                'last_seen_at', t.last_seen_at,
                'grant_groups', t.grant_groups,
                'runtime_capabilities', t.runtime_capabilities
              )
              order by t.display_name, t.device_id
            ),
            '[]'::jsonb
          )
        )
        from targets t
    )
  end;
$function$
;

commit;
