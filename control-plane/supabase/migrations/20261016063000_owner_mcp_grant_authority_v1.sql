begin;

create or replace function public.ordax_owner_mcp_remote_authority_v1(
  p_owner_user_id uuid,
  p_device_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_clients jsonb;
  v_groups jsonb;
begin
  if p_owner_user_id is null or p_device_id is null then
    return jsonb_build_object('ok', false, 'error', 'owner_remote_authority_invalid');
  end if;
  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return jsonb_build_object('ok', false, 'error', 'product_owner_auth_ineligible');
  end if;
  if not exists (
    select 1 from public.ordax_product_devices d
    where d.device_id=p_device_id and d.owner_user_id=p_owner_user_id and d.state='active'
  ) then
    return jsonb_build_object('ok', false, 'error', 'device_not_owned');
  end if;

  select coalesce(jsonb_agg(jsonb_build_object(
    'client_id', c.id::text,
    'client_name', c.client_name,
    'client_uri', c.client_uri,
    'scopes', consent.scopes,
    'granted_at', consent.granted_at
  ) order by consent.granted_at desc), '[]'::jsonb)
  into v_clients
  from (
    select distinct on (client_id) client_id, scopes, granted_at
    from auth.oauth_consents
    where user_id=p_owner_user_id and revoked_at is null
    order by client_id, granted_at desc
  ) consent
  join auth.oauth_clients c on c.id=consent.client_id and c.deleted_at is null;

  select coalesce(jsonb_agg(group_row.value order by group_row.created_at desc), '[]'::jsonb)
  into v_groups
  from (
    select min(g.created_at) as created_at,
      jsonb_build_object(
        'grant_group_id', g.grant_group_id,
        'client_id', g.client_id,
        'client_name', max(client.client_name),
        'client_consent_active', bool_or(active_consent.active is true and client.deleted_at is null),
        'profile_key', g.profile_key,
        'scope_kind', g.scope_kind,
        'space_id', g.space_id,
        'project_id', g.project_id,
        'device_id', g.device_id,
        'valid_until', max(g.valid_until),
        'capabilities', jsonb_agg(jsonb_build_object(
          'capability', g.capability,
          'access_mode', g.access_mode
        ) order by g.capability)
      ) as value
    from public.ordax_remote_capability_grants g
    left join auth.oauth_clients client on client.id::text=g.client_id
    left join lateral (
      select true as active
      from auth.oauth_consents consent
      where consent.user_id=g.owner_user_id
        and consent.client_id=client.id
        and consent.revoked_at is null
      order by consent.granted_at desc
      limit 1
    ) active_consent on true
    where g.owner_user_id=p_owner_user_id
      and g.device_id=p_device_id
      and g.client_kind='product-mcp'
      and g.state='active'
      and (g.valid_until is null or g.valid_until>pg_catalog.clock_timestamp())
    group by g.grant_group_id,g.client_id,g.profile_key,g.scope_kind,g.space_id,g.project_id,g.device_id
  ) group_row;

  return jsonb_build_object('ok', true, 'device_id', p_device_id,
    'clients', v_clients, 'grant_groups', v_groups);
end;
$$;

create or replace function public.ordax_replace_owner_mcp_grant_group_v1(
  p_owner_user_id uuid,
  p_space_id uuid,
  p_project_id uuid,
  p_device_id uuid,
  p_client_id text,
  p_profile_key text,
  p_capabilities text[],
  p_access_modes text[],
  p_valid_until timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_owner_user_id is null or p_client_id is null
     or p_client_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  then
    return jsonb_build_object('ok', false, 'error', 'owner_mcp_client_invalid');
  end if;
  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return jsonb_build_object('ok', false, 'error', 'product_owner_auth_ineligible');
  end if;
  if not exists (
    select 1
    from auth.oauth_consents consent
    join auth.oauth_clients client on client.id=consent.client_id and client.deleted_at is null
    where consent.user_id=p_owner_user_id
      and consent.client_id=p_client_id::uuid
      and consent.revoked_at is null
  ) then
    return jsonb_build_object('ok', false, 'error', 'product_mcp_oauth_consent_required');
  end if;
  return public.ordax_replace_remote_grant_group_v1(
    p_owner_user_id,p_space_id,p_project_id,p_device_id,'product-mcp',p_client_id,
    p_profile_key,p_capabilities,p_access_modes,p_valid_until
  );
end;
$$;

create or replace function public.ordax_revoke_owner_mcp_grant_group_v1(
  p_owner_user_id uuid,
  p_client_id text,
  p_grant_group_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_owner_user_id is null or p_grant_group_id is null or p_client_id is null then
    return jsonb_build_object('ok', false, 'error', 'owner_mcp_grant_revoke_invalid');
  end if;
  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return jsonb_build_object('ok', false, 'error', 'product_owner_auth_ineligible');
  end if;
  if not exists (
    select 1 from public.ordax_remote_capability_grants g
    where g.owner_user_id=p_owner_user_id
      and g.grant_group_id=p_grant_group_id
      and g.client_kind='product-mcp'
      and g.client_id=p_client_id
      and g.state='active'
  ) then
    return jsonb_build_object('ok', false, 'error', 'remote_grant_group_not_found');
  end if;
  return public.ordax_revoke_remote_grant_group_v1(p_owner_user_id,p_grant_group_id);
end;
$$;

revoke all on function public.ordax_owner_mcp_remote_authority_v1(uuid,uuid)
  from public,anon,authenticated,service_role;
revoke all on function public.ordax_replace_owner_mcp_grant_group_v1(
  uuid,uuid,uuid,uuid,text,text,text[],text[],timestamptz
) from public,anon,authenticated,service_role;
revoke all on function public.ordax_revoke_owner_mcp_grant_group_v1(uuid,text,uuid)
  from public,anon,authenticated,service_role;

grant execute on function public.ordax_owner_mcp_remote_authority_v1(uuid,uuid)
  to ordax_edge_runtime;
grant execute on function public.ordax_replace_owner_mcp_grant_group_v1(
  uuid,uuid,uuid,uuid,text,text,text[],text[],timestamptz
) to ordax_edge_executor;
grant execute on function public.ordax_revoke_owner_mcp_grant_group_v1(uuid,text,uuid)
  to ordax_edge_executor;

commit;
