begin;

create or replace function public.ordax_resolve_owner_project_scope_v1(
  p_owner_user_id uuid,
  p_device_id uuid,
  p_repository_full_name text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_repository_full_name text := btrim(coalesce(p_repository_full_name, ''));
  v_count integer;
  v_space_id uuid;
  v_project_id uuid;
  v_repository_id bigint;
  v_canonical_repository_full_name text;
begin
  if p_owner_user_id is null
     or p_device_id is null
     or char_length(v_repository_full_name) not between 3 and 200
     or v_repository_full_name !~ '^[^[:space:]/]+/[^[:space:]/]+$'
  then
    return jsonb_build_object('ok', false, 'error', 'owner_project_scope_invalid');
  end if;

  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return jsonb_build_object('ok', false, 'error', 'product_owner_auth_ineligible');
  end if;

  if not exists (
    select 1
      from public.ordax_product_devices d
     where d.device_id = p_device_id
       and d.owner_user_id = p_owner_user_id
       and d.state = 'active'
  ) then
    return jsonb_build_object('ok', false, 'error', 'device_not_owned');
  end if;

  with candidates as (
    select
      c.space_id,
      c.project_id,
      c.repository_id,
      c.repository_full_name
    from public.ordax_project_connections c
    join public.ordax_projects p
      on p.project_id = c.project_id
     and p.space_id = c.space_id
    join public.ordax_space_devices sd
      on sd.space_id = c.space_id
     and sd.device_id = p_device_id
     and sd.state = 'active'
     and sd.access_mode = 'execute'
    join public.ordax_device_project_bindings b
      on b.project_id = c.project_id
     and b.device_id = p_device_id
     and b.state = 'active'
    where c.provider = 'github'
      and c.state = 'active'
      and p.state = 'active'
      and c.repository_id is not null
      and c.repository_full_name is not null
      and lower(c.repository_full_name) = lower(v_repository_full_name)
      and private.ordax_subject_can_access_project_v1(
        p_owner_user_id,
        c.project_id
      )
      and private.ordax_subject_can_admin_space_v1(
        p_owner_user_id,
        c.space_id
      )
  )
  select count(*)::integer,
         min(space_id),
         min(project_id),
         min(repository_id),
         min(repository_full_name)
    into v_count,
         v_space_id,
         v_project_id,
         v_repository_id,
         v_canonical_repository_full_name
    from candidates;

  if v_count = 0 then
    return jsonb_build_object('ok', false, 'error', 'owner_project_scope_not_found');
  end if;
  if v_count <> 1 then
    return jsonb_build_object('ok', false, 'error', 'owner_project_scope_ambiguous');
  end if;

  return jsonb_build_object(
    'ok', true,
    'space_id', v_space_id,
    'project_id', v_project_id,
    'repository_id', v_repository_id,
    'repository_full_name', v_canonical_repository_full_name
  );
end;
$$;

revoke all on function public.ordax_resolve_owner_project_scope_v1(uuid,uuid,text)
  from public, anon, authenticated, service_role, ordax_edge_executor, ordax_edge_runtime,
       ordax_space_executor, ordax_project_executor;

grant execute on function public.ordax_resolve_owner_project_scope_v1(uuid,uuid,text)
  to ordax_edge_runtime;

do $postflight$
begin
  if not has_function_privilege(
    'ordax_edge_runtime',
    'public.ordax_resolve_owner_project_scope_v1(uuid,uuid,text)',
    'EXECUTE'
  ) then
    raise exception 'owner project scope resolver: edge runtime execute missing';
  end if;

  if has_function_privilege(
       'service_role',
       'public.ordax_resolve_owner_project_scope_v1(uuid,uuid,text)',
       'EXECUTE'
     )
     or has_function_privilege(
       'authenticated',
       'public.ordax_resolve_owner_project_scope_v1(uuid,uuid,text)',
       'EXECUTE'
     )
     or has_function_privilege(
       'ordax_edge_executor',
       'public.ordax_resolve_owner_project_scope_v1(uuid,uuid,text)',
       'EXECUTE'
     ) then
    raise exception 'owner project scope resolver: unexpected execute authority';
  end if;
end;
$postflight$;

commit;
