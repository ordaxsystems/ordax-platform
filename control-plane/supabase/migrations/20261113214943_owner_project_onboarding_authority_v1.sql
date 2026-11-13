begin;

-- Owner-only onboarding bridge for the existing Space/Project/Device authorities.
-- This role can execute reviewed RPCs only. It never owns table DML and does
-- not create GitHub repository connections or Product grants.
do $role$
begin
  if not exists (
    select 1 from pg_catalog.pg_roles
    where rolname = 'ordax_owner_project_onboarding_executor'
  ) then
    create role ordax_owner_project_onboarding_executor
      nologin
      inherit
      nosuperuser
      nocreatedb
      nocreaterole
      noreplication
      nobypassrls;
  end if;
end;
$role$;

revoke all on schema private from ordax_owner_project_onboarding_executor;
revoke all on all tables in schema public from ordax_owner_project_onboarding_executor;
revoke all on all tables in schema private from ordax_owner_project_onboarding_executor;
revoke all on all sequences in schema public from ordax_owner_project_onboarding_executor;
revoke all on all sequences in schema private from ordax_owner_project_onboarding_executor;
revoke all on all functions in schema public from ordax_owner_project_onboarding_executor;
revoke all on all functions in schema private from ordax_owner_project_onboarding_executor;
grant usage on schema public to ordax_owner_project_onboarding_executor;

create or replace function public.ordax_owner_project_onboarding_state_v1(
  p_owner_user_id uuid,
  p_device_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_spaces jsonb;
  v_projects jsonb;
begin
  if p_owner_user_id is null or p_device_id is null then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'owner_project_onboarding_invalid'
    );
  end if;

  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'product_owner_auth_ineligible'
    );
  end if;

  if not exists (
    select 1
    from public.ordax_product_devices d
    where d.device_id = p_device_id
      and d.owner_user_id = p_owner_user_id
      and d.state = 'active'
  ) then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'device_not_owned'
    );
  end if;

  select coalesce(
    pg_catalog.jsonb_agg(
      pg_catalog.jsonb_build_object(
        'space_id', s.space_id,
        'name', s.name,
        'kind', s.kind,
        'state', s.state
      )
      order by s.created_at, s.space_id
    ),
    '[]'::jsonb
  )
  into v_spaces
  from public.ordax_spaces s
  where s.state = 'active'
    and private.ordax_subject_can_admin_space_v1(
      p_owner_user_id,
      s.space_id
    );

  with project_state as (
    select
      p.project_id,
      p.space_id,
      p.name,
      p.kind,
      p.state,
      (
        select pg_catalog.count(*)::integer
        from public.ordax_project_connections c
        where c.project_id = p.project_id
          and c.space_id = p.space_id
          and c.provider = 'github'
          and c.state = 'active'
      ) as github_connection_count,
      (
        select case
          when pg_catalog.count(*) = 1
          then pg_catalog.min(pg_catalog.lower(c.repository_full_name))
          else null
        end
        from public.ordax_project_connections c
        where c.project_id = p.project_id
          and c.space_id = p.space_id
          and c.provider = 'github'
          and c.state = 'active'
      ) as repository_full_name,
      exists (
        select 1
        from public.ordax_space_devices sd
        where sd.space_id = p.space_id
          and sd.device_id = p_device_id
          and sd.state = 'active'
          and sd.access_mode = 'execute'
      ) as space_device_execute,
      exists (
        select 1
        from public.ordax_device_project_bindings b
        where b.project_id = p.project_id
          and b.device_id = p_device_id
          and b.state = 'active'
      ) as project_device_bound,
      p.created_at
    from public.ordax_projects p
    where p.state = 'active'
      and private.ordax_subject_can_admin_space_v1(
        p_owner_user_id,
        p.space_id
      )
  )
  select coalesce(
    pg_catalog.jsonb_agg(
      pg_catalog.jsonb_build_object(
        'project_id', ps.project_id,
        'space_id', ps.space_id,
        'name', ps.name,
        'kind', ps.kind,
        'state', ps.state,
        'github_connection_count', ps.github_connection_count,
        'repository_full_name', ps.repository_full_name,
        'space_device_execute', ps.space_device_execute,
        'project_device_bound', ps.project_device_bound,
        'next_state', case
          when ps.github_connection_count = 0
            then 'needs_github_installation'
          when ps.github_connection_count > 1
            then 'needs_repository_selection'
          when not ps.space_device_execute or not ps.project_device_bound
            then 'needs_device_binding'
          else 'ready_without_grants'
        end
      )
      order by ps.created_at, ps.project_id
    ),
    '[]'::jsonb
  )
  into v_projects
  from project_state ps;

  return pg_catalog.jsonb_build_object(
    'ok', true,
    'device_id', p_device_id,
    'spaces', v_spaces,
    'projects', v_projects,
    'next_state', case
      when pg_catalog.jsonb_array_length(v_spaces) = 0 then 'needs_space'
      when pg_catalog.jsonb_array_length(v_projects) = 0 then 'needs_project'
      else null
    end
  );
end;
$$;

revoke all on function public.ordax_owner_project_onboarding_state_v1(
  uuid, uuid
) from public, anon, authenticated, service_role, ordax_edge_executor,
  ordax_space_executor, ordax_project_executor, ordax_edge_runtime,
  ordax_owner_project_onboarding_executor;

grant execute on function public.ordax_owner_project_onboarding_state_v1(
  uuid, uuid
) to ordax_owner_project_onboarding_executor;

-- Reuse the canonical project authority rather than duplicating project
-- creation semantics. It already checks Auth eligibility, active Space state
-- and Owner/admin authority.
grant execute on function public.ordax_create_project_v1(
  uuid, uuid, text, text, jsonb
) to ordax_owner_project_onboarding_executor;

-- The login role inherits this narrow capability exactly as it already
-- inherits ordax_edge_executor. No table privilege is added.
grant ordax_owner_project_onboarding_executor to ordax_edge_runtime;

commit;
