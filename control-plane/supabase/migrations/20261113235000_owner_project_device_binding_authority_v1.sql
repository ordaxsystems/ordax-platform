begin;

-- Owner -> Device Agent two-phase Project binding.
-- The browser can request an intent for an owned Device/Project, but only the
-- enrolled Device Agent may confirm the opaque local Project catalog id.
-- No Product grant is created here.

create table private.ordax_owner_project_device_binding_intents (
  intent_id uuid primary key,
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  space_id uuid not null references public.ordax_spaces(space_id) on delete cascade,
  project_id uuid not null,
  device_id uuid not null references public.ordax_product_devices(device_id) on delete cascade,
  connection_id uuid not null references public.ordax_project_connections(connection_id) on delete cascade,
  repository_id bigint not null,
  repository_full_name text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  foreign key (project_id, space_id)
    references public.ordax_projects(project_id, space_id) on delete cascade,
  check (expires_at > created_at),
  check (char_length(repository_full_name) between 3 and 200)
);

alter table private.ordax_owner_project_device_binding_intents enable row level security;
alter table private.ordax_owner_project_device_binding_intents force row level security;

revoke all on table private.ordax_owner_project_device_binding_intents
  from public, anon, authenticated, service_role, ordax_edge_executor,
       ordax_edge_runtime, ordax_space_executor, ordax_project_executor,
       ordax_owner_project_onboarding_executor;

create unique index ordax_owner_project_device_binding_intents_pending_uq
  on private.ordax_owner_project_device_binding_intents(project_id, device_id)
  where consumed_at is null;

-- One active local Project reference per canonical Project/Device. Multiple
-- active rows would make the existing Project scope resolver ambiguous.
create unique index ordax_device_project_bindings_one_active_uq
  on public.ordax_device_project_bindings(project_id, device_id)
  where state = 'active';

create or replace function public.ordax_owner_create_project_device_binding_intent_v1(
  p_owner_user_id uuid,
  p_project_id uuid,
  p_device_id uuid,
  p_intent_id uuid,
  p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_space_id uuid;
  v_connection_id uuid;
  v_repository_id bigint;
  v_repository_full_name text;
  v_connection_count integer;
begin
  if p_owner_user_id is null
     or p_project_id is null
     or p_device_id is null
     or p_intent_id is null
     or p_expires_at is null
     or p_expires_at <= v_now
     or p_expires_at > v_now + interval '5 minutes'
  then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'project_device_binding_intent_invalid'
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

  select p.space_id
    into v_space_id
  from public.ordax_projects p
  where p.project_id = p_project_id
    and p.state = 'active';

  if not found then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'project_not_found'
    );
  end if;

  if not private.ordax_subject_can_admin_space_v1(
    p_owner_user_id,
    v_space_id
  ) then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'space_admin_required'
    );
  end if;

  select
    pg_catalog.count(*)::integer,
    pg_catalog.min(c.connection_id::text)::uuid,
    pg_catalog.min(c.repository_id),
    pg_catalog.min(c.repository_full_name)
  into
    v_connection_count,
    v_connection_id,
    v_repository_id,
    v_repository_full_name
  from public.ordax_project_connections c
  where c.project_id = p_project_id
    and c.space_id = v_space_id
    and c.owner_user_id = p_owner_user_id
    and c.provider = 'github'
    and c.state = 'active'
    and c.repository_id is not null
    and c.repository_full_name is not null;

  if v_connection_count = 0 then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_repository_required'
    );
  end if;
  if v_connection_count <> 1 then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_repository_ambiguous'
    );
  end if;

  -- Explicitly supersede any older unconsumed request for this Project/Device.
  -- A stale Device Agent can never confirm the superseded intent.
  update private.ordax_owner_project_device_binding_intents
     set consumed_at = v_now
   where project_id = p_project_id
     and device_id = p_device_id
     and consumed_at is null;

  insert into private.ordax_owner_project_device_binding_intents(
    intent_id,
    owner_user_id,
    space_id,
    project_id,
    device_id,
    connection_id,
    repository_id,
    repository_full_name,
    expires_at
  ) values (
    p_intent_id,
    p_owner_user_id,
    v_space_id,
    p_project_id,
    p_device_id,
    v_connection_id,
    v_repository_id,
    pg_catalog.lower(v_repository_full_name),
    p_expires_at
  );

  return pg_catalog.jsonb_build_object(
    'ok', true,
    'intent_id', p_intent_id,
    'project_id', p_project_id,
    'device_id', p_device_id,
    'expires_at', p_expires_at,
    'next_state', 'awaiting_device_confirmation'
  );
end;
$$;

create or replace function public.ordax_device_read_project_binding_intents_v1(
  p_device_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_intents jsonb;
begin
  if p_device_id is null
     or not exists (
       select 1
       from public.ordax_product_devices d
       where d.device_id = p_device_id
         and d.state = 'active'
     )
  then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'device_not_active'
    );
  end if;

  select pg_catalog.coalesce(
    pg_catalog.jsonb_agg(
      pg_catalog.jsonb_build_object(
        'intent_id', i.intent_id,
        'project_id', i.project_id,
        'space_id', i.space_id,
        'repository_full_name', i.repository_full_name,
        'expires_at', i.expires_at
      )
      order by i.created_at, i.intent_id
    ),
    '[]'::jsonb
  )
  into v_intents
  from private.ordax_owner_project_device_binding_intents i
  join public.ordax_projects p
    on p.project_id = i.project_id
   and p.space_id = i.space_id
   and p.state = 'active'
  join public.ordax_project_connections c
    on c.connection_id = i.connection_id
   and c.project_id = i.project_id
   and c.space_id = i.space_id
   and c.owner_user_id = i.owner_user_id
   and c.provider = 'github'
   and c.state = 'active'
   and c.repository_id = i.repository_id
   and pg_catalog.lower(c.repository_full_name) = i.repository_full_name
  where i.device_id = p_device_id
    and i.consumed_at is null
    and i.expires_at > pg_catalog.clock_timestamp();

  return pg_catalog.jsonb_build_object(
    'ok', true,
    'device_id', p_device_id,
    'intents', v_intents
  );
end;
$$;

create or replace function public.ordax_device_confirm_project_binding_v1(
  p_device_id uuid,
  p_intent_id uuid,
  p_local_project_ref text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_intent private.ordax_owner_project_device_binding_intents%rowtype;
  v_active_binding public.ordax_device_project_bindings%rowtype;
  v_binding_id uuid;
  v_had_active_binding boolean := false;
  v_allowed_capabilities text[] := array[
    'agent.project_briefing',
    'browser.click',
    'browser.list',
    'browser.navigate',
    'browser.screenshot',
    'browser.snapshot',
    'browser.start',
    'browser.status',
    'browser.stop',
    'browser.type',
    'continuity.get',
    'continuity.update',
    'handoff.create',
    'handoff.get',
    'process.list',
    'process.logs',
    'process.start',
    'process.status',
    'process.stop',
    'process.write_stdin',
    'terminal.exec',
    'workspace.project_snapshot'
  ]::text[];
begin
  if p_device_id is null
     or p_intent_id is null
     or p_local_project_ref is null
     or char_length(p_local_project_ref) not between 9 and 160
     or p_local_project_ref !~ '^project-[1-9][0-9]*$'
  then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'project_device_binding_confirmation_invalid'
    );
  end if;

  select *
    into v_intent
  from private.ordax_owner_project_device_binding_intents i
  where i.intent_id = p_intent_id
  for update;

  if not found
     or v_intent.device_id <> p_device_id
     or v_intent.consumed_at is not null
     or v_intent.expires_at <= v_now
  then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'project_device_binding_intent_not_active'
    );
  end if;

  if not private.ordax_trusted_actor_auth_eligible_v1(v_intent.owner_user_id)
     or not exists (
       select 1
       from public.ordax_product_devices d
       where d.device_id = p_device_id
         and d.owner_user_id = v_intent.owner_user_id
         and d.state = 'active'
     )
     or not exists (
       select 1
       from public.ordax_projects p
       where p.project_id = v_intent.project_id
         and p.space_id = v_intent.space_id
         and p.state = 'active'
     )
     or not private.ordax_subject_can_admin_space_v1(
       v_intent.owner_user_id,
       v_intent.space_id
     )
  then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'project_device_binding_authority_changed'
    );
  end if;

  if not exists (
    select 1
    from public.ordax_project_connections c
    where c.connection_id = v_intent.connection_id
      and c.project_id = v_intent.project_id
      and c.space_id = v_intent.space_id
      and c.owner_user_id = v_intent.owner_user_id
      and c.provider = 'github'
      and c.state = 'active'
      and c.repository_id = v_intent.repository_id
      and pg_catalog.lower(c.repository_full_name) = v_intent.repository_full_name
  ) then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_repository_changed'
    );
  end if;

  select *
    into v_active_binding
  from public.ordax_device_project_bindings b
  where b.project_id = v_intent.project_id
    and b.device_id = p_device_id
    and b.state = 'active'
  for update;

  v_had_active_binding := found;
  if v_had_active_binding and v_active_binding.local_project_ref <> p_local_project_ref then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'project_device_binding_conflict'
    );
  end if;

  insert into public.ordax_space_devices(
    space_id,
    device_id,
    access_mode,
    state,
    granted_by_user_id
  ) values (
    v_intent.space_id,
    p_device_id,
    'execute',
    'active',
    v_intent.owner_user_id
  )
  on conflict (space_id, device_id)
  do update
     set access_mode = 'execute',
         state = 'active',
         granted_by_user_id = excluded.granted_by_user_id,
         updated_at = v_now;

  if v_had_active_binding then
    update public.ordax_device_project_bindings
       set allowed_capabilities = v_allowed_capabilities,
           updated_at = v_now
     where binding_id = v_active_binding.binding_id
     returning binding_id into v_binding_id;
  else
    insert into public.ordax_device_project_bindings(
      project_id,
      device_id,
      local_project_ref,
      state,
      allowed_capabilities
    ) values (
      v_intent.project_id,
      p_device_id,
      p_local_project_ref,
      'active',
      v_allowed_capabilities
    )
    on conflict (project_id, device_id, local_project_ref)
    do update
       set state = 'active',
           allowed_capabilities = excluded.allowed_capabilities,
           updated_at = v_now
    returning binding_id into v_binding_id;
  end if;

  update private.ordax_owner_project_device_binding_intents
     set consumed_at = v_now
   where intent_id = p_intent_id;

  return pg_catalog.jsonb_build_object(
    'ok', true,
    'binding_id', v_binding_id,
    'project_id', v_intent.project_id,
    'space_id', v_intent.space_id,
    'device_id', p_device_id,
    'state', 'active',
    'next_state', 'ready_without_grants'
  );
end;
$$;

revoke all on function public.ordax_owner_create_project_device_binding_intent_v1(
  uuid, uuid, uuid, uuid, timestamptz
) from public, anon, authenticated, service_role, ordax_edge_executor,
  ordax_edge_runtime, ordax_space_executor, ordax_project_executor,
  ordax_owner_project_onboarding_executor;

revoke all on function public.ordax_device_read_project_binding_intents_v1(uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor,
       ordax_edge_runtime, ordax_space_executor, ordax_project_executor,
       ordax_owner_project_onboarding_executor;

revoke all on function public.ordax_device_confirm_project_binding_v1(uuid, uuid, text)
  from public, anon, authenticated, service_role, ordax_edge_executor,
       ordax_edge_runtime, ordax_space_executor, ordax_project_executor,
       ordax_owner_project_onboarding_executor;

grant execute on function public.ordax_owner_create_project_device_binding_intent_v1(
  uuid, uuid, uuid, uuid, timestamptz
) to ordax_owner_project_onboarding_executor;

grant execute on function public.ordax_device_read_project_binding_intents_v1(uuid)
  to ordax_edge_runtime;

grant execute on function public.ordax_device_confirm_project_binding_v1(uuid, uuid, text)
  to ordax_edge_runtime;

do $postflight$
declare
  v_direct integer;
begin
  if not exists (
    select 1
    from pg_catalog.pg_indexes
    where schemaname = 'public'
      and tablename = 'ordax_device_project_bindings'
      and indexname = 'ordax_device_project_bindings_one_active_uq'
  ) then
    raise exception 'owner project device binding: active binding uniqueness missing';
  end if;

  if has_schema_privilege(
       'ordax_owner_project_onboarding_executor', 'private', 'USAGE'
     )
     or has_schema_privilege('ordax_edge_runtime', 'private', 'USAGE') then
    raise exception 'owner project device binding: private schema leaked';
  end if;

  select pg_catalog.count(*)
    into v_direct
  from pg_catalog.pg_class c
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'private'
    and c.relname = 'ordax_owner_project_device_binding_intents'
    and (
      has_table_privilege('ordax_owner_project_onboarding_executor', c.oid, 'SELECT')
      or has_table_privilege('ordax_owner_project_onboarding_executor', c.oid, 'INSERT')
      or has_table_privilege('ordax_owner_project_onboarding_executor', c.oid, 'UPDATE')
      or has_table_privilege('ordax_owner_project_onboarding_executor', c.oid, 'DELETE')
      or has_table_privilege('ordax_edge_runtime', c.oid, 'SELECT')
      or has_table_privilege('ordax_edge_runtime', c.oid, 'INSERT')
      or has_table_privilege('ordax_edge_runtime', c.oid, 'UPDATE')
      or has_table_privilege('ordax_edge_runtime', c.oid, 'DELETE')
    );

  if v_direct <> 0 then
    raise exception 'owner project device binding: direct intent table authority leaked';
  end if;
end;
$postflight$;

commit;
