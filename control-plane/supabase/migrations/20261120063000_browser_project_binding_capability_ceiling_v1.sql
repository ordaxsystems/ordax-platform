begin;

-- Evolves the existing Owner/Device Project capability ceiling for browser
-- tab identity. No Product grant is created; every action still requires
-- its current signed project-browser-automation grant. Preserve the original attestation
-- rules and Project Catalog binding procedure verbatim.

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
    'blender.live_create_primitive',
    'blender.live_material_apply',
    'blender.live_modeling_schema',
    'blender.live_object_inspect',
    'blender.live_object_transform',
    'blender.live_rig_create',
    'blender.live_save',
    'blender.live_scene_snapshot',
    'blender.live_start',
    'blender.live_status',
    'browser.click',
    'browser.list',
    'browser.navigate',
    'browser.screenshot',
    'browser.snapshot',
    'browser.start',
    'browser.tab_open',
    'browser.tabs',
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

  -- First resolve the immutable intent identity without locking it. Then lock
  -- the canonical Project row before locking the intent, matching the Owner
  -- creation lock order and avoiding a Project<->intent deadlock.
  select *
    into v_intent
  from private.ordax_owner_project_device_binding_intents i
  where i.intent_id = p_intent_id;

  if not found
     or v_intent.device_id <> p_device_id
     or v_intent.consumed_at is not null
     or v_intent.expires_at <= v_now
  then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'project_device_binding_intent_not_active'
    );
  end if;

  perform 1
  from public.ordax_projects p
  where p.project_id = v_intent.project_id
    and p.space_id = v_intent.space_id
  for update;

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

-- Existing bindings produced with the prior exact ceiling can gain
-- visibility of tab capabilities. Do not widen intentionally restricted
-- or non-canonical bindings. This does not mint or modify OAuth grants.
update public.ordax_device_project_bindings
   set allowed_capabilities = array[
  'agent.project_briefing',
  'blender.live_create_primitive',
  'blender.live_material_apply',
  'blender.live_modeling_schema',
  'blender.live_object_inspect',
  'blender.live_object_transform',
  'blender.live_rig_create',
  'blender.live_save',
  'blender.live_scene_snapshot',
  'blender.live_start',
  'blender.live_status',
  'browser.click',
  'browser.list',
  'browser.navigate',
  'browser.screenshot',
  'browser.snapshot',
  'browser.start',
  'browser.tab_open',
  'browser.tabs',
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
]::text[],
       updated_at = pg_catalog.clock_timestamp()
 where state = 'active'
   and allowed_capabilities = array[
    'agent.project_briefing',
    'blender.live_create_primitive',
    'blender.live_material_apply',
    'blender.live_modeling_schema',
    'blender.live_object_inspect',
    'blender.live_object_transform',
    'blender.live_rig_create',
    'blender.live_save',
    'blender.live_scene_snapshot',
    'blender.live_start',
    'blender.live_status',
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

revoke all on function public.ordax_device_confirm_project_binding_v1(uuid, uuid, text)
  from public, anon, authenticated, service_role, ordax_edge_executor,
       ordax_edge_runtime, ordax_space_executor, ordax_project_executor,
       ordax_owner_project_onboarding_executor;
grant execute on function public.ordax_device_confirm_project_binding_v1(uuid, uuid, text)
  to ordax_edge_runtime;

commit;
