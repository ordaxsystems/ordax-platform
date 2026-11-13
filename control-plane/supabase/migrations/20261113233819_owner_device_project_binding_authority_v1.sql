begin;

-- Owner-authorized, Device-confirmed Project binding.
--
-- Browser/Owner input can choose only the canonical cloud Project + Device.
-- The local Project reference and capability ceiling arrive only later from
-- the already-enrolled Device transport. No path, grant or provider token is
-- stored here and no remote capability grant is issued by this migration.

create table private.ordax_owner_project_binding_intents (
  intent_id uuid primary key,
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  project_id uuid not null,
  space_id uuid not null,
  device_id uuid not null references public.ordax_product_devices(device_id) on delete cascade,
  state text not null default 'pending',
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now()),
  constraint ordax_owner_project_binding_intent_project_space_fk
    foreign key (project_id, space_id)
    references public.ordax_projects(project_id, space_id)
    on delete cascade,
  constraint ordax_owner_project_binding_intent_state_check
    check (state in ('pending','consumed')),
  constraint ordax_owner_project_binding_intent_consumed_check
    check (
      (state='pending' and consumed_at is null)
      or (state='consumed' and consumed_at is not null)
    )
);

alter table private.ordax_owner_project_binding_intents enable row level security;
alter table private.ordax_owner_project_binding_intents force row level security;

create unique index ordax_owner_project_binding_pending_uidx
  on private.ordax_owner_project_binding_intents(project_id, device_id)
  where state='pending';

create index ordax_owner_project_binding_device_pending_idx
  on private.ordax_owner_project_binding_intents(device_id, expires_at)
  where state='pending';

-- A Project/device pair has one current local binding. Historical revoked or
-- unavailable rows may remain without making canonical resolution ambiguous.
create unique index ordax_device_project_bindings_active_pair_uidx
  on public.ordax_device_project_bindings(project_id, device_id)
  where state='active';

revoke all on table private.ordax_owner_project_binding_intents
  from public, anon, authenticated, service_role, ordax_edge_executor,
       ordax_space_executor, ordax_project_executor, ordax_edge_runtime,
       ordax_owner_project_onboarding_executor;

create function public.ordax_owner_create_project_binding_intent_v1(
  p_owner_user_id uuid,
  p_project_id uuid,
  p_device_id uuid,
  p_intent_id uuid,
  p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path=''
as $$
declare
  v_space_id uuid;
  v_github_count integer;
  v_now timestamptz := pg_catalog.clock_timestamp();
begin
  if p_owner_user_id is null or p_project_id is null or p_device_id is null
     or p_intent_id is null or p_expires_at is null
     or p_expires_at <= v_now + interval '2 minutes'
     or p_expires_at > v_now + interval '10 minutes' then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','project_binding_intent_invalid'
    );
  end if;

  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','product_owner_auth_ineligible'
    );
  end if;

  select p.space_id into v_space_id
  from public.ordax_projects p
  where p.project_id=p_project_id and p.state='active';

  if not found then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','project_not_found_or_inactive'
    );
  end if;

  if not private.ordax_subject_can_admin_space_v1(p_owner_user_id,v_space_id) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','space_admin_required'
    );
  end if;

  if not exists (
    select 1 from public.ordax_product_devices d
    where d.device_id=p_device_id
      and d.owner_user_id=p_owner_user_id
      and d.state='active'
  ) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','device_not_owned'
    );
  end if;

  select pg_catalog.count(*)::integer into v_github_count
  from public.ordax_project_connections c
  where c.project_id=p_project_id
    and c.space_id=v_space_id
    and c.provider='github'
    and c.state='active';

  if v_github_count=0 then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','github_repository_required'
    );
  end if;
  if v_github_count<>1 then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','github_repository_ambiguous'
    );
  end if;

  if exists (
    select 1 from public.ordax_device_project_bindings b
    where b.project_id=p_project_id
      and b.device_id=p_device_id
      and b.state='active'
  ) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','project_device_binding_exists'
    );
  end if;

  delete from private.ordax_owner_project_binding_intents i
  where i.state='pending' and i.expires_at<=v_now;

  insert into private.ordax_owner_project_binding_intents(
    intent_id,owner_user_id,project_id,space_id,device_id,state,expires_at
  ) values (
    p_intent_id,p_owner_user_id,p_project_id,v_space_id,p_device_id,'pending',p_expires_at
  );

  return pg_catalog.jsonb_build_object(
    'ok',true,
    'intent_id',p_intent_id,
    'project_id',p_project_id,
    'space_id',v_space_id,
    'device_id',p_device_id,
    'expires_at',p_expires_at,
    'next_state','awaiting_device_confirmation'
  );
exception
  when unique_violation then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','project_binding_intent_pending'
    );
end;
$$;

create function public.ordax_device_project_binding_intents_v1(
  p_device_id uuid
)
returns jsonb
language plpgsql
stable
security definer
set search_path=''
as $$
declare
  v_count integer;
  v_intents jsonb;
  v_now timestamptz := pg_catalog.statement_timestamp();
begin
  if p_device_id is null then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','project_binding_device_invalid'
    );
  end if;

  if not exists (
    select 1 from public.ordax_product_devices d
    where d.device_id=p_device_id and d.state='active'
  ) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','project_binding_device_inactive'
    );
  end if;

  select pg_catalog.count(*)::integer into v_count
  from private.ordax_owner_project_binding_intents i
  join public.ordax_projects p
    on p.project_id=i.project_id
   and p.space_id=i.space_id
   and p.state='active'
  where i.device_id=p_device_id
    and i.state='pending'
    and i.expires_at>v_now
    and private.ordax_subject_can_admin_space_v1(i.owner_user_id,i.space_id)
    and (
      select pg_catalog.count(*)
      from public.ordax_project_connections c
      where c.project_id=i.project_id
        and c.space_id=i.space_id
        and c.provider='github'
        and c.state='active'
    )=1;

  if v_count>32 then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','project_binding_intents_overflow'
    );
  end if;

  select pg_catalog.coalesce(
    pg_catalog.jsonb_agg(
      pg_catalog.jsonb_build_object(
        'intent_id',i.intent_id,
        'project_id',i.project_id,
        'space_id',i.space_id,
        'project_name',p.name,
        'repository_full_name',(
          select c.repository_full_name
          from public.ordax_project_connections c
          where c.project_id=i.project_id
            and c.space_id=i.space_id
            and c.provider='github'
            and c.state='active'
          limit 1
        ),
        'expires_at',i.expires_at
      )
      order by i.created_at,i.intent_id
    ),
    '[]'::jsonb
  ) into v_intents
  from private.ordax_owner_project_binding_intents i
  join public.ordax_projects p
    on p.project_id=i.project_id
   and p.space_id=i.space_id
   and p.state='active'
  where i.device_id=p_device_id
    and i.state='pending'
    and i.expires_at>v_now
    and private.ordax_subject_can_admin_space_v1(i.owner_user_id,i.space_id)
    and (
      select pg_catalog.count(*)
      from public.ordax_project_connections c
      where c.project_id=i.project_id
        and c.space_id=i.space_id
        and c.provider='github'
        and c.state='active'
    )=1;

  return pg_catalog.jsonb_build_object(
    'ok',true,
    'device_id',p_device_id,
    'intents',v_intents
  );
end;
$$;

create function public.ordax_device_confirm_project_binding_v1(
  p_device_id uuid,
  p_intent_id uuid,
  p_local_project_ref text,
  p_allowed_capabilities text[]
)
returns jsonb
language plpgsql
security definer
set search_path=''
as $$
declare
  v_intent private.ordax_owner_project_binding_intents%rowtype;
  v_binding_id uuid;
  v_existing_ref text;
  v_capabilities text[];
  v_github_count integer;
  v_now timestamptz := pg_catalog.clock_timestamp();
begin
  if p_device_id is null or p_intent_id is null
     or p_local_project_ref is null
     or p_local_project_ref !~ '^project-[1-9][0-9]*$'
     or char_length(p_local_project_ref)>160
     or p_allowed_capabilities is null
     or cardinality(p_allowed_capabilities) not between 1 and 128 then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','project_binding_confirmation_invalid'
    );
  end if;

  if exists (
    select 1 from unnest(p_allowed_capabilities) capability
    where capability is null
       or char_length(capability) not between 2 and 120
       or capability !~ '^[a-z][a-z0-9._-]+$'
  ) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','project_binding_capabilities_invalid'
    );
  end if;

  select pg_catalog.array_agg(capability order by capability)
    into v_capabilities
  from (
    select distinct capability
    from unnest(p_allowed_capabilities) capability
  ) canonical;

  if cardinality(v_capabilities)<>cardinality(p_allowed_capabilities) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','project_binding_capabilities_duplicate'
    );
  end if;

  select * into v_intent
  from private.ordax_owner_project_binding_intents i
  where i.intent_id=p_intent_id
    and i.device_id=p_device_id
    and i.state='pending'
    and i.expires_at>v_now
  for update;

  if not found then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','project_binding_intent_invalid'
    );
  end if;

  if not exists (
    select 1 from public.ordax_product_devices d
    where d.device_id=p_device_id
      and d.owner_user_id=v_intent.owner_user_id
      and d.state='active'
  ) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','device_not_owned'
    );
  end if;

  if not exists (
    select 1 from public.ordax_projects p
    where p.project_id=v_intent.project_id
      and p.space_id=v_intent.space_id
      and p.state='active'
  ) or not private.ordax_subject_can_admin_space_v1(
    v_intent.owner_user_id,v_intent.space_id
  ) then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','project_binding_authority_changed'
    );
  end if;

  select pg_catalog.count(*)::integer into v_github_count
  from public.ordax_project_connections c
  where c.project_id=v_intent.project_id
    and c.space_id=v_intent.space_id
    and c.provider='github'
    and c.state='active';

  if v_github_count<>1 then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','project_binding_repository_changed'
    );
  end if;

  select b.local_project_ref into v_existing_ref
  from public.ordax_device_project_bindings b
  where b.project_id=v_intent.project_id
    and b.device_id=p_device_id
    and b.state='active'
  for update;

  if found and v_existing_ref<>p_local_project_ref then
    return pg_catalog.jsonb_build_object(
      'ok',false,'error','project_binding_local_ref_conflict'
    );
  end if;

  insert into public.ordax_space_devices(
    space_id,device_id,access_mode,state,granted_by_user_id,updated_at
  ) values (
    v_intent.space_id,p_device_id,'execute','active',v_intent.owner_user_id,v_now
  )
  on conflict (space_id,device_id) do update
    set access_mode='execute',
        state='active',
        granted_by_user_id=excluded.granted_by_user_id,
        updated_at=v_now;

  select b.binding_id into v_binding_id
  from public.ordax_device_project_bindings b
  where b.project_id=v_intent.project_id
    and b.device_id=p_device_id
    and b.local_project_ref=p_local_project_ref
  for update;

  if found then
    update public.ordax_device_project_bindings
       set state='active',
           allowed_capabilities=v_capabilities,
           updated_at=v_now
     where binding_id=v_binding_id;
  else
    insert into public.ordax_device_project_bindings(
      project_id,device_id,local_project_ref,state,allowed_capabilities
    ) values (
      v_intent.project_id,p_device_id,p_local_project_ref,'active',v_capabilities
    )
    returning binding_id into v_binding_id;
  end if;

  update private.ordax_owner_project_binding_intents
     set state='consumed',consumed_at=v_now,updated_at=v_now
   where intent_id=p_intent_id;

  return pg_catalog.jsonb_build_object(
    'ok',true,
    'binding_id',v_binding_id,
    'project_id',v_intent.project_id,
    'space_id',v_intent.space_id,
    'device_id',p_device_id,
    'capability_count',cardinality(v_capabilities),
    'state','active',
    'next_state','ready_without_grants'
  );
end;
$$;

revoke all on function public.ordax_owner_create_project_binding_intent_v1(
  uuid,uuid,uuid,uuid,timestamptz
) from public,anon,authenticated,service_role,ordax_edge_executor,
  ordax_space_executor,ordax_project_executor,ordax_edge_runtime,
  ordax_owner_project_onboarding_executor;

revoke all on function public.ordax_device_project_binding_intents_v1(uuid)
  from public,anon,authenticated,service_role,ordax_edge_executor,
       ordax_space_executor,ordax_project_executor,ordax_edge_runtime,
       ordax_owner_project_onboarding_executor;

revoke all on function public.ordax_device_confirm_project_binding_v1(
  uuid,uuid,text,text[]
) from public,anon,authenticated,service_role,ordax_edge_executor,
  ordax_space_executor,ordax_project_executor,ordax_edge_runtime,
  ordax_owner_project_onboarding_executor;

grant execute on function public.ordax_owner_create_project_binding_intent_v1(
  uuid,uuid,uuid,uuid,timestamptz
) to ordax_owner_project_onboarding_executor;
grant execute on function public.ordax_device_project_binding_intents_v1(uuid)
  to ordax_owner_project_onboarding_executor;
grant execute on function public.ordax_device_confirm_project_binding_v1(
  uuid,uuid,text,text[]
) to ordax_owner_project_onboarding_executor;

do $postflight$
declare
  v_direct integer;
begin
  select pg_catalog.count(*) into v_direct
  from pg_catalog.pg_class c
  join pg_catalog.pg_namespace n on n.oid=c.relnamespace
  where n.nspname in ('public','private')
    and c.relkind in ('r','p','v','m','f','S')
    and (
      (c.relkind='S' and (
        pg_catalog.has_sequence_privilege(
          'ordax_owner_project_onboarding_executor',c.oid,'USAGE'
        ) or pg_catalog.has_sequence_privilege(
          'ordax_owner_project_onboarding_executor',c.oid,'SELECT'
        ) or pg_catalog.has_sequence_privilege(
          'ordax_owner_project_onboarding_executor',c.oid,'UPDATE'
        )
      ))
      or
      (c.relkind<>'S' and (
        pg_catalog.has_table_privilege(
          'ordax_owner_project_onboarding_executor',c.oid,'SELECT'
        ) or pg_catalog.has_table_privilege(
          'ordax_owner_project_onboarding_executor',c.oid,'INSERT'
        ) or pg_catalog.has_table_privilege(
          'ordax_owner_project_onboarding_executor',c.oid,'UPDATE'
        ) or pg_catalog.has_table_privilege(
          'ordax_owner_project_onboarding_executor',c.oid,'DELETE'
        )
      ))
    );

  if v_direct<>0 then
    raise exception 'project binding authority: direct relation authority detected';
  end if;

  if pg_catalog.has_schema_privilege(
    'ordax_owner_project_onboarding_executor','private','USAGE'
  ) then
    raise exception 'project binding authority: private schema unexpectedly visible';
  end if;
end;
$postflight$;

commit;
