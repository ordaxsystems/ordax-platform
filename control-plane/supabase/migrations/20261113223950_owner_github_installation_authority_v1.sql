begin;

-- Owner GitHub App authorization is a short-lived server authority. Browser/model
-- input can start a challenge or select a server-verified repository, but can
-- never supply installation identity or create ordax_project_connections directly.

create table private.ordax_owner_github_authorization_challenges (
  challenge_id uuid primary key,
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  project_id uuid not null,
  space_id uuid not null,
  state_sha256 text not null,
  status text not null default 'pending',
  github_user_id bigint,
  github_user_login text,
  expires_at timestamptz not null,
  verified_at timestamptz,
  consumed_at timestamptz,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now()),
  constraint ordax_owner_github_challenge_project_space_fk
    foreign key (project_id, space_id)
    references public.ordax_projects(project_id, space_id)
    on delete cascade,
  constraint ordax_owner_github_challenge_state_hash_check
    check (state_sha256 ~ '^[0-9a-f]{64}$'),
  constraint ordax_owner_github_challenge_status_check
    check (status in ('pending', 'verifying', 'verified', 'selected')),
  constraint ordax_owner_github_challenge_user_identity_check
    check (
      (github_user_id is null and github_user_login is null)
      or (
        github_user_id is not null and github_user_id > 0
        and github_user_login is not null
        and char_length(github_user_login) between 1 and 100
        and github_user_login ~ '^[A-Za-z0-9-]+$'
      )
    )
);

create unique index ordax_owner_github_challenge_state_uidx
  on private.ordax_owner_github_authorization_challenges(state_sha256);
create index ordax_owner_github_challenge_owner_state_idx
  on private.ordax_owner_github_authorization_challenges(
    owner_user_id, status, expires_at
  );

create table private.ordax_owner_github_repository_candidates (
  challenge_id uuid not null
    references private.ordax_owner_github_authorization_challenges(challenge_id)
    on delete cascade,
  installation_id bigint not null check (installation_id > 0),
  installation_account_id bigint not null check (installation_account_id > 0),
  installation_account_login text not null,
  repository_id bigint not null check (repository_id > 0),
  repository_full_name text not null,
  default_branch text,
  expires_at timestamptz not null,
  created_at timestamptz not null default timezone('utc', now()),
  primary key (challenge_id, repository_id),
  constraint ordax_owner_github_candidate_account_login_check
    check (
      char_length(installation_account_login) between 1 and 100
      and installation_account_login ~ '^[A-Za-z0-9-]+$'
    ),
  constraint ordax_owner_github_candidate_repository_check
    check (
      char_length(repository_full_name) between 3 and 200
      and repository_full_name ~ '^[^[:space:]/]+/[^[:space:]/]+$'
    ),
  constraint ordax_owner_github_candidate_default_branch_check
    check (
      default_branch is null
      or (
        char_length(default_branch) between 1 and 255
        and default_branch !~ '[[:cntrl:]]'
      )
    )
);

create index ordax_owner_github_candidate_challenge_idx
  on private.ordax_owner_github_repository_candidates(
    challenge_id, repository_full_name
  );

revoke all on table private.ordax_owner_github_authorization_challenges
  from public, anon, authenticated, service_role, ordax_edge_executor,
       ordax_space_executor, ordax_project_executor, ordax_edge_runtime,
       ordax_owner_project_onboarding_executor;
revoke all on table private.ordax_owner_github_repository_candidates
  from public, anon, authenticated, service_role, ordax_edge_executor,
       ordax_space_executor, ordax_project_executor, ordax_edge_runtime,
       ordax_owner_project_onboarding_executor;

create function public.ordax_owner_create_github_authorization_challenge_v1(
  p_owner_user_id uuid,
  p_project_id uuid,
  p_challenge_id uuid,
  p_state_sha256 text,
  p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_space_id uuid;
  v_now timestamptz := pg_catalog.timezone('utc', pg_catalog.now());
begin
  if p_owner_user_id is null or p_project_id is null or p_challenge_id is null
     or p_state_sha256 is null or p_state_sha256 !~ '^[0-9a-f]{64}$'
     or p_expires_at is null
     or p_expires_at <= v_now + interval '2 minutes'
     or p_expires_at > v_now + interval '20 minutes' then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_authorization_challenge_invalid'
    );
  end if;

  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'product_owner_auth_ineligible'
    );
  end if;

  select p.space_id into v_space_id
  from public.ordax_projects p
  where p.project_id = p_project_id and p.state = 'active';

  if not found then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'project_not_found_or_inactive'
    );
  end if;

  if not private.ordax_subject_can_admin_space_v1(p_owner_user_id, v_space_id) then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'space_admin_required'
    );
  end if;

  if exists (
    select 1 from public.ordax_project_connections c
    where c.project_id = p_project_id
      and c.space_id = v_space_id
      and c.provider = 'github'
      and c.state = 'active'
  ) then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'project_github_connection_exists'
    );
  end if;

  delete from private.ordax_owner_github_authorization_challenges c
  where c.owner_user_id = p_owner_user_id and c.expires_at <= v_now;

  insert into private.ordax_owner_github_authorization_challenges(
    challenge_id, owner_user_id, project_id, space_id,
    state_sha256, status, expires_at
  ) values (
    p_challenge_id, p_owner_user_id, p_project_id, v_space_id,
    p_state_sha256, 'pending', p_expires_at
  );

  return pg_catalog.jsonb_build_object(
    'ok', true,
    'challenge_id', p_challenge_id,
    'project_id', p_project_id,
    'expires_at', p_expires_at
  );
exception
  when unique_violation then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_authorization_challenge_conflict'
    );
end;
$$;

create function public.ordax_owner_begin_github_authorization_completion_v1(
  p_owner_user_id uuid,
  p_challenge_id uuid,
  p_state_sha256 text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_project_id uuid;
  v_space_id uuid;
  v_expires_at timestamptz;
  v_now timestamptz := pg_catalog.timezone('utc', pg_catalog.now());
begin
  if p_owner_user_id is null or p_challenge_id is null
     or p_state_sha256 is null or p_state_sha256 !~ '^[0-9a-f]{64}$' then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_authorization_completion_invalid'
    );
  end if;

  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'product_owner_auth_ineligible'
    );
  end if;

  update private.ordax_owner_github_authorization_challenges c
     set status = 'verifying', updated_at = v_now
   where c.challenge_id = p_challenge_id
     and c.owner_user_id = p_owner_user_id
     and c.state_sha256 = p_state_sha256
     and c.status = 'pending'
     and c.expires_at > v_now
     and exists (
       select 1 from public.ordax_projects p
       where p.project_id = c.project_id
         and p.space_id = c.space_id
         and p.state = 'active'
         and private.ordax_subject_can_admin_space_v1(
           p_owner_user_id, p.space_id
         )
     )
  returning c.project_id, c.space_id, c.expires_at
       into v_project_id, v_space_id, v_expires_at;

  if not found then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_authorization_challenge_invalid'
    );
  end if;

  return pg_catalog.jsonb_build_object(
    'ok', true,
    'challenge_id', p_challenge_id,
    'project_id', v_project_id,
    'expires_at', v_expires_at
  );
end;
$$;

create function public.ordax_owner_complete_github_authorization_v1(
  p_owner_user_id uuid,
  p_challenge_id uuid,
  p_github_user_id bigint,
  p_github_user_login text,
  p_candidates jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_project_id uuid;
  v_space_id uuid;
  v_expires_at timestamptz;
  v_candidate_count integer;
  v_now timestamptz := pg_catalog.timezone('utc', pg_catalog.now());
begin
  if p_owner_user_id is null or p_challenge_id is null
     or p_github_user_id is null or p_github_user_id <= 0
     or p_github_user_login is null
     or char_length(p_github_user_login) not between 1 and 100
     or p_github_user_login !~ '^[A-Za-z0-9-]+$'
     or p_candidates is null
     or pg_catalog.jsonb_typeof(p_candidates) <> 'array'
     or pg_catalog.jsonb_array_length(p_candidates) > 500 then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_authorization_result_invalid'
    );
  end if;

  select c.project_id, c.space_id, c.expires_at
    into v_project_id, v_space_id, v_expires_at
    from private.ordax_owner_github_authorization_challenges c
   where c.challenge_id = p_challenge_id
     and c.owner_user_id = p_owner_user_id
     and c.status = 'verifying'
     and c.expires_at > v_now
     and exists (
       select 1 from public.ordax_projects p
       where p.project_id = c.project_id
         and p.space_id = c.space_id
         and p.state = 'active'
         and private.ordax_subject_can_admin_space_v1(
           p_owner_user_id, p.space_id
         )
     )
   for update;

  if not found then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_authorization_challenge_invalid'
    );
  end if;

  if exists (
    select 1
    from pg_catalog.jsonb_array_elements(p_candidates) e(value)
    where pg_catalog.jsonb_typeof(e.value) <> 'object'
       or (
         select pg_catalog.array_agg(k order by k)
         from pg_catalog.jsonb_object_keys(e.value) k
       ) <> array[
         'default_branch',
         'installation_account_id',
         'installation_account_login',
         'installation_id',
         'repository_full_name',
         'repository_id'
       ]::text[]
       or not (
         case
           when coalesce(e.value->>'installation_id', '') ~ '^[1-9][0-9]{0,18}       or char_length(coalesce(e.value->>'installation_account_login', ''))
            not between 1 and 100
       or coalesce(e.value->>'installation_account_login', '')
            !~ '^[A-Za-z0-9-]+$'
       or char_length(coalesce(e.value->>'repository_full_name', ''))
            not between 3 and 200
       or coalesce(e.value->>'repository_full_name', '')
            !~ '^[^[:space:]/]+/[^[:space:]/]+$'
       or (
         e.value->'default_branch' <> 'null'::jsonb
         and (
           pg_catalog.jsonb_typeof(e.value->'default_branch') <> 'string'
           or char_length(e.value->>'default_branch') not between 1 and 255
           or (e.value->>'default_branch') ~ '[[:cntrl:]]'
         )
       )
  ) then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_repository_candidates_invalid'
    );
  end if;

  if exists (
    select 1
    from pg_catalog.jsonb_array_elements(p_candidates) e(value)
    group by e.value->>'repository_id'
    having pg_catalog.count(*) > 1
  ) then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_repository_candidates_duplicate'
    );
  end if;

  delete from private.ordax_owner_github_repository_candidates r
  where r.challenge_id = p_challenge_id;

  insert into private.ordax_owner_github_repository_candidates(
    challenge_id, installation_id, installation_account_id,
    installation_account_login, repository_id, repository_full_name,
    default_branch, expires_at
  )
  select
    p_challenge_id,
    (e.value->>'installation_id')::bigint,
    (e.value->>'installation_account_id')::bigint,
    e.value->>'installation_account_login',
    (e.value->>'repository_id')::bigint,
    e.value->>'repository_full_name',
    case
      when e.value->'default_branch' = 'null'::jsonb then null
      else e.value->>'default_branch'
    end,
    v_expires_at
  from pg_catalog.jsonb_array_elements(p_candidates) e(value);

  get diagnostics v_candidate_count = row_count;

  update private.ordax_owner_github_authorization_challenges c
     set status = 'verified',
         github_user_id = p_github_user_id,
         github_user_login = p_github_user_login,
         verified_at = v_now,
         updated_at = v_now
   where c.challenge_id = p_challenge_id;

  return pg_catalog.jsonb_build_object(
    'ok', true,
    'challenge_id', p_challenge_id,
    'project_id', v_project_id,
    'candidate_count', v_candidate_count,
    'expires_at', v_expires_at
  );
end;
$$;

create function public.ordax_owner_read_github_repository_candidates_v1(
  p_owner_user_id uuid,
  p_challenge_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_project_id uuid;
  v_expires_at timestamptz;
  v_repositories jsonb;
  v_now timestamptz := pg_catalog.timezone('utc', pg_catalog.now());
begin
  select c.project_id, c.expires_at
    into v_project_id, v_expires_at
    from private.ordax_owner_github_authorization_challenges c
   where c.challenge_id = p_challenge_id
     and c.owner_user_id = p_owner_user_id
     and c.status = 'verified'
     and c.expires_at > v_now
     and exists (
       select 1 from public.ordax_projects p
       where p.project_id = c.project_id
         and p.space_id = c.space_id
         and p.state = 'active'
         and private.ordax_subject_can_admin_space_v1(
           p_owner_user_id, p.space_id
         )
     );

  if not found then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_repository_candidates_unavailable'
    );
  end if;

  select coalesce(
    pg_catalog.jsonb_agg(
      pg_catalog.jsonb_build_object(
        'repository_id', r.repository_id::text,
        'repository_full_name', r.repository_full_name,
        'default_branch', r.default_branch,
        'installation_account_login', r.installation_account_login
      )
      order by pg_catalog.lower(r.repository_full_name), r.repository_id
    ),
    '[]'::jsonb
  )
  into v_repositories
  from private.ordax_owner_github_repository_candidates r
  where r.challenge_id = p_challenge_id and r.expires_at > v_now;

  return pg_catalog.jsonb_build_object(
    'ok', true,
    'challenge_id', p_challenge_id,
    'project_id', v_project_id,
    'repositories', v_repositories,
    'expires_at', v_expires_at
  );
end;
$$;

create function public.ordax_owner_select_github_repository_v1(
  p_owner_user_id uuid,
  p_challenge_id uuid,
  p_repository_id text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_project_id uuid;
  v_space_id uuid;
  v_installation_id bigint;
  v_installation_account_id bigint;
  v_repository_id bigint;
  v_repository_full_name text;
  v_default_branch text;
  v_connection_id uuid;
  v_now timestamptz := pg_catalog.timezone('utc', pg_catalog.now());
begin
  if p_owner_user_id is null or p_challenge_id is null
     or p_repository_id is null
     or not (
       case
         when p_repository_id ~ '^[1-9][0-9]{0,18}    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_repository_selection_invalid'
    );
  end if;

  select c.project_id, c.space_id
    into v_project_id, v_space_id
    from private.ordax_owner_github_authorization_challenges c
   where c.challenge_id = p_challenge_id
     and c.owner_user_id = p_owner_user_id
     and c.status = 'verified'
     and c.expires_at > v_now
     and exists (
       select 1 from public.ordax_projects p
       where p.project_id = c.project_id
         and p.space_id = c.space_id
         and p.state = 'active'
         and private.ordax_subject_can_admin_space_v1(
           p_owner_user_id, p.space_id
         )
     )
   for update;

  if not found then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_authorization_challenge_invalid'
    );
  end if;

  if exists (
    select 1 from public.ordax_project_connections c
    where c.project_id = v_project_id
      and c.space_id = v_space_id
      and c.provider = 'github'
      and c.state = 'active'
  ) then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'project_github_connection_exists'
    );
  end if;

  select r.installation_id,
         r.installation_account_id,
         r.repository_id,
         r.repository_full_name,
         r.default_branch
    into v_installation_id,
         v_installation_account_id,
         v_repository_id,
         v_repository_full_name,
         v_default_branch
  from private.ordax_owner_github_repository_candidates r
  where r.challenge_id = p_challenge_id
    and r.repository_id = p_repository_id::bigint
    and r.expires_at > v_now;

  if not found then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_repository_not_verified'
    );
  end if;

  select c.connection_id into v_connection_id
  from public.ordax_project_connections c
  where c.project_id = v_project_id
    and c.provider = 'github'
    and c.repository_id = v_repository_id
  for update;

  if found then
    update public.ordax_project_connections
       set space_id = v_space_id,
           owner_user_id = p_owner_user_id,
           external_account_id = v_installation_account_id::text,
           installation_id = v_installation_id,
           repository_full_name = v_repository_full_name,
           default_branch = v_default_branch,
           access_mode = 'read',
           state = 'active',
           metadata = pg_catalog.jsonb_build_object(
             'authority', 'github_app_user_authorization_v1'
           ),
           updated_at = v_now
     where connection_id = v_connection_id;
  else
    insert into public.ordax_project_connections(
      space_id, owner_user_id, provider, external_account_id,
      installation_id, repository_id, repository_full_name,
      default_branch, access_mode, state, metadata, project_id
    ) values (
      v_space_id, p_owner_user_id, 'github',
      v_installation_account_id::text, v_installation_id, v_repository_id,
      v_repository_full_name, v_default_branch, 'read', 'active',
      pg_catalog.jsonb_build_object(
        'authority', 'github_app_user_authorization_v1'
      ),
      v_project_id
    )
    returning connection_id into v_connection_id;
  end if;

  update private.ordax_owner_github_authorization_challenges c
     set status = 'selected', consumed_at = v_now, updated_at = v_now
   where c.challenge_id = p_challenge_id;

  delete from private.ordax_owner_github_repository_candidates r
  where r.challenge_id = p_challenge_id;

  return pg_catalog.jsonb_build_object(
    'ok', true,
    'connection_id', v_connection_id,
    'project_id', v_project_id,
    'repository_id', v_repository_id::text,
    'repository_full_name', v_repository_full_name,
    'default_branch', v_default_branch,
    'state', 'active',
    'next_state', 'needs_device_binding'
  );
end;
$$;

revoke all on function public.ordax_owner_create_github_authorization_challenge_v1(
  uuid, uuid, uuid, text, timestamptz
) from public, anon, authenticated, service_role, ordax_edge_executor,
  ordax_space_executor, ordax_project_executor, ordax_edge_runtime,
  ordax_owner_project_onboarding_executor;
revoke all on function public.ordax_owner_begin_github_authorization_completion_v1(
  uuid, uuid, text
) from public, anon, authenticated, service_role, ordax_edge_executor,
  ordax_space_executor, ordax_project_executor, ordax_edge_runtime,
  ordax_owner_project_onboarding_executor;
revoke all on function public.ordax_owner_complete_github_authorization_v1(
  uuid, uuid, bigint, text, jsonb
) from public, anon, authenticated, service_role, ordax_edge_executor,
  ordax_space_executor, ordax_project_executor, ordax_edge_runtime,
  ordax_owner_project_onboarding_executor;
revoke all on function public.ordax_owner_read_github_repository_candidates_v1(
  uuid, uuid
) from public, anon, authenticated, service_role, ordax_edge_executor,
  ordax_space_executor, ordax_project_executor, ordax_edge_runtime,
  ordax_owner_project_onboarding_executor;
revoke all on function public.ordax_owner_select_github_repository_v1(
  uuid, uuid, text
) from public, anon, authenticated, service_role, ordax_edge_executor,
  ordax_space_executor, ordax_project_executor, ordax_edge_runtime,
  ordax_owner_project_onboarding_executor;

grant execute on function public.ordax_owner_create_github_authorization_challenge_v1(
  uuid, uuid, uuid, text, timestamptz
) to ordax_owner_project_onboarding_executor;
grant execute on function public.ordax_owner_begin_github_authorization_completion_v1(
  uuid, uuid, text
) to ordax_owner_project_onboarding_executor;
grant execute on function public.ordax_owner_complete_github_authorization_v1(
  uuid, uuid, bigint, text, jsonb
) to ordax_owner_project_onboarding_executor;
grant execute on function public.ordax_owner_read_github_repository_candidates_v1(
  uuid, uuid
) to ordax_owner_project_onboarding_executor;
grant execute on function public.ordax_owner_select_github_repository_v1(
  uuid, uuid, text
) to ordax_owner_project_onboarding_executor;

do $postflight$
declare
  v_relation_authority integer;
begin
  select pg_catalog.count(*) into v_relation_authority
  from pg_catalog.pg_class c
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
  where n.nspname in ('public', 'private')
    and c.relkind in ('r', 'p', 'v', 'm', 'f', 'S')
    and (
      (c.relkind = 'S' and (
        pg_catalog.has_sequence_privilege(
          'ordax_owner_project_onboarding_executor', c.oid, 'USAGE'
        )
        or pg_catalog.has_sequence_privilege(
          'ordax_owner_project_onboarding_executor', c.oid, 'SELECT'
        )
        or pg_catalog.has_sequence_privilege(
          'ordax_owner_project_onboarding_executor', c.oid, 'UPDATE'
        )
      ))
      or
      (c.relkind <> 'S' and (
        pg_catalog.has_table_privilege(
          'ordax_owner_project_onboarding_executor', c.oid, 'SELECT'
        )
        or pg_catalog.has_table_privilege(
          'ordax_owner_project_onboarding_executor', c.oid, 'INSERT'
        )
        or pg_catalog.has_table_privilege(
          'ordax_owner_project_onboarding_executor', c.oid, 'UPDATE'
        )
        or pg_catalog.has_table_privilege(
          'ordax_owner_project_onboarding_executor', c.oid, 'DELETE'
        )
      ))
    );

  if v_relation_authority <> 0 then
    raise exception 'owner github authority: direct relation authority detected';
  end if;

  if pg_catalog.has_schema_privilege(
    'ordax_owner_project_onboarding_executor', 'private', 'USAGE'
  ) then
    raise exception 'owner github authority: private schema unexpectedly visible';
  end if;
end;
$postflight$;

commit;
