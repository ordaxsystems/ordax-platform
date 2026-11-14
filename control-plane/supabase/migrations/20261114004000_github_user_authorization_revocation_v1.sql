begin;

-- User-level GitHub App authorization revocation is independent of installation
-- removal. Persist only the verified GitHub user id in server-side connection
-- metadata so a signed github_app_authorization webhook can revoke authority
-- without storing user access tokens.

do $preflight$
begin
  if exists (
    select 1
    from public.ordax_project_connections c
    where c.provider = 'github'
      and c.state = 'active'
      and (
        c.metadata is null
        or not (c.metadata ? 'verified_at')
        or not (c.metadata ? 'verified_github_user_id')
      )
  ) then
    raise exception 'github user revocation: active connection requires explicit user-authority backfill';
  end if;
end;
$preflight$;

alter table private.ordax_github_webhook_deliveries
  add column github_user_id bigint;

alter table private.ordax_github_webhook_deliveries
  alter column installation_id drop not null;

alter table private.ordax_github_webhook_deliveries
  drop constraint ordax_github_webhook_deliveries_installation_id_check,
  drop constraint ordax_github_webhook_deliveries_event_check;

alter table private.ordax_github_webhook_deliveries
  add constraint ordax_github_webhook_deliveries_event_check
    check (event in (
      'github_app_authorization','installation','installation_repositories','repository'
    )),
  add constraint ordax_github_webhook_deliveries_provider_identity_check
    check (
      (
        event = 'github_app_authorization'
        and action = 'revoked'
        and installation_id is null
        and github_user_id is not null
        and github_user_id > 0
        and cardinality(repository_ids) = 0
      )
      or
      (
        event <> 'github_app_authorization'
        and installation_id is not null
        and installation_id > 0
        and github_user_id is null
      )
    );

alter table private.ordax_github_authority_revocations
  add column github_user_id bigint;

alter table private.ordax_github_authority_revocations
  alter column installation_id drop not null;

alter table private.ordax_github_authority_revocations
  drop constraint ordax_github_authority_revocations_installation_id_check,
  drop constraint ordax_github_authority_revocations_scope_kind_check,
  drop constraint ordax_github_authority_revocations_check;

alter table private.ordax_github_authority_revocations
  add constraint ordax_github_authority_revocations_scope_kind_check
    check (scope_kind in ('user','installation','repository')),
  add constraint ordax_github_authority_revocations_provider_identity_check
    check (
      (
        scope_kind = 'user'
        and github_user_id is not null
        and github_user_id > 0
        and installation_id is null
        and repository_id is null
      )
      or
      (
        scope_kind = 'installation'
        and github_user_id is null
        and installation_id is not null
        and installation_id > 0
        and repository_id is null
      )
      or
      (
        scope_kind = 'repository'
        and github_user_id is null
        and installation_id is not null
        and installation_id > 0
        and repository_id is not null
        and repository_id > 0
      )
    );

create unique index ordax_github_authority_revocations_user_uq
  on private.ordax_github_authority_revocations(github_user_id)
  where scope_kind = 'user';

revoke all on function public.ordax_apply_github_authority_revocation_v1(
  uuid,text,text,bigint,bigint[],text
) from public, anon, authenticated, service_role, ordax_edge_executor,
  ordax_edge_runtime, ordax_owner_project_onboarding_executor,
  ordax_github_webhook_executor;

drop function public.ordax_apply_github_authority_revocation_v1(
  uuid,text,text,bigint,bigint[],text
);

create function public.ordax_apply_github_authority_revocation_v2(
  p_delivery_id uuid,
  p_event text,
  p_action text,
  p_installation_id bigint,
  p_github_user_id bigint,
  p_repository_ids bigint[],
  p_payload_sha256 text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_repository_ids bigint[];
  v_existing private.ordax_github_webhook_deliveries%rowtype;
  v_project_ids uuid[] := '{}'::uuid[];
  v_connection_count integer := 0;
  v_binding_count integer := 0;
  v_grant_count integer := 0;
  v_action_count integer := 0;
  v_intent_count integer := 0;
  v_repository_id bigint;
begin
  select coalesce(pg_catalog.array_agg(x order by x), '{}'::bigint[])
    into v_repository_ids
  from (
    select distinct value as x
    from pg_catalog.unnest(coalesce(p_repository_ids, '{}'::bigint[])) value
  ) canonical;

  if p_delivery_id is null
     or p_payload_sha256 is null
     or p_payload_sha256 !~ '^[0-9a-f]{64}$'
     or p_event not in (
       'github_app_authorization','installation','installation_repositories','repository'
     )
     or p_action is null
     or char_length(p_action) not between 1 and 80
     or p_action ~ '[[:cntrl:]]'
     or pg_catalog.cardinality(v_repository_ids) > 500
     or exists (
       select 1 from pg_catalog.unnest(v_repository_ids) x where x <= 0
     )
  then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_webhook_revocation_invalid'
    );
  end if;

  if (
       p_event = 'github_app_authorization'
       and (
         p_action <> 'revoked'
         or p_installation_id is not null
         or p_github_user_id is null
         or p_github_user_id <= 0
         or pg_catalog.cardinality(v_repository_ids) <> 0
       )
     )
     or (
       p_event = 'installation'
       and (
         p_action not in ('deleted','suspend')
         or p_installation_id is null
         or p_installation_id <= 0
         or p_github_user_id is not null
         or pg_catalog.cardinality(v_repository_ids) <> 0
       )
     )
     or (
       p_event = 'installation_repositories'
       and (
         p_action not in ('added','removed')
         or p_installation_id is null
         or p_installation_id <= 0
         or p_github_user_id is not null
         or pg_catalog.cardinality(v_repository_ids) = 0
       )
     )
     or (
       p_event = 'repository'
       and (
         p_action not in ('archived','deleted','renamed','transferred')
         or p_installation_id is null
         or p_installation_id <= 0
         or p_github_user_id is not null
         or pg_catalog.cardinality(v_repository_ids) <> 1
       )
     )
  then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_webhook_revocation_invalid'
    );
  end if;

  if p_event = 'github_app_authorization' then
    perform pg_catalog.pg_advisory_xact_lock(
      pg_catalog.hashtextextended(
        'ordax-github-user:' || p_github_user_id::text,
        0
      )
    );
  else
    perform pg_catalog.pg_advisory_xact_lock(
      pg_catalog.hashtextextended(
        'ordax-github-installation:' || p_installation_id::text,
        0
      )
    );
  end if;

  select *
    into v_existing
  from private.ordax_github_webhook_deliveries d
  where d.delivery_id = p_delivery_id;

  if found then
    if v_existing.event = p_event
       and v_existing.action = p_action
       and v_existing.installation_id is not distinct from p_installation_id
       and v_existing.github_user_id is not distinct from p_github_user_id
       and v_existing.repository_ids = v_repository_ids
       and v_existing.payload_sha256 = p_payload_sha256
    then
      return pg_catalog.jsonb_build_object(
        'ok', true,
        'replayed', true,
        'delivery_id', p_delivery_id,
        'connection_count', v_existing.connection_count,
        'binding_count', v_existing.binding_count,
        'grant_count', v_existing.grant_count,
        'action_count', v_existing.action_count,
        'intent_count', v_existing.intent_count
      );
    end if;

    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_webhook_delivery_conflict'
    );
  end if;

  insert into private.ordax_github_webhook_deliveries(
    delivery_id,event,action,installation_id,github_user_id,
    repository_ids,payload_sha256
  ) values (
    p_delivery_id,p_event,p_action,p_installation_id,p_github_user_id,
    v_repository_ids,p_payload_sha256
  );

  if p_event = 'github_app_authorization' then
    delete from private.ordax_github_authority_revocations r
    where r.scope_kind = 'user'
      and r.github_user_id = p_github_user_id;

    insert into private.ordax_github_authority_revocations(
      scope_kind,installation_id,repository_id,github_user_id,delivery_id,
      event,action,payload_sha256,revoked_at
    ) values (
      'user',null,null,p_github_user_id,p_delivery_id,
      p_event,p_action,p_payload_sha256,v_now
    );
  elsif p_event = 'installation' then
    delete from private.ordax_github_authority_revocations r
    where r.scope_kind = 'installation'
      and r.installation_id = p_installation_id;

    insert into private.ordax_github_authority_revocations(
      scope_kind,installation_id,repository_id,github_user_id,delivery_id,
      event,action,payload_sha256,revoked_at
    ) values (
      'installation',p_installation_id,null,null,p_delivery_id,
      p_event,p_action,p_payload_sha256,v_now
    );
  else
    foreach v_repository_id in array v_repository_ids loop
      delete from private.ordax_github_authority_revocations r
      where r.scope_kind = 'repository'
        and r.installation_id = p_installation_id
        and r.repository_id = v_repository_id;

      insert into private.ordax_github_authority_revocations(
        scope_kind,installation_id,repository_id,github_user_id,delivery_id,
        event,action,payload_sha256,revoked_at
      ) values (
        'repository',p_installation_id,v_repository_id,null,p_delivery_id,
        p_event,p_action,p_payload_sha256,v_now
      );
    end loop;
  end if;

  select coalesce(pg_catalog.array_agg(distinct c.project_id), '{}'::uuid[]),
         pg_catalog.count(*)::integer
    into v_project_ids, v_connection_count
  from public.ordax_project_connections c
  where c.provider = 'github'
    and c.state = 'active'
    and (
      (
        p_event = 'github_app_authorization'
        and c.metadata->>'verified_github_user_id' = p_github_user_id::text
      )
      or
      (
        p_event <> 'github_app_authorization'
        and c.installation_id = p_installation_id
        and (
          p_event = 'installation'
          or c.repository_id = any(v_repository_ids)
        )
      )
    );

  update public.ordax_project_connections c
     set state = 'revoked',
         metadata = coalesce(c.metadata, '{}'::jsonb)
           || pg_catalog.jsonb_build_object(
             'github_authority_revocation',
             pg_catalog.jsonb_build_object(
               'delivery_id', p_delivery_id,
               'event', p_event,
               'action', p_action,
               'revoked_at', v_now
             )
           ),
         updated_at = v_now
   where c.provider = 'github'
     and c.state = 'active'
     and (
       (
         p_event = 'github_app_authorization'
         and c.metadata->>'verified_github_user_id' = p_github_user_id::text
       )
       or
       (
         p_event <> 'github_app_authorization'
         and c.installation_id = p_installation_id
         and (
           p_event = 'installation'
           or c.repository_id = any(v_repository_ids)
         )
       )
     );

  update public.ordax_device_project_bindings b
     set state = 'revoked',
         updated_at = v_now
   where b.state = 'active'
     and b.project_id = any(v_project_ids);
  get diagnostics v_binding_count = row_count;

  update public.ordax_remote_capability_grants g
     set state = 'revoked',
         updated_at = v_now
   where g.state = 'active'
     and g.project_id = any(v_project_ids);
  get diagnostics v_grant_count = row_count;

  update private.ordax_owner_project_device_binding_intents i
     set consumed_at = v_now
   where i.consumed_at is null
     and i.project_id = any(v_project_ids);
  get diagnostics v_intent_count = row_count;

  update private.ordax_product_action_requests a
     set status = 'cancelled',
         lease_expires_at = null,
         finished_at = v_now,
         error_code = 'github_authority_revoked'
   where a.project_id = any(v_project_ids)
     and a.status in ('queued','leased','running');
  get diagnostics v_action_count = row_count;

  update private.ordax_github_webhook_deliveries d
     set connection_count = v_connection_count,
         binding_count = v_binding_count,
         grant_count = v_grant_count,
         action_count = v_action_count,
         intent_count = v_intent_count,
         processed_at = v_now
   where d.delivery_id = p_delivery_id;

  return pg_catalog.jsonb_build_object(
    'ok', true,
    'replayed', false,
    'delivery_id', p_delivery_id,
    'connection_count', v_connection_count,
    'binding_count', v_binding_count,
    'grant_count', v_grant_count,
    'action_count', v_action_count,
    'intent_count', v_intent_count
  );
end;
$$;

revoke all on function public.ordax_apply_github_authority_revocation_v2(
  uuid,text,text,bigint,bigint,bigint[],text
) from public, anon, authenticated, service_role, ordax_edge_executor,
  ordax_edge_runtime, ordax_owner_project_onboarding_executor,
  ordax_github_webhook_executor;

grant execute on function public.ordax_apply_github_authority_revocation_v2(
  uuid,text,text,bigint,bigint,bigint[],text
) to ordax_github_webhook_executor;

create or replace function public.ordax_owner_select_github_repository_v1(
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
  v_verified_at timestamptz;
  v_github_user_id bigint;
  v_now timestamptz := pg_catalog.timezone('utc', pg_catalog.now());
begin
  if p_owner_user_id is null or p_challenge_id is null
     or p_repository_id is null
     or not (
       case
         when p_repository_id ~ '^[1-9][0-9]{0,18}$'
         then p_repository_id::numeric <= 9223372036854775807
         else false
       end
     ) then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_repository_selection_invalid'
    );
  end if;

  select c.project_id, c.space_id, c.verified_at, c.github_user_id
    into v_project_id, v_space_id, v_verified_at, v_github_user_id
    from private.ordax_owner_github_authorization_challenges c
   where c.challenge_id = p_challenge_id
     and c.owner_user_id = p_owner_user_id
     and c.status = 'verified'
     and c.expires_at > v_now
     and exists (
       select 1
         from public.ordax_projects p
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

  -- Serialize selections across distinct challenges for the same Project.
  -- This keeps one active GitHub connection authoritative under concurrency.
  perform 1
    from public.ordax_projects p
   where p.project_id = v_project_id
     and p.space_id = v_space_id
     and p.state = 'active'
   for update;

  if not found then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'project_not_found_or_inactive'
    );
  end if;

  if exists (
    select 1
      from public.ordax_project_connections c
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

  if v_verified_at is null or v_github_user_id is null or v_github_user_id <= 0 then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_authorization_challenge_invalid'
    );
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      'ordax-github-user:' || v_github_user_id::text,
      0
    )
  );
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended(
      'ordax-github-installation:' || v_installation_id::text,
      0
    )
  );

  if exists (
    select 1
    from private.ordax_github_authority_revocations r
    where (
      r.scope_kind = 'user'
      and r.github_user_id = v_github_user_id
      and r.revoked_at >= v_verified_at
    ) or (
      r.installation_id = v_installation_id
      and (
        r.scope_kind = 'installation'
        or (
          r.scope_kind = 'repository'
          and r.repository_id = v_repository_id
        )
      )
      and r.revoked_at >= v_verified_at
    )
  ) then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'github_repository_authority_revoked'
    );
  end if;

  select c.connection_id
    into v_connection_id
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
             'authority', 'github_app_user_authorization_v1',
             'verified_at', v_verified_at,
             'verified_github_user_id', v_github_user_id::text
           ),
           updated_at = v_now
     where connection_id = v_connection_id;
  else
    insert into public.ordax_project_connections(
      space_id,
      owner_user_id,
      provider,
      external_account_id,
      installation_id,
      repository_id,
      repository_full_name,
      default_branch,
      access_mode,
      state,
      metadata,
      project_id
    ) values (
      v_space_id,
      p_owner_user_id,
      'github',
      v_installation_account_id::text,
      v_installation_id,
      v_repository_id,
      v_repository_full_name,
      v_default_branch,
      'read',
      'active',
      pg_catalog.jsonb_build_object(
        'authority', 'github_app_user_authorization_v1',
        'verified_at', v_verified_at,
        'verified_github_user_id', v_github_user_id::text
      ),
      v_project_id
    )
    returning connection_id into v_connection_id;
  end if;

  update private.ordax_owner_github_authorization_challenges c
     set status = 'selected',
         consumed_at = v_now,
         updated_at = v_now
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


create or replace function private.ordax_guard_active_github_connection_v1()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_verified_at timestamptz;
  v_github_user_id bigint;
  v_github_user_id_text text;
begin
  if new.provider <> 'github' or new.state <> 'active' then
    return new;
  end if;

  v_github_user_id_text := new.metadata->>'verified_github_user_id';

  if new.installation_id is null
     or new.repository_id is null
     or new.metadata is null
     or not (new.metadata ? 'verified_at')
     or not (new.metadata ? 'verified_github_user_id')
     or v_github_user_id_text is null
     or v_github_user_id_text !~ '^[1-9][0-9]{0,18}$'
     or v_github_user_id_text::numeric > 9223372036854775807
  then
    raise exception 'github connection activation requires verified authority metadata';
  end if;

  v_verified_at := (new.metadata->>'verified_at')::timestamptz;
  v_github_user_id := v_github_user_id_text::bigint;
  if v_verified_at is null then
    raise exception 'github connection activation requires verified authority timestamp';
  end if;

  if exists (
    select 1
    from private.ordax_github_authority_revocations r
    where (
      r.scope_kind = 'user'
      and r.github_user_id = v_github_user_id
      and r.revoked_at >= v_verified_at
    ) or (
      r.installation_id = new.installation_id
      and (
        r.scope_kind = 'installation'
        or (
          r.scope_kind = 'repository'
          and r.repository_id = new.repository_id
        )
      )
      and r.revoked_at >= v_verified_at
    )
  ) then
    raise exception 'github connection authority was revoked after verification';
  end if;

  return new;
end;
$$;

revoke all on function private.ordax_guard_active_github_connection_v1()
  from public, anon, authenticated, service_role, ordax_edge_executor,
       ordax_edge_runtime, ordax_owner_project_onboarding_executor,
       ordax_github_webhook_executor;

do $postflight$
declare
  v_direct integer;
  v_unexpected_exec integer;
begin
  if to_regprocedure(
       'public.ordax_apply_github_authority_revocation_v1(uuid,text,text,bigint,bigint[],text)'
     ) is not null
  then
    raise exception 'github user revocation: v1 RPC must not remain';
  end if;

  if not pg_catalog.has_function_privilege(
       'ordax_github_webhook_executor',
       'public.ordax_apply_github_authority_revocation_v2(uuid,text,text,bigint,bigint,bigint[],text)',
       'EXECUTE'
     )
     or pg_catalog.has_function_privilege(
       'authenticated',
       'public.ordax_apply_github_authority_revocation_v2(uuid,text,text,bigint,bigint,bigint[],text)',
       'EXECUTE'
     )
     or pg_catalog.has_function_privilege(
       'service_role',
       'public.ordax_apply_github_authority_revocation_v2(uuid,text,text,bigint,bigint,bigint[],text)',
       'EXECUTE'
     )
  then
    raise exception 'github user revocation: v2 execute boundary invalid';
  end if;

  select pg_catalog.count(*) into v_direct
  from pg_catalog.pg_class c
  join pg_catalog.pg_namespace n on n.oid=c.relnamespace
  where n.nspname in ('public','private')
    and c.relkind in ('r','p','v','m','f','S')
    and (
      (c.relkind='S' and (
        pg_catalog.has_sequence_privilege('ordax_github_webhook_executor',c.oid,'USAGE')
        or pg_catalog.has_sequence_privilege('ordax_github_webhook_executor',c.oid,'SELECT')
        or pg_catalog.has_sequence_privilege('ordax_github_webhook_executor',c.oid,'UPDATE')
      ))
      or
      (c.relkind<>'S' and (
        pg_catalog.has_table_privilege('ordax_github_webhook_executor',c.oid,'SELECT')
        or pg_catalog.has_table_privilege('ordax_github_webhook_executor',c.oid,'INSERT')
        or pg_catalog.has_table_privilege('ordax_github_webhook_executor',c.oid,'UPDATE')
        or pg_catalog.has_table_privilege('ordax_github_webhook_executor',c.oid,'DELETE')
      ))
    );

  if v_direct <> 0 then
    raise exception 'github user revocation: executor has direct relation authority';
  end if;

  select pg_catalog.count(*) into v_unexpected_exec
  from pg_catalog.pg_proc p
  join pg_catalog.pg_namespace n on n.oid=p.pronamespace
  where n.nspname='public'
    and pg_catalog.has_function_privilege(
      'ordax_github_webhook_executor',p.oid,'EXECUTE'
    )
    and p.oid <> 'public.ordax_apply_github_authority_revocation_v2(uuid,text,text,bigint,bigint,bigint[],text)'::regprocedure;

  if v_unexpected_exec <> 0 then
    raise exception 'github user revocation: executor can execute unexpected public function';
  end if;
end;
$postflight$;

commit;
