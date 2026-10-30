-- Account Sync must not depend on direct auth-schema USAGE:
-- Supabase owns schema auth, so product executors cannot safely obtain access.
-- Reuse the existing, read-only subject bridge already owned by postgres;
-- it returns only auth.uid() under the caller JWT and reads no table.
begin;

do $preflight$
begin
 if not exists (select 1 from pg_roles where rolname='ordax_sync_executor' and not rolcanlogin and not rolbypassrls and not rolinherit and not rolsuper) then raise exception 'sync executor role contract drifted'; end if;
 if to_regprocedure('public.ordax_request_subject_v1()') is null then raise exception 'canonical subject bridge missing'; end if;
 if has_function_privilege('anon','public.ordax_request_subject_v1()','EXECUTE') or has_function_privilege('authenticated','public.ordax_request_subject_v1()','EXECUTE') or has_function_privilege('service_role','public.ordax_request_subject_v1()','EXECUTE') then raise exception 'subject bridge exposed to API roles'; end if;
 if pg_get_userbyid((select proowner from pg_proc where oid='public.ordax_request_subject_v1()'::regprocedure))<>'postgres' then raise exception 'subject bridge owner is not postgres'; end if;
 if (select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and pg_get_userbyid(p.proowner)='ordax_sync_executor' and p.proname in ('ordax_apply_sync_mutation_v1','ordax_apply_sync_mutation_v2','ordax_list_sync_objects_v1','ordax_pull_sync_changes_v1','ordax_sync_snapshot_v1','ordax_sync_snapshot_page_v2') and p.prosecdef)<>6 then raise exception 'sync rpc owner contract missing'; end if;
end;
$preflight$;

grant usage on schema public to ordax_sync_executor;
grant execute on function public.ordax_request_subject_v1() to ordax_sync_executor;

-- Preserve five existing RLS policies; change only their subject source.
alter policy ordax_sync_objects_select_own on private.ordax_sync_objects
 using (owner_user_id=(select public.ordax_request_subject_v1()));
alter policy ordax_sync_objects_insert_own on private.ordax_sync_objects
 with check (owner_user_id=(select public.ordax_request_subject_v1()));
alter policy ordax_sync_objects_update_own on private.ordax_sync_objects
 using (owner_user_id=(select public.ordax_request_subject_v1()))
 with check (owner_user_id=(select public.ordax_request_subject_v1()));
alter policy ordax_sync_mutations_select_own on private.ordax_sync_mutations
 using (owner_user_id=(select public.ordax_request_subject_v1()));
alter policy ordax_sync_mutations_insert_own on private.ordax_sync_mutations
 with check (owner_user_id=(select public.ordax_request_subject_v1()));

-- Recompile only the existing six owner-bound RPCs, preserving every signature,
-- data-class rule, revision/cursor semantics and the NOLOGIN/NOBYPASSRLS owner.
-- ordax_apply_sync_mutation_v1 (replaced 1 direct auth.uid calls)
CREATE OR REPLACE FUNCTION public.ordax_apply_sync_mutation_v1(p_idempotency_key text, p_data_class text, p_stable_object_id text, p_object_schema_version integer, p_resolver_version integer, p_base_server_revision bigint, p_tombstone boolean, p_payload jsonb)
 RETURNS TABLE(sync_object_id uuid, server_revision bigint, tombstone boolean, applied boolean, conflict boolean)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_user_id uuid := (select public.ordax_request_subject_v1());
  v_existing private.ordax_sync_objects%rowtype;
  v_mutation private.ordax_sync_mutations%rowtype;
  v_revision bigint;
begin
  if v_user_id is null then raise exception 'authentication-required' using errcode = '42501'; end if;
  if p_idempotency_key is null or char_length(p_idempotency_key) < 8 or char_length(p_idempotency_key) > 200 then raise exception 'invalid-idempotency-key' using errcode = '22023'; end if;
  if p_data_class not in ('appearance','preferences','workspace-metadata','app-state-metadata','user-selected-cloud-content') then raise exception 'invalid-data-class' using errcode = '22023'; end if;
  if p_stable_object_id is null or char_length(p_stable_object_id) < 1 or char_length(p_stable_object_id) > 240 then raise exception 'invalid-stable-object-id' using errcode = '22023'; end if;
  if p_object_schema_version is null or p_object_schema_version <= 0 or p_resolver_version is null or p_resolver_version <= 0 then raise exception 'invalid-schema-version' using errcode = '22023'; end if;
  if p_payload is null or jsonb_typeof(p_payload) <> 'object' then raise exception 'payload-must-be-object' using errcode = '22023'; end if;

  select * into v_mutation from private.ordax_sync_mutations
  where owner_user_id = v_user_id and idempotency_key = p_idempotency_key;

  if found then
    select * into v_existing from private.ordax_sync_objects
    where owner_user_id = v_user_id and data_class = v_mutation.data_class and stable_object_id = v_mutation.stable_object_id;
    return query select v_existing.sync_object_id, v_mutation.resulting_server_revision, v_mutation.tombstone, false, false;
    return;
  end if;

  select * into v_existing from private.ordax_sync_objects
  where owner_user_id = v_user_id and data_class = p_data_class and stable_object_id = p_stable_object_id
  for update;

  if found then
    if p_base_server_revision is null or p_base_server_revision <> v_existing.server_revision then
      return query select v_existing.sync_object_id, v_existing.server_revision, v_existing.tombstone, false, true;
      return;
    end if;
    v_revision := v_existing.server_revision + 1;
    update private.ordax_sync_objects
      set object_schema_version = p_object_schema_version,
          resolver_version = p_resolver_version,
          server_revision = v_revision,
          tombstone = p_tombstone,
          payload = p_payload,
          updated_at = timezone('utc', now())
      where sync_object_id = v_existing.sync_object_id
      returning * into v_existing;
  else
    if coalesce(p_base_server_revision, 0) <> 0 then
      return query select null::uuid, 0::bigint, false, false, true;
      return;
    end if;
    v_revision := 1;
    insert into private.ordax_sync_objects(
      owner_user_id, data_class, stable_object_id, object_schema_version,
      resolver_version, server_revision, tombstone, payload
    ) values (
      v_user_id, p_data_class, p_stable_object_id, p_object_schema_version,
      p_resolver_version, v_revision, p_tombstone, p_payload
    )
    returning * into v_existing;
  end if;

  insert into private.ordax_sync_mutations(
    owner_user_id, idempotency_key, data_class, stable_object_id,
    base_server_revision, resulting_server_revision, mutation_kind,
    object_schema_version, resolver_version, tombstone, payload
  ) values (
    v_user_id, p_idempotency_key, p_data_class, p_stable_object_id,
    p_base_server_revision, v_revision, case when p_tombstone then 'delete' else 'upsert' end,
    p_object_schema_version, p_resolver_version, p_tombstone, p_payload
  );

  return query select v_existing.sync_object_id, v_revision, p_tombstone, true, false;
end;
$function$;

-- ordax_apply_sync_mutation_v2 (replaced 1 direct auth.uid calls)
CREATE OR REPLACE FUNCTION public.ordax_apply_sync_mutation_v2(p_idempotency_key text, p_data_class text, p_stable_object_id text, p_object_schema_version integer, p_resolver_version integer, p_base_server_revision bigint, p_tombstone boolean, p_payload jsonb)
 RETURNS TABLE(sync_object_id uuid, server_revision bigint, tombstone boolean, applied boolean, conflict boolean, change_cursor bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_user_id uuid := (select public.ordax_request_subject_v1());
  v_result record;
  v_cursor bigint;
begin
  if v_user_id is null then raise exception 'authentication-required' using errcode = '42501'; end if;

  select * into v_result
  from public.ordax_apply_sync_mutation_v1(
    p_idempotency_key, p_data_class, p_stable_object_id,
    p_object_schema_version, p_resolver_version,
    p_base_server_revision, p_tombstone, p_payload
  );

  select m.change_seq into v_cursor
  from private.ordax_sync_mutations m
  where m.owner_user_id = v_user_id and m.idempotency_key = p_idempotency_key;

  return query select
    v_result.sync_object_id, v_result.server_revision, v_result.tombstone,
    v_result.applied, v_result.conflict, v_cursor;
end;
$function$;

-- ordax_list_sync_objects_v1 (replaced 1 direct auth.uid calls)
CREATE OR REPLACE FUNCTION public.ordax_list_sync_objects_v1(p_after_revision bigint DEFAULT 0, p_limit integer DEFAULT 200)
 RETURNS TABLE(sync_object_id uuid, data_class text, stable_object_id text, object_schema_version integer, resolver_version integer, server_revision bigint, tombstone boolean, payload jsonb, updated_at timestamp with time zone)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select
    s.sync_object_id,
    s.data_class,
    s.stable_object_id,
    s.object_schema_version,
    s.resolver_version,
    s.server_revision,
    s.tombstone,
    s.payload,
    s.updated_at
  from private.ordax_sync_objects s
  where s.owner_user_id = (select public.ordax_request_subject_v1())
    and s.server_revision > greatest(coalesce(p_after_revision, 0), 0)
  order by s.server_revision, s.sync_object_id
  limit least(greatest(coalesce(p_limit, 200), 1), 500)
$function$;

-- ordax_pull_sync_changes_v1 (replaced 1 direct auth.uid calls)
CREATE OR REPLACE FUNCTION public.ordax_pull_sync_changes_v1(p_after_cursor bigint DEFAULT 0, p_limit integer DEFAULT 200)
 RETURNS TABLE(change_cursor bigint, data_class text, stable_object_id text, object_schema_version integer, resolver_version integer, server_revision bigint, tombstone boolean, payload jsonb, changed_at timestamp with time zone)
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select
    m.change_seq, m.data_class, m.stable_object_id,
    m.object_schema_version, m.resolver_version,
    m.resulting_server_revision, m.tombstone, m.payload, m.applied_at
  from private.ordax_sync_mutations m
  where m.owner_user_id = (select public.ordax_request_subject_v1())
    and m.change_seq > greatest(coalesce(p_after_cursor, 0), 0)
  order by m.change_seq
  limit least(greatest(coalesce(p_limit, 200), 1), 500);
$function$;

-- ordax_sync_snapshot_page_v2 (replaced 1 direct auth.uid calls)
CREATE OR REPLACE FUNCTION public.ordax_sync_snapshot_page_v2(p_cursor bigint DEFAULT NULL::bigint, p_after_data_class text DEFAULT NULL::text, p_after_stable_object_id text DEFAULT NULL::text, p_limit integer DEFAULT 200)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_user_id uuid := (select public.ordax_request_subject_v1());
  v_current_cursor bigint;
  v_cursor bigint;
  v_has_more boolean;
  v_next_data_class text;
  v_next_stable_object_id text;
  v_objects jsonb;
begin
  if v_user_id is null then
    raise exception 'authentication-required' using errcode = '42501';
  end if;
  if p_limit is null or p_limit < 1 or p_limit > 500 then
    raise exception 'invalid-snapshot-page-limit' using errcode = '22023';
  end if;
  if (p_after_data_class is null) <> (p_after_stable_object_id is null) then
    raise exception 'invalid-snapshot-page-token' using errcode = '22023';
  end if;
  if p_after_data_class is not null and (
    char_length(p_after_data_class) < 1 or char_length(p_after_data_class) > 80
    or char_length(p_after_stable_object_id) < 1 or char_length(p_after_stable_object_id) > 240
  ) then
    raise exception 'invalid-snapshot-page-token' using errcode = '22023';
  end if;
  if p_cursor is not null and p_cursor < 0 then
    raise exception 'invalid-snapshot-cursor' using errcode = '22023';
  end if;

  select coalesce(max(m.change_seq), 0)::bigint
    into v_current_cursor
  from private.ordax_sync_mutations m
  where m.owner_user_id = v_user_id;

  if p_cursor is null then
    v_cursor := v_current_cursor;
  elsif p_cursor > v_current_cursor then
    raise exception 'snapshot-cursor-ahead-of-account-history' using errcode = '22023';
  else
    v_cursor := p_cursor;
  end if;

  if exists (
    select 1
    from private.ordax_sync_objects o
    where o.owner_user_id = v_user_id
      and not exists (
        select 1
        from private.ordax_sync_mutations m
        where m.owner_user_id = o.owner_user_id
          and m.data_class = o.data_class
          and m.stable_object_id = o.stable_object_id
      )
  ) then
    raise exception 'sync-object-history-missing' using errcode = '55000';
  end if;

  with eligible as materialized (
    select
      o.sync_object_id,
      o.data_class,
      o.stable_object_id,
      o.object_schema_version,
      o.resolver_version,
      o.server_revision,
      o.tombstone,
      o.payload,
      o.updated_at
    from private.ordax_sync_objects o
    join lateral (
      select m.change_seq
      from private.ordax_sync_mutations m
      where m.owner_user_id = o.owner_user_id
        and m.data_class = o.data_class
        and m.stable_object_id = o.stable_object_id
      order by m.change_seq desc
      limit 1
    ) latest on true
    where o.owner_user_id = v_user_id
      and latest.change_seq <= v_cursor
      and (
        p_after_data_class is null
        or (o.data_class, o.stable_object_id) > (p_after_data_class, p_after_stable_object_id)
      )
    order by o.data_class, o.stable_object_id
    limit p_limit + 1
  ),
  page as materialized (
    select *
    from eligible
    order by data_class, stable_object_id
    limit p_limit
  )
  select
    (select count(*) > p_limit from eligible),
    (select data_class from page order by data_class desc, stable_object_id desc limit 1),
    (select stable_object_id from page order by data_class desc, stable_object_id desc limit 1),
    coalesce(
      (
        select jsonb_agg(
          jsonb_build_object(
            'sync_object_id', p.sync_object_id,
            'data_class', p.data_class,
            'stable_object_id', p.stable_object_id,
            'object_schema_version', p.object_schema_version,
            'resolver_version', p.resolver_version,
            'server_revision', p.server_revision,
            'tombstone', p.tombstone,
            'payload', p.payload,
            'updated_at', p.updated_at
          )
          order by p.data_class, p.stable_object_id
        )
        from page p
      ),
      '[]'::jsonb
    )
  into v_has_more, v_next_data_class, v_next_stable_object_id, v_objects;

  if not v_has_more then
    v_next_data_class := null;
    v_next_stable_object_id := null;
  end if;

  return jsonb_build_object(
    'cursor', v_cursor,
    'objects', v_objects,
    'has_more', v_has_more,
    'next_data_class', v_next_data_class,
    'next_stable_object_id', v_next_stable_object_id
  );
end;
$function$;

-- ordax_sync_snapshot_v1 (replaced 2 direct auth.uid calls)
CREATE OR REPLACE FUNCTION public.ordax_sync_snapshot_v1(p_limit integer DEFAULT 200)
 RETURNS jsonb
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
  with checkpoint as (
    select coalesce(max(m.change_seq), 0)::bigint as cursor
    from private.ordax_sync_mutations m
    where m.owner_user_id = (select public.ordax_request_subject_v1())
  ),
  objects as (
    select jsonb_agg(
      jsonb_build_object(
        'sync_object_id', o.sync_object_id,
        'data_class', o.data_class,
        'stable_object_id', o.stable_object_id,
        'object_schema_version', o.object_schema_version,
        'resolver_version', o.resolver_version,
        'server_revision', o.server_revision,
        'tombstone', o.tombstone,
        'payload', o.payload,
        'updated_at', o.updated_at
      )
      order by o.data_class, o.stable_object_id
    ) as value
    from (
      select * from private.ordax_sync_objects
      where owner_user_id = (select public.ordax_request_subject_v1())
      order by data_class, stable_object_id
      limit least(greatest(coalesce(p_limit, 200), 1), 500)
    ) o
  )
  select jsonb_build_object(
    'cursor', checkpoint.cursor,
    'objects', coalesce(objects.value, '[]'::jsonb)
  )
  from checkpoint cross join objects;
$function$;
do $postflight$
declare x record;
begin
 if not has_schema_privilege('ordax_sync_executor','public','USAGE') or not has_function_privilege('ordax_sync_executor','public.ordax_request_subject_v1()','EXECUTE') then raise exception 'sync executor cannot use the canonical subject bridge'; end if;
 if has_schema_privilege('ordax_sync_executor','auth','USAGE') then raise exception 'sync executor unexpectedly gained auth schema authority'; end if;
 if has_function_privilege('authenticated','public.ordax_request_subject_v1()','EXECUTE') or has_function_privilege('anon','public.ordax_request_subject_v1()','EXECUTE') then raise exception 'subject bridge leaked to clients'; end if;
 for x in select p.oid,p.proname,p.prosecdef,pg_get_userbyid(p.proowner) as owner_name,pg_get_functiondef(p.oid) as definition
 from pg_proc p join pg_namespace n on n.oid=p.pronamespace
 where n.nspname='public' and p.proname in ('ordax_apply_sync_mutation_v1','ordax_apply_sync_mutation_v2','ordax_list_sync_objects_v1','ordax_pull_sync_changes_v1','ordax_sync_snapshot_v1','ordax_sync_snapshot_page_v2')
 loop
   if x.owner_name<>'ordax_sync_executor' or not x.prosecdef or x.definition like '%auth.uid()%' or x.definition not like '%ordax_request_subject_v1()%' then raise exception 'sync RPC privilege or subject contract drifted: %', x.proname; end if;
 end loop;
 if exists (select 1 from pg_policies where schemaname='private' and tablename in ('ordax_sync_objects','ordax_sync_mutations') and policyname like 'ordax_sync_%_own' and (coalesce(qual,'') ilike '%auth.uid()%' or coalesce(with_check,'') ilike '%auth.uid()%')) then raise exception 'sync RLS still uses unavailable auth schema'; end if;
 if has_table_privilege('authenticated','private.ordax_sync_objects','SELECT') or has_table_privilege('service_role','private.ordax_sync_objects','SELECT') then raise exception 'sync transport table exposed'; end if;
end;
$postflight$;

commit;
