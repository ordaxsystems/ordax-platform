-- Generated exclusively from infra/supabase/product/account_destination_migration_plan.json
-- Destination Supabase project: jhfphsjptrpmtnzkpwud
-- Apply atomically as ONE Supabase migration; this text carries no runtime secrets.
BEGIN;
SET LOCAL lock_timeout='5s';
DO $preflight$
BEGIN
  IF to_regclass('private.ordax_sync_objects') IS NOT NULL
    OR to_regclass('private.ordax_sync_mutations') IS NOT NULL
    OR to_regprocedure('public.ordax_account_export_v1()') IS NOT NULL
    OR to_regprocedure('public.ordax_sync_snapshot_page_v2(bigint,text,text,integer)') IS NOT NULL
  THEN
    RAISE EXCEPTION 'account-cutover-destination-not-empty';
  END IF;
  IF EXISTS (SELECT 1 FROM auth.users) THEN
    RAISE EXCEPTION 'account-cutover-users-present';
  END IF;
END;
$preflight$;

-- SOURCE 20260925004439_account_sync_objects_v1.sql
-- Applied to ordax-control-plane as Supabase migration 20260925004439.
-- Provider-neutral account sync store. Clients see OrdaX object/revision semantics,
-- never provider row identity. Device-private material is not allowed here.

create table if not exists public.ordax_sync_objects (
  sync_object_id uuid primary key default gen_random_uuid(),
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  data_class text not null check (data_class in ('appearance','preferences','workspace-metadata','app-state-metadata','user-selected-cloud-content')),
  stable_object_id text not null check (char_length(stable_object_id) between 1 and 240),
  object_schema_version integer not null check (object_schema_version > 0),
  resolver_version integer not null default 1 check (resolver_version > 0),
  server_revision bigint not null default 1 check (server_revision > 0),
  tombstone boolean not null default false,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now()),
  unique (owner_user_id, data_class, stable_object_id)
);

create table if not exists public.ordax_sync_mutations (
  mutation_id uuid primary key default gen_random_uuid(),
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  idempotency_key text not null check (char_length(idempotency_key) between 8 and 200),
  data_class text not null check (data_class in ('appearance','preferences','workspace-metadata','app-state-metadata','user-selected-cloud-content')),
  stable_object_id text not null check (char_length(stable_object_id) between 1 and 240),
  base_server_revision bigint,
  resulting_server_revision bigint not null check (resulting_server_revision > 0),
  mutation_kind text not null check (mutation_kind in ('upsert','delete')),
  applied_at timestamptz not null default timezone('utc', now()),
  unique (owner_user_id, idempotency_key)
);

create index if not exists ordax_sync_objects_owner_revision_idx
  on public.ordax_sync_objects(owner_user_id, server_revision);
create index if not exists ordax_sync_mutations_owner_applied_idx
  on public.ordax_sync_mutations(owner_user_id, applied_at desc);

alter table public.ordax_sync_objects enable row level security;
alter table public.ordax_sync_mutations enable row level security;

revoke all on table public.ordax_sync_objects from public, anon, authenticated;
revoke all on table public.ordax_sync_mutations from public, anon, authenticated;
grant select on table public.ordax_sync_objects to authenticated;
grant select on table public.ordax_sync_mutations to authenticated;

create policy ordax_sync_objects_select_own
on public.ordax_sync_objects for select to authenticated
using ((select auth.uid()) = owner_user_id);

create policy ordax_sync_mutations_select_own
on public.ordax_sync_mutations for select to authenticated
using ((select auth.uid()) = owner_user_id);

create or replace function public.ordax_apply_sync_mutation_v1(
  p_idempotency_key text,
  p_data_class text,
  p_stable_object_id text,
  p_object_schema_version integer,
  p_resolver_version integer,
  p_base_server_revision bigint,
  p_tombstone boolean,
  p_payload jsonb
)
returns table (
  sync_object_id uuid,
  server_revision bigint,
  tombstone boolean,
  applied boolean,
  conflict boolean
)
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user_id uuid := (select auth.uid());
  v_existing public.ordax_sync_objects%rowtype;
  v_mutation public.ordax_sync_mutations%rowtype;
  v_revision bigint;
begin
  if v_user_id is null then
    raise exception 'authentication-required' using errcode = '42501';
  end if;
  if p_idempotency_key is null or char_length(p_idempotency_key) < 8 or char_length(p_idempotency_key) > 200 then
    raise exception 'invalid-idempotency-key' using errcode = '22023';
  end if;
  if p_data_class not in ('appearance','preferences','workspace-metadata','app-state-metadata','user-selected-cloud-content') then
    raise exception 'invalid-data-class' using errcode = '22023';
  end if;
  if p_stable_object_id is null or char_length(p_stable_object_id) < 1 or char_length(p_stable_object_id) > 240 then
    raise exception 'invalid-stable-object-id' using errcode = '22023';
  end if;
  if p_object_schema_version is null or p_object_schema_version <= 0 or p_resolver_version is null or p_resolver_version <= 0 then
    raise exception 'invalid-schema-version' using errcode = '22023';
  end if;
  if p_payload is null or jsonb_typeof(p_payload) <> 'object' then
    raise exception 'payload-must-be-object' using errcode = '22023';
  end if;

  select * into v_mutation
  from public.ordax_sync_mutations
  where owner_user_id = v_user_id and idempotency_key = p_idempotency_key;

  if found then
    select * into v_existing
    from public.ordax_sync_objects
    where owner_user_id = v_user_id
      and data_class = v_mutation.data_class
      and stable_object_id = v_mutation.stable_object_id;
    return query select v_existing.sync_object_id, v_mutation.resulting_server_revision,
      coalesce(v_existing.tombstone, false), false, false;
    return;
  end if;

  select * into v_existing
  from public.ordax_sync_objects
  where owner_user_id = v_user_id
    and data_class = p_data_class
    and stable_object_id = p_stable_object_id
  for update;

  if found then
    if p_base_server_revision is null or p_base_server_revision <> v_existing.server_revision then
      return query select v_existing.sync_object_id, v_existing.server_revision,
        v_existing.tombstone, false, true;
      return;
    end if;
    v_revision := v_existing.server_revision + 1;
    update public.ordax_sync_objects
      set object_schema_version = p_object_schema_version,
          resolver_version = p_resolver_version,
          server_revision = v_revision,
          tombstone = p_tombstone,
          payload = p_payload,
          updated_at = timezone('utc', now())
      where sync_object_id = v_existing.sync_object_id;
  else
    if coalesce(p_base_server_revision, 0) <> 0 then
      return query select null::uuid, 0::bigint, false, false, true;
      return;
    end if;
    v_revision := 1;
    insert into public.ordax_sync_objects(
      owner_user_id, data_class, stable_object_id, object_schema_version,
      resolver_version, server_revision, tombstone, payload
    ) values (
      v_user_id, p_data_class, p_stable_object_id, p_object_schema_version,
      p_resolver_version, v_revision, p_tombstone, p_payload
    )
    returning * into v_existing;
  end if;

  insert into public.ordax_sync_mutations(
    owner_user_id, idempotency_key, data_class, stable_object_id,
    base_server_revision, resulting_server_revision, mutation_kind
  ) values (
    v_user_id, p_idempotency_key, p_data_class, p_stable_object_id,
    p_base_server_revision, v_revision, case when p_tombstone then 'delete' else 'upsert' end
  );

  return query select v_existing.sync_object_id, v_revision, p_tombstone, true, false;
end;
$$;

revoke all on function public.ordax_apply_sync_mutation_v1(text,text,text,integer,integer,bigint,boolean,jsonb) from public, anon;
grant execute on function public.ordax_apply_sync_mutation_v1(text,text,text,integer,integer,bigint,boolean,jsonb) to authenticated;

-- SOURCE 20260925004832_account_sync_private_store_v1.sql
-- Applied to ordax-control-plane after 20260925004439_account_sync_objects_v1.
-- Internal sync rows live in the unexposed private schema. Public API functions
-- run as SECURITY INVOKER so RLS remains authoritative for each signed-in user.

alter table public.ordax_sync_objects set schema private;
alter table public.ordax_sync_mutations set schema private;

revoke all on table private.ordax_sync_objects from public, anon, authenticated;
revoke all on table private.ordax_sync_mutations from public, anon, authenticated;
grant usage on schema private to authenticated;
grant select, insert, update on table private.ordax_sync_objects to authenticated;
grant select, insert on table private.ordax_sync_mutations to authenticated;

drop policy if exists ordax_sync_objects_select_own on private.ordax_sync_objects;
create policy ordax_sync_objects_select_own
on private.ordax_sync_objects for select to authenticated
using ((select auth.uid()) = owner_user_id);

create policy ordax_sync_objects_insert_own
on private.ordax_sync_objects for insert to authenticated
with check ((select auth.uid()) = owner_user_id);

create policy ordax_sync_objects_update_own
on private.ordax_sync_objects for update to authenticated
using ((select auth.uid()) = owner_user_id)
with check ((select auth.uid()) = owner_user_id);

drop policy if exists ordax_sync_mutations_select_own on private.ordax_sync_mutations;
create policy ordax_sync_mutations_select_own
on private.ordax_sync_mutations for select to authenticated
using ((select auth.uid()) = owner_user_id);

create policy ordax_sync_mutations_insert_own
on private.ordax_sync_mutations for insert to authenticated
with check ((select auth.uid()) = owner_user_id);

create or replace function public.ordax_apply_sync_mutation_v1(
  p_idempotency_key text,
  p_data_class text,
  p_stable_object_id text,
  p_object_schema_version integer,
  p_resolver_version integer,
  p_base_server_revision bigint,
  p_tombstone boolean,
  p_payload jsonb
)
returns table (
  sync_object_id uuid,
  server_revision bigint,
  tombstone boolean,
  applied boolean,
  conflict boolean
)
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_user_id uuid := (select auth.uid());
  v_existing private.ordax_sync_objects%rowtype;
  v_mutation private.ordax_sync_mutations%rowtype;
  v_revision bigint;
begin
  if v_user_id is null then
    raise exception 'authentication-required' using errcode = '42501';
  end if;
  if p_idempotency_key is null or char_length(p_idempotency_key) < 8 or char_length(p_idempotency_key) > 200 then
    raise exception 'invalid-idempotency-key' using errcode = '22023';
  end if;
  if p_data_class not in ('appearance','preferences','workspace-metadata','app-state-metadata','user-selected-cloud-content') then
    raise exception 'invalid-data-class' using errcode = '22023';
  end if;
  if p_stable_object_id is null or char_length(p_stable_object_id) < 1 or char_length(p_stable_object_id) > 240 then
    raise exception 'invalid-stable-object-id' using errcode = '22023';
  end if;
  if p_object_schema_version is null or p_object_schema_version <= 0 or p_resolver_version is null or p_resolver_version <= 0 then
    raise exception 'invalid-schema-version' using errcode = '22023';
  end if;
  if p_payload is null or jsonb_typeof(p_payload) <> 'object' then
    raise exception 'payload-must-be-object' using errcode = '22023';
  end if;

  select * into v_mutation
  from private.ordax_sync_mutations
  where owner_user_id = v_user_id and idempotency_key = p_idempotency_key;

  if found then
    select * into v_existing
    from private.ordax_sync_objects
    where owner_user_id = v_user_id
      and data_class = v_mutation.data_class
      and stable_object_id = v_mutation.stable_object_id;
    return query select v_existing.sync_object_id, v_mutation.resulting_server_revision,
      coalesce(v_existing.tombstone, false), false, false;
    return;
  end if;

  select * into v_existing
  from private.ordax_sync_objects
  where owner_user_id = v_user_id
    and data_class = p_data_class
    and stable_object_id = p_stable_object_id
  for update;

  if found then
    if p_base_server_revision is null or p_base_server_revision <> v_existing.server_revision then
      return query select v_existing.sync_object_id, v_existing.server_revision,
        v_existing.tombstone, false, true;
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
      where sync_object_id = v_existing.sync_object_id;
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
    base_server_revision, resulting_server_revision, mutation_kind
  ) values (
    v_user_id, p_idempotency_key, p_data_class, p_stable_object_id,
    p_base_server_revision, v_revision, case when p_tombstone then 'delete' else 'upsert' end
  );

  return query select v_existing.sync_object_id, v_revision, p_tombstone, true, false;
end;
$$;

create or replace function public.ordax_list_sync_objects_v1(
  p_after_revision bigint default 0,
  p_limit integer default 200
)
returns table (
  sync_object_id uuid,
  data_class text,
  stable_object_id text,
  object_schema_version integer,
  resolver_version integer,
  server_revision bigint,
  tombstone boolean,
  payload jsonb,
  updated_at timestamptz
)
language sql
stable
security invoker
set search_path = ''
as $$
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
  where s.owner_user_id = (select auth.uid())
    and s.server_revision > greatest(coalesce(p_after_revision, 0), 0)
  order by s.server_revision, s.sync_object_id
  limit least(greatest(coalesce(p_limit, 200), 1), 500)
$$;

revoke all on function public.ordax_apply_sync_mutation_v1(text,text,text,integer,integer,bigint,boolean,jsonb) from public, anon;
revoke all on function public.ordax_list_sync_objects_v1(bigint,integer) from public, anon;
grant execute on function public.ordax_apply_sync_mutation_v1(text,text,text,integer,integer,bigint,boolean,jsonb) to authenticated;
grant execute on function public.ordax_list_sync_objects_v1(bigint,integer) to authenticated;

-- SOURCE 20260925013355_account_sync_incremental_cursor_v1.sql
alter table private.ordax_sync_mutations
  add column if not exists change_seq bigint generated always as identity,
  add column if not exists object_schema_version integer,
  add column if not exists resolver_version integer,
  add column if not exists tombstone boolean,
  add column if not exists payload jsonb;

alter table private.ordax_sync_mutations
  alter column object_schema_version set default 1,
  alter column resolver_version set default 1,
  alter column tombstone set default false,
  alter column payload set default '{}'::jsonb;

update private.ordax_sync_mutations
set object_schema_version = coalesce(object_schema_version, 1),
    resolver_version = coalesce(resolver_version, 1),
    tombstone = coalesce(tombstone, mutation_kind = 'delete'),
    payload = coalesce(payload, '{}'::jsonb)
where object_schema_version is null
   or resolver_version is null
   or tombstone is null
   or payload is null;

alter table private.ordax_sync_mutations
  alter column object_schema_version set not null,
  alter column resolver_version set not null,
  alter column tombstone set not null,
  alter column payload set not null;

create unique index if not exists ordax_sync_mutations_change_seq_uidx
  on private.ordax_sync_mutations(change_seq);

create index if not exists ordax_sync_mutations_owner_change_seq_idx
  on private.ordax_sync_mutations(owner_user_id, change_seq);

create or replace function public.ordax_apply_sync_mutation_v1(
  p_idempotency_key text,
  p_data_class text,
  p_stable_object_id text,
  p_object_schema_version integer,
  p_resolver_version integer,
  p_base_server_revision bigint,
  p_tombstone boolean,
  p_payload jsonb
)
returns table(
  sync_object_id uuid,
  server_revision bigint,
  tombstone boolean,
  applied boolean,
  conflict boolean
)
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_user_id uuid := (select auth.uid());
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

create or replace function public.ordax_apply_sync_mutation_v2(
  p_idempotency_key text,
  p_data_class text,
  p_stable_object_id text,
  p_object_schema_version integer,
  p_resolver_version integer,
  p_base_server_revision bigint,
  p_tombstone boolean,
  p_payload jsonb
)
returns table(
  sync_object_id uuid,
  server_revision bigint,
  tombstone boolean,
  applied boolean,
  conflict boolean,
  change_cursor bigint
)
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_user_id uuid := (select auth.uid());
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

create or replace function public.ordax_pull_sync_changes_v1(
  p_after_cursor bigint default 0,
  p_limit integer default 200
)
returns table(
  change_cursor bigint,
  data_class text,
  stable_object_id text,
  object_schema_version integer,
  resolver_version integer,
  server_revision bigint,
  tombstone boolean,
  payload jsonb,
  changed_at timestamptz
)
language sql
security invoker
set search_path = ''
as $function$
  select
    m.change_seq, m.data_class, m.stable_object_id,
    m.object_schema_version, m.resolver_version,
    m.resulting_server_revision, m.tombstone, m.payload, m.applied_at
  from private.ordax_sync_mutations m
  where m.owner_user_id = (select auth.uid())
    and m.change_seq > greatest(coalesce(p_after_cursor, 0), 0)
  order by m.change_seq
  limit least(greatest(coalesce(p_limit, 200), 1), 500);
$function$;

revoke all on function public.ordax_apply_sync_mutation_v2(text,text,text,integer,integer,bigint,boolean,jsonb) from public, anon;
grant execute on function public.ordax_apply_sync_mutation_v2(text,text,text,integer,integer,bigint,boolean,jsonb) to authenticated;
revoke all on function public.ordax_pull_sync_changes_v1(bigint,integer) from public, anon;
grant execute on function public.ordax_pull_sync_changes_v1(bigint,integer) to authenticated;

-- SOURCE 20260925013524_account_sync_atomic_snapshot_v1.sql
create or replace function public.ordax_sync_snapshot_v1(
  p_limit integer default 200
)
returns jsonb
language sql
security invoker
set search_path = ''
as $function$
  with checkpoint as (
    select coalesce(max(m.change_seq), 0)::bigint as cursor
    from private.ordax_sync_mutations m
    where m.owner_user_id = (select auth.uid())
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
      where owner_user_id = (select auth.uid())
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

revoke all on function public.ordax_sync_snapshot_v1(integer) from public, anon;
grant execute on function public.ordax_sync_snapshot_v1(integer) to authenticated;

-- SOURCE 20260930140051_account_sync_paginated_snapshot_v2.sql
-- Restored from the live, reviewed paginated snapshot function on the prior
-- provider (migration ledger: 20260930140051 account_sync_paginated_snapshot_v2).
-- The historical source was absent from the canonical Git repository.
-- Use SECURITY INVOKER at this stage, because the existing ordered migration
-- 20261005025500_sync_private_least_privilege_v2.sql is the sole authority to
-- promote the RPC to the restricted ordax_sync_executor owner.
-- This migration does not create a second sync owner or activate public sync.


CREATE OR REPLACE FUNCTION public.ordax_sync_snapshot_page_v2(p_cursor bigint DEFAULT NULL::bigint, p_after_data_class text DEFAULT NULL::text, p_after_stable_object_id text DEFAULT NULL::text, p_limit integer DEFAULT 200)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY INVOKER
 SET search_path = ''
AS $function$
declare
  v_user_id uuid := (select auth.uid());
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

revoke all on function public.ordax_sync_snapshot_page_v2(bigint,text,text,integer)
  from public, anon, authenticated, service_role;
grant execute on function public.ordax_sync_snapshot_page_v2(bigint,text,text,integer)
  to authenticated;

-- SOURCE 20261008085000_account_data_export_project_id_v1.sql
-- Destination-specific initial implementation of the EXISTING account export RPC.
-- The canonical product schema on ordax-platform uses memory_items.project_id,
-- not the older provider's memory_items.project_ref. Do not add a shadow column.
-- This is an initialization migration, not a parallel RPC or dual-write owner.
-- For destination provisioning, use this source INSTEAD OF the historical
-- 20260925031000_account_data_export_v1.sql. Existing legacy deployments
-- preserve their applied migration and are not rewritten.
-- Before enabling any public route, execute the restricted executor and
-- subject bridge migrations on the same backend and verify actual RLS grants.


create or replace function public.ordax_account_export_v1()
returns jsonb
language sql
security invoker
set search_path = ''
as $$
  with me as (
    select auth.uid() as user_id
  ),
  account as (
    select coalesce(
      (
        select jsonb_build_object(
          'user_id', a.user_id,
          'display_name', a.display_name,
          'created_at', a.created_at,
          'updated_at', a.updated_at
        )
        from public.ordax_accounts a
        where a.user_id = (select user_id from me)
      ),
      '{}'::jsonb
    ) as value
  ),
  spaces as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'space_id', s.space_id,
        'name', s.name,
        'kind', s.kind,
        'state', s.state,
        'created_at', s.created_at,
        'updated_at', s.updated_at
      )
      order by s.created_at, s.space_id
    ), '[]'::jsonb) as value
    from public.ordax_spaces s
    where s.owner_user_id = (select user_id from me)
  ),
  memberships as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'space_id', m.space_id,
        'user_id', m.user_id,
        'role', m.role,
        'state', m.state,
        'created_at', m.created_at,
        'updated_at', m.updated_at
      )
      order by m.created_at, m.space_id
    ), '[]'::jsonb) as value
    from public.ordax_space_members m
    where m.user_id = (select user_id from me)
  ),
  profile_packs as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'space_id', p.space_id,
        'pack_slug', p.pack_slug,
        'pack_version', p.pack_version,
        'config', p.config,
        'enabled_at', p.enabled_at,
        'enabled_by', p.enabled_by
      )
      order by p.space_id, p.pack_slug, p.pack_version
    ), '[]'::jsonb) as value
    from public.ordax_space_profile_packs p
    where exists (
      select 1
      from public.ordax_spaces s
      where s.space_id = p.space_id
        and s.owner_user_id = (select user_id from me)
    )
  ),
  entitlements as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'grant_id', e.grant_id,
        'space_id', e.space_id,
        'entitlement_key', e.entitlement_key,
        'entitlement_value', e.entitlement_value,
        'source', e.source,
        'valid_from', e.valid_from,
        'valid_until', e.valid_until,
        'created_at', e.created_at
      )
      order by e.created_at, e.grant_id
    ), '[]'::jsonb) as value
    from public.ordax_entitlement_grants e
    where e.user_id = (select user_id from me)
  ),
  projects as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'project_id', p.project_id,
        'space_id', p.space_id,
        'name', p.name,
        'kind', p.kind,
        'state', p.state,
        'created_at', p.created_at,
        'updated_at', p.updated_at
      )
      order by p.created_at, p.project_id
    ), '[]'::jsonb) as value
    from public.ordax_projects p
    where p.created_by_user_id = (select user_id from me)
  ),
  devices as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'device_id', d.device_id,
        'device_public_id', d.device_public_id,
        'display_name', d.display_name,
        'device_kind', d.device_kind,
        'channel', d.channel,
        'state', d.state,
        'created_at', d.created_at,
        'updated_at', d.updated_at
      )
      order by d.created_at, d.device_id
    ), '[]'::jsonb) as value
    from public.ordax_product_devices d
    where d.owner_user_id = (select user_id from me)
  ),
  connections as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'connection_id', c.connection_id,
        'space_id', c.space_id,
        'project_id', c.project_id,
        'provider', c.provider,
        'external_account_id', c.external_account_id,
        'installation_id', c.installation_id,
        'repository_id', c.repository_id,
        'repository_full_name', c.repository_full_name,
        'default_branch', c.default_branch,
        'access_mode', c.access_mode,
        'state', c.state,
        'created_at', c.created_at,
        'updated_at', c.updated_at
      )
      order by c.created_at, c.connection_id
    ), '[]'::jsonb) as value
    from public.ordax_project_connections c
    where c.owner_user_id = (select user_id from me)
  ),
  memory_items as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'memory_id', m.memory_id,
        'space_id', m.space_id,
        'project_id', m.project_id,
        'scope', m.scope,
        'kind', m.kind,
        'sensitivity', m.sensitivity,
        'content', m.content,
        'provenance', m.provenance,
        'source_timestamp', m.source_timestamp,
        'confidence', m.confidence,
        'state', m.state,
        'created_at', m.created_at,
        'updated_at', m.updated_at
      )
      order by m.created_at, m.memory_id
    ), '[]'::jsonb) as value
    from public.ordax_memory_items m
    where m.owner_user_id = (select user_id from me)
  ),
  sync_objects as (
    select coalesce(jsonb_agg(
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
    ), '[]'::jsonb) as value
    from private.ordax_sync_objects o
    where o.owner_user_id = (select user_id from me)
  )
  select case
    when me.user_id is null then null
    else jsonb_build_object(
      '$schema', 'prototype-ordax.account-export/1',
      'subject', me.user_id,
      'exported_at', now(),
      'account', account.value,
      'spaces', spaces.value,
      'memberships', memberships.value,
      'space_profile_packs', profile_packs.value,
      'entitlements', entitlements.value,
      'projects', projects.value,
      'devices', devices.value,
      'project_connections', connections.value,
      'memory_items', memory_items.value,
      'sync_objects', sync_objects.value
    )
  end
  from me
  cross join account
  cross join spaces
  cross join memberships
  cross join profile_packs
  cross join entitlements
  cross join projects
  cross join devices
  cross join connections
  cross join memory_items
  cross join sync_objects;
$$;

revoke all on function public.ordax_account_export_v1() from public, anon, authenticated;
grant execute on function public.ordax_account_export_v1() to authenticated;

-- SOURCE 20261005025500_sync_private_least_privilege_v2.sql
do $role$
declare
  r record;
begin
  select rolsuper, rolcreatedb, rolcreaterole, rolinherit, rolcanlogin, rolreplication, rolbypassrls
    into r
    from pg_roles
   where rolname = 'ordax_sync_executor';

  if not found then
    create role ordax_sync_executor
      nosuperuser nocreatedb nocreaterole noinherit nologin noreplication nobypassrls;
  elsif r.rolsuper or r.rolcreatedb or r.rolcreaterole or r.rolinherit
     or r.rolcanlogin or r.rolreplication or r.rolbypassrls then
    raise exception 'ordax_sync_executor violates least-privilege role contract';
  end if;
end;
$role$;

grant ordax_sync_executor to postgres;
revoke all on schema private from ordax_sync_executor;
revoke all on schema auth from ordax_sync_executor;
grant usage on schema private to ordax_sync_executor;
grant usage on schema auth to ordax_sync_executor;
grant execute on function auth.uid() to ordax_sync_executor;

revoke all on table private.ordax_sync_objects from ordax_sync_executor;
revoke all on table private.ordax_sync_mutations from ordax_sync_executor;
revoke all on sequence private.ordax_sync_mutations_change_seq_seq from ordax_sync_executor;
grant select, insert, update on table private.ordax_sync_objects to ordax_sync_executor;
grant select, insert on table private.ordax_sync_mutations to ordax_sync_executor;
grant usage, select on sequence private.ordax_sync_mutations_change_seq_seq to ordax_sync_executor;

alter policy ordax_sync_objects_select_own on private.ordax_sync_objects to ordax_sync_executor;
alter policy ordax_sync_objects_insert_own on private.ordax_sync_objects to ordax_sync_executor;
alter policy ordax_sync_objects_update_own on private.ordax_sync_objects to ordax_sync_executor;
alter policy ordax_sync_mutations_select_own on private.ordax_sync_mutations to ordax_sync_executor;
alter policy ordax_sync_mutations_insert_own on private.ordax_sync_mutations to ordax_sync_executor;

grant create on schema public to ordax_sync_executor;

alter function public.ordax_apply_sync_mutation_v1(text, text, text, integer, integer, bigint, boolean, jsonb) security definer;
alter function public.ordax_apply_sync_mutation_v1(text, text, text, integer, integer, bigint, boolean, jsonb) set search_path = '';
alter function public.ordax_apply_sync_mutation_v1(text, text, text, integer, integer, bigint, boolean, jsonb) owner to ordax_sync_executor;
alter function public.ordax_apply_sync_mutation_v2(text, text, text, integer, integer, bigint, boolean, jsonb) security definer;
alter function public.ordax_apply_sync_mutation_v2(text, text, text, integer, integer, bigint, boolean, jsonb) set search_path = '';
alter function public.ordax_apply_sync_mutation_v2(text, text, text, integer, integer, bigint, boolean, jsonb) owner to ordax_sync_executor;
alter function public.ordax_pull_sync_changes_v1(bigint, integer) security definer;
alter function public.ordax_pull_sync_changes_v1(bigint, integer) set search_path = '';
alter function public.ordax_pull_sync_changes_v1(bigint, integer) owner to ordax_sync_executor;
alter function public.ordax_list_sync_objects_v1(bigint, integer) security definer;
alter function public.ordax_list_sync_objects_v1(bigint, integer) set search_path = '';
alter function public.ordax_list_sync_objects_v1(bigint, integer) owner to ordax_sync_executor;
alter function public.ordax_sync_snapshot_v1(integer) security definer;
alter function public.ordax_sync_snapshot_v1(integer) set search_path = '';
alter function public.ordax_sync_snapshot_v1(integer) owner to ordax_sync_executor;
alter function public.ordax_sync_snapshot_page_v2(bigint, text, text, integer) security definer;
alter function public.ordax_sync_snapshot_page_v2(bigint, text, text, integer) set search_path = '';
alter function public.ordax_sync_snapshot_page_v2(bigint, text, text, integer) owner to ordax_sync_executor;

revoke create on schema public from ordax_sync_executor;

alter function public.ordax_account_export_v1() security definer;
alter function public.ordax_account_export_v1() set search_path = '';

revoke all on function public.ordax_apply_sync_mutation_v1(text, text, text, integer, integer, bigint, boolean, jsonb) from public, anon, authenticated, service_role;
revoke all on function public.ordax_apply_sync_mutation_v2(text, text, text, integer, integer, bigint, boolean, jsonb) from public, anon, authenticated, service_role;
revoke all on function public.ordax_pull_sync_changes_v1(bigint, integer) from public, anon, authenticated, service_role;
revoke all on function public.ordax_list_sync_objects_v1(bigint, integer) from public, anon, authenticated, service_role;
revoke all on function public.ordax_sync_snapshot_v1(integer) from public, anon, authenticated, service_role;
revoke all on function public.ordax_sync_snapshot_page_v2(bigint, text, text, integer) from public, anon, authenticated, service_role;
revoke all on function public.ordax_account_export_v1() from public, anon, authenticated, service_role;

grant execute on function public.ordax_apply_sync_mutation_v1(text, text, text, integer, integer, bigint, boolean, jsonb) to authenticated;
grant execute on function public.ordax_apply_sync_mutation_v2(text, text, text, integer, integer, bigint, boolean, jsonb) to authenticated;
grant execute on function public.ordax_pull_sync_changes_v1(bigint, integer) to authenticated;
grant execute on function public.ordax_list_sync_objects_v1(bigint, integer) to authenticated;
grant execute on function public.ordax_sync_snapshot_v1(integer) to authenticated;
grant execute on function public.ordax_sync_snapshot_page_v2(bigint, text, text, integer) to authenticated;
grant execute on function public.ordax_account_export_v1() to authenticated;

revoke all on table private.ordax_sync_objects from public, anon, authenticated, service_role;
revoke all on table private.ordax_sync_mutations from public, anon, authenticated, service_role;
revoke all on sequence private.ordax_sync_mutations_change_seq_seq from public, anon, authenticated, service_role;

-- SOURCE 20261007070000_account_export_executor_v1.sql
do $role$
declare
  r record;
begin
  select
    rolsuper,
    rolcreatedb,
    rolcreaterole,
    rolinherit,
    rolcanlogin,
    rolreplication,
    rolbypassrls
  into r
  from pg_roles
  where rolname = 'ordax_account_export_executor';

  if not found then
    create role ordax_account_export_executor
      nosuperuser nocreatedb nocreaterole noinherit nologin noreplication nobypassrls;
  elsif r.rolsuper
     or r.rolcreatedb
     or r.rolcreaterole
     or r.rolinherit
     or r.rolcanlogin
     or r.rolreplication
     or r.rolbypassrls then
    raise exception 'ordax_account_export_executor violates least-privilege role contract';
  end if;
end;
$role$;

grant ordax_account_export_executor to postgres;

revoke all on schema public from ordax_account_export_executor;
revoke all on schema private from ordax_account_export_executor;
revoke all on schema auth from ordax_account_export_executor;
grant usage on schema public, private, auth to ordax_account_export_executor;
grant execute on function auth.uid() to ordax_account_export_executor;

revoke all on table
  public.ordax_accounts,
  public.ordax_spaces,
  public.ordax_space_members,
  public.ordax_space_profile_packs,
  public.ordax_entitlement_grants,
  public.ordax_projects,
  public.ordax_product_devices,
  public.ordax_project_connections,
  public.ordax_memory_items,
  private.ordax_sync_objects
from ordax_account_export_executor;

grant select on table
  public.ordax_accounts,
  public.ordax_spaces,
  public.ordax_space_members,
  public.ordax_space_profile_packs,
  public.ordax_entitlement_grants,
  public.ordax_projects,
  public.ordax_product_devices,
  public.ordax_project_connections,
  public.ordax_memory_items,
  private.ordax_sync_objects
to ordax_account_export_executor;

drop policy if exists ordax_accounts_export_own on public.ordax_accounts;
create policy ordax_accounts_export_own
  on public.ordax_accounts
  for select
  to ordax_account_export_executor
  using (user_id = (select auth.uid()));

drop policy if exists ordax_spaces_export_own on public.ordax_spaces;
create policy ordax_spaces_export_own
  on public.ordax_spaces
  for select
  to ordax_account_export_executor
  using (owner_user_id = (select auth.uid()));

drop policy if exists ordax_space_members_export_own on public.ordax_space_members;
create policy ordax_space_members_export_own
  on public.ordax_space_members
  for select
  to ordax_account_export_executor
  using (user_id = (select auth.uid()));

drop policy if exists ordax_space_profile_packs_export_own on public.ordax_space_profile_packs;
create policy ordax_space_profile_packs_export_own
  on public.ordax_space_profile_packs
  for select
  to ordax_account_export_executor
  using (
    exists (
      select 1
      from public.ordax_spaces s
      where s.space_id = ordax_space_profile_packs.space_id
        and s.owner_user_id = (select auth.uid())
    )
  );

drop policy if exists ordax_entitlement_grants_export_own on public.ordax_entitlement_grants;
create policy ordax_entitlement_grants_export_own
  on public.ordax_entitlement_grants
  for select
  to ordax_account_export_executor
  using (user_id = (select auth.uid()));

drop policy if exists ordax_projects_export_own on public.ordax_projects;
create policy ordax_projects_export_own
  on public.ordax_projects
  for select
  to ordax_account_export_executor
  using (created_by_user_id = (select auth.uid()));

drop policy if exists ordax_product_devices_export_own on public.ordax_product_devices;
create policy ordax_product_devices_export_own
  on public.ordax_product_devices
  for select
  to ordax_account_export_executor
  using (owner_user_id = (select auth.uid()));

drop policy if exists ordax_project_connections_export_own on public.ordax_project_connections;
create policy ordax_project_connections_export_own
  on public.ordax_project_connections
  for select
  to ordax_account_export_executor
  using (owner_user_id = (select auth.uid()));

drop policy if exists ordax_memory_items_export_own on public.ordax_memory_items;
create policy ordax_memory_items_export_own
  on public.ordax_memory_items
  for select
  to ordax_account_export_executor
  using (owner_user_id = (select auth.uid()));

drop policy if exists ordax_sync_objects_export_own on private.ordax_sync_objects;
create policy ordax_sync_objects_export_own
  on private.ordax_sync_objects
  for select
  to ordax_account_export_executor
  using (owner_user_id = (select auth.uid()));

-- PostgreSQL requires the new function owner to be able to create in the
-- containing schema at ownership-transfer time. Keep that authority scoped to
-- this migration only; the executor must not retain CREATE afterwards.
grant create on schema public to ordax_account_export_executor;
alter function public.ordax_account_export_v1() owner to ordax_account_export_executor;
alter function public.ordax_account_export_v1() security definer;
alter function public.ordax_account_export_v1() set search_path = '';
revoke create on schema public from ordax_account_export_executor;

revoke all on function public.ordax_account_export_v1()
  from public, anon, authenticated, service_role;
grant execute on function public.ordax_account_export_v1() to authenticated;

-- SOURCE 20261007071500_account_export_subject_bridge_v1.sql
-- The Supabase-managed auth schema is owned by supabase_admin. The product
-- postgres role may use auth.uid(), but cannot delegate auth-schema USAGE to a
-- product executor. Keep that provider-owned boundary intact. This helper is a
-- deliberately tiny SECURITY DEFINER bridge: it reads no relation and returns
-- only the request subject already present in the caller JWT context.
create or replace function public.ordax_request_subject_v1()
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select auth.uid();
$$;

alter function public.ordax_request_subject_v1() owner to postgres;
revoke all on function public.ordax_request_subject_v1()
  from public, anon, authenticated, service_role;
grant execute on function public.ordax_request_subject_v1()
  to ordax_account_export_executor;

-- The executor must remain independent from the provider-owned auth schema.
revoke all on schema auth from ordax_account_export_executor;

drop policy if exists ordax_accounts_export_own on public.ordax_accounts;
create policy ordax_accounts_export_own
  on public.ordax_accounts
  for select
  to ordax_account_export_executor
  using (user_id = (select public.ordax_request_subject_v1()));

drop policy if exists ordax_spaces_export_own on public.ordax_spaces;
create policy ordax_spaces_export_own
  on public.ordax_spaces
  for select
  to ordax_account_export_executor
  using (owner_user_id = (select public.ordax_request_subject_v1()));

drop policy if exists ordax_space_members_export_own on public.ordax_space_members;
create policy ordax_space_members_export_own
  on public.ordax_space_members
  for select
  to ordax_account_export_executor
  using (user_id = (select public.ordax_request_subject_v1()));

drop policy if exists ordax_space_profile_packs_export_own on public.ordax_space_profile_packs;
create policy ordax_space_profile_packs_export_own
  on public.ordax_space_profile_packs
  for select
  to ordax_account_export_executor
  using (
    exists (
      select 1
      from public.ordax_spaces s
      where s.space_id = ordax_space_profile_packs.space_id
        and s.owner_user_id = (select public.ordax_request_subject_v1())
    )
  );

drop policy if exists ordax_entitlement_grants_export_own on public.ordax_entitlement_grants;
create policy ordax_entitlement_grants_export_own
  on public.ordax_entitlement_grants
  for select
  to ordax_account_export_executor
  using (user_id = (select public.ordax_request_subject_v1()));

drop policy if exists ordax_projects_export_own on public.ordax_projects;
create policy ordax_projects_export_own
  on public.ordax_projects
  for select
  to ordax_account_export_executor
  using (created_by_user_id = (select public.ordax_request_subject_v1()));

drop policy if exists ordax_product_devices_export_own on public.ordax_product_devices;
create policy ordax_product_devices_export_own
  on public.ordax_product_devices
  for select
  to ordax_account_export_executor
  using (owner_user_id = (select public.ordax_request_subject_v1()));

drop policy if exists ordax_project_connections_export_own on public.ordax_project_connections;
create policy ordax_project_connections_export_own
  on public.ordax_project_connections
  for select
  to ordax_account_export_executor
  using (owner_user_id = (select public.ordax_request_subject_v1()));

drop policy if exists ordax_memory_items_export_own on public.ordax_memory_items;
create policy ordax_memory_items_export_own
  on public.ordax_memory_items
  for select
  to ordax_account_export_executor
  using (owner_user_id = (select public.ordax_request_subject_v1()));

drop policy if exists ordax_sync_objects_export_own on private.ordax_sync_objects;
create policy ordax_sync_objects_export_own
  on private.ordax_sync_objects
  for select
  to ordax_account_export_executor
  using (owner_user_id = (select public.ordax_request_subject_v1()));

-- Rebind only the subject lookup in the existing export contract. The payload
-- and route schema stay byte-for-byte compatible with account-export/1.
grant create on schema public to ordax_account_export_executor;
alter function public.ordax_account_export_v1() owner to postgres;

create or replace function public.ordax_account_export_v1()
returns jsonb
language sql
security definer
set search_path = ''
as $$
  with me as (
    select public.ordax_request_subject_v1() as user_id
  ),
  account as (
    select coalesce(
      (
        select jsonb_build_object(
          'user_id', a.user_id,
          'display_name', a.display_name,
          'created_at', a.created_at,
          'updated_at', a.updated_at
        )
        from public.ordax_accounts a
        where a.user_id = (select user_id from me)
      ),
      '{}'::jsonb
    ) as value
  ),
  spaces as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'space_id', s.space_id,
        'name', s.name,
        'kind', s.kind,
        'state', s.state,
        'created_at', s.created_at,
        'updated_at', s.updated_at
      )
      order by s.created_at, s.space_id
    ), '[]'::jsonb) as value
    from public.ordax_spaces s
    where s.owner_user_id = (select user_id from me)
  ),
  memberships as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'space_id', m.space_id,
        'user_id', m.user_id,
        'role', m.role,
        'state', m.state,
        'created_at', m.created_at,
        'updated_at', m.updated_at
      )
      order by m.created_at, m.space_id
    ), '[]'::jsonb) as value
    from public.ordax_space_members m
    where m.user_id = (select user_id from me)
  ),
  profile_packs as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'space_id', p.space_id,
        'pack_slug', p.pack_slug,
        'pack_version', p.pack_version,
        'config', p.config,
        'enabled_at', p.enabled_at,
        'enabled_by', p.enabled_by
      )
      order by p.space_id, p.pack_slug, p.pack_version
    ), '[]'::jsonb) as value
    from public.ordax_space_profile_packs p
    where exists (
      select 1
      from public.ordax_spaces s
      where s.space_id = p.space_id
        and s.owner_user_id = (select user_id from me)
    )
  ),
  entitlements as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'grant_id', e.grant_id,
        'space_id', e.space_id,
        'entitlement_key', e.entitlement_key,
        'entitlement_value', e.entitlement_value,
        'source', e.source,
        'valid_from', e.valid_from,
        'valid_until', e.valid_until,
        'created_at', e.created_at
      )
      order by e.created_at, e.grant_id
    ), '[]'::jsonb) as value
    from public.ordax_entitlement_grants e
    where e.user_id = (select user_id from me)
  ),
  projects as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'project_id', p.project_id,
        'space_id', p.space_id,
        'name', p.name,
        'kind', p.kind,
        'state', p.state,
        'created_at', p.created_at,
        'updated_at', p.updated_at
      )
      order by p.created_at, p.project_id
    ), '[]'::jsonb) as value
    from public.ordax_projects p
    where p.created_by_user_id = (select user_id from me)
  ),
  devices as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'device_id', d.device_id,
        'device_public_id', d.device_public_id,
        'display_name', d.display_name,
        'device_kind', d.device_kind,
        'channel', d.channel,
        'state', d.state,
        'created_at', d.created_at,
        'updated_at', d.updated_at
      )
      order by d.created_at, d.device_id
    ), '[]'::jsonb) as value
    from public.ordax_product_devices d
    where d.owner_user_id = (select user_id from me)
  ),
  connections as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'connection_id', c.connection_id,
        'space_id', c.space_id,
        'project_id', c.project_id,
        'provider', c.provider,
        'external_account_id', c.external_account_id,
        'installation_id', c.installation_id,
        'repository_id', c.repository_id,
        'repository_full_name', c.repository_full_name,
        'default_branch', c.default_branch,
        'access_mode', c.access_mode,
        'state', c.state,
        'created_at', c.created_at,
        'updated_at', c.updated_at
      )
      order by c.created_at, c.connection_id
    ), '[]'::jsonb) as value
    from public.ordax_project_connections c
    where c.owner_user_id = (select user_id from me)
  ),
  memory_items as (
    select coalesce(jsonb_agg(
      jsonb_build_object(
        'memory_id', m.memory_id,
        'space_id', m.space_id,
        'project_id', m.project_id,
        'scope', m.scope,
        'kind', m.kind,
        'sensitivity', m.sensitivity,
        'content', m.content,
        'provenance', m.provenance,
        'source_timestamp', m.source_timestamp,
        'confidence', m.confidence,
        'state', m.state,
        'created_at', m.created_at,
        'updated_at', m.updated_at
      )
      order by m.created_at, m.memory_id
    ), '[]'::jsonb) as value
    from public.ordax_memory_items m
    where m.owner_user_id = (select user_id from me)
  ),
  sync_objects as (
    select coalesce(jsonb_agg(
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
    ), '[]'::jsonb) as value
    from private.ordax_sync_objects o
    where o.owner_user_id = (select user_id from me)
  )
  select case
    when me.user_id is null then null
    else jsonb_build_object(
      '$schema', 'prototype-ordax.account-export/1',
      'subject', me.user_id,
      'exported_at', now(),
      'account', account.value,
      'spaces', spaces.value,
      'memberships', memberships.value,
      'space_profile_packs', profile_packs.value,
      'entitlements', entitlements.value,
      'projects', projects.value,
      'devices', devices.value,
      'project_connections', connections.value,
      'memory_items', memory_items.value,
      'sync_objects', sync_objects.value
    )
  end
  from me
  cross join account
  cross join spaces
  cross join memberships
  cross join profile_packs
  cross join entitlements
  cross join projects
  cross join devices
  cross join connections
  cross join memory_items
  cross join sync_objects;
$$;

alter function public.ordax_account_export_v1() owner to ordax_account_export_executor;
alter function public.ordax_account_export_v1() security definer;
alter function public.ordax_account_export_v1() set search_path = '';
revoke create on schema public from ordax_account_export_executor;

revoke all on function public.ordax_account_export_v1()
  from public, anon, authenticated, service_role;
grant execute on function public.ordax_account_export_v1() to authenticated;

DO $proof$
BEGIN
  IF (SELECT count(*) FROM pg_roles
      WHERE rolname IN ('ordax_sync_executor','ordax_account_export_executor')
      AND NOT rolcanlogin AND NOT rolbypassrls AND NOT rolsuper AND NOT rolinherit) <> 2
  THEN RAISE EXCEPTION 'account-cutover-privileged-executor'; END IF;
  IF has_table_privilege('authenticated','private.ordax_sync_objects','SELECT')
    OR has_table_privilege('service_role','private.ordax_sync_objects','SELECT')
    OR has_table_privilege('anon','private.ordax_sync_objects','SELECT')
  THEN RAISE EXCEPTION 'account-cutover-sync-table-exposed'; END IF;
  IF has_function_privilege('anon','public.ordax_account_export_v1()','EXECUTE')
    OR has_function_privilege('service_role','public.ordax_account_export_v1()','EXECUTE')
    OR NOT has_function_privilege('authenticated','public.ordax_account_export_v1()','EXECUTE')
  THEN RAISE EXCEPTION 'account-cutover-export-grants-invalid'; END IF;
  IF has_function_privilege('anon','public.ordax_request_subject_v1()','EXECUTE')
    OR has_function_privilege('authenticated','public.ordax_request_subject_v1()','EXECUTE')
  THEN RAISE EXCEPTION 'account-cutover-subject-bridge-exposed'; END IF;
  IF pg_get_functiondef('public.ordax_account_export_v1()'::regprocedure)
       NOT LIKE '%m.project_id%'
    OR pg_get_functiondef('public.ordax_account_export_v1()'::regprocedure)
       LIKE '%m.project_ref%'
  THEN RAISE EXCEPTION 'account-cutover-memory-project-identity-drift'; END IF;
  IF EXISTS (SELECT 1 FROM auth.users)
  THEN RAISE EXCEPTION 'account-cutover-users-created-during-apply'; END IF;
END;
$proof$;
COMMIT;
