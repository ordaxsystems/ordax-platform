begin;

-- Canonical artifact metadata authority.
-- R2 owns object bytes; PostgreSQL owns durable metadata and read-token state.
-- These tables intentionally do not mirror the legacy D1 schema 1:1 and do
-- not depend on the still-unresolved engineering job/device persistence model.

create table private.ordax_artifact_records (
  artifact_id uuid primary key,
  producer_kind text not null
    check (producer_kind in ('product','engineering')),
  producer_job_id uuid not null,
  producer_device_id uuid not null,
  object_key text not null unique
    check (char_length(object_key) between 1 and 1024),
  file_name text not null
    check (
      char_length(file_name) between 1 and 180
      and file_name !~ '[[:cntrl:]]'
    ),
  kind text not null
    check (
      char_length(kind) between 1 and 80
      and kind !~ '[[:cntrl:]]'
    ),
  content_type text not null
    check (
      char_length(content_type) between 1 and 255
      and content_type !~ '[[:cntrl:]]'
    ),
  sha256 text not null
    check (sha256 ~ '^[0-9a-f]{64}$'),
  size_bytes bigint not null
    check (size_bytes between 0 and 966367641600),
  metadata jsonb not null default '{}'::jsonb
    check (
      jsonb_typeof(metadata) = 'object'
      and pg_catalog.octet_length(metadata::text) <= 4096
    ),
  read_token_sha256 text not null
    check (read_token_sha256 ~ '^[0-9a-f]{64}$'),
  read_expires_at timestamptz not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  updated_at timestamptz not null default pg_catalog.clock_timestamp()
);

create index ordax_artifact_records_job_idx
  on private.ordax_artifact_records(producer_job_id, created_at);
create index ordax_artifact_records_device_idx
  on private.ordax_artifact_records(producer_device_id, created_at);
create index ordax_artifact_records_product_retention_idx
  on private.ordax_artifact_records(created_at)
  where producer_kind = 'product';

create table private.ordax_artifact_upload_sessions (
  artifact_id uuid primary key,
  producer_kind text not null
    check (producer_kind in ('product','engineering')),
  producer_job_id uuid not null,
  producer_device_id uuid not null,
  r2_upload_id text not null
    check (char_length(r2_upload_id) between 1 and 512),
  object_key text not null unique
    check (char_length(object_key) between 1 and 1024),
  file_name text not null
    check (
      char_length(file_name) between 1 and 180
      and file_name !~ '[[:cntrl:]]'
    ),
  kind text not null
    check (
      char_length(kind) between 1 and 80
      and kind !~ '[[:cntrl:]]'
    ),
  content_type text not null
    check (
      char_length(content_type) between 1 and 255
      and content_type !~ '[[:cntrl:]]'
    ),
  sha256 text not null
    check (sha256 ~ '^[0-9a-f]{64}$'),
  size_bytes bigint not null
    check (size_bytes between 1 and 966367641600),
  metadata jsonb not null default '{}'::jsonb
    check (
      jsonb_typeof(metadata) = 'object'
      and pg_catalog.octet_length(metadata::text) <= 4096
    ),
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  expires_at timestamptz not null
);

create index ordax_artifact_upload_sessions_device_idx
  on private.ordax_artifact_upload_sessions(producer_device_id, created_at);
create index ordax_artifact_upload_sessions_product_retention_idx
  on private.ordax_artifact_upload_sessions(expires_at)
  where producer_kind = 'product';

alter table private.ordax_artifact_records enable row level security;
alter table private.ordax_artifact_upload_sessions enable row level security;

revoke all on table private.ordax_artifact_records
  from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on table private.ordax_artifact_upload_sessions
  from public, anon, authenticated, service_role, ordax_edge_executor;

create or replace function public.ordax_artifact_lookup_v1(
  p_artifact_id uuid
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $function$
  select jsonb_build_object(
    'ok', true,
    'artifact',
    case
      when a.artifact_id is null then null
      else jsonb_build_object(
        'artifact_id', a.artifact_id,
        'producer_kind', a.producer_kind,
        'job_id', a.producer_job_id,
        'device_id', a.producer_device_id,
        'storage_path', a.object_key,
        'file_name', a.file_name,
        'kind', a.kind,
        'content_type', a.content_type,
        'sha256', a.sha256,
        'size_bytes', a.size_bytes,
        'metadata', a.metadata,
        'read_expires_at', a.read_expires_at,
        'created_at', a.created_at
      )
    end
  )
  from (select 1) seed
  left join private.ordax_artifact_records a
    on a.artifact_id = p_artifact_id;
$function$;

create or replace function public.ordax_rotate_artifact_read_token_v1(
  p_artifact_id uuid,
  p_job_id uuid,
  p_device_id uuid,
  p_read_token_sha256 text,
  p_read_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_count integer;
begin
  if p_artifact_id is null
     or p_job_id is null
     or p_device_id is null
     or p_read_token_sha256 is null
     or p_read_token_sha256 !~ '^[0-9a-f]{64}$'
     or p_read_expires_at is null
     or p_read_expires_at <= v_now
     or p_read_expires_at > v_now + interval '24 hours'
  then
    return jsonb_build_object('ok', false, 'error', 'artifact_read_token_invalid');
  end if;

  update private.ordax_artifact_records
     set read_token_sha256 = p_read_token_sha256,
         read_expires_at = p_read_expires_at,
         updated_at = v_now
   where artifact_id = p_artifact_id
     and producer_job_id = p_job_id
     and producer_device_id = p_device_id;

  get diagnostics v_count = row_count;
  if v_count <> 1 then
    return jsonb_build_object('ok', false, 'error', 'artifact_not_found');
  end if;

  return jsonb_build_object(
    'ok', true,
    'artifact_id', p_artifact_id,
    'expires_at', p_read_expires_at
  );
end;
$function$;

create or replace function public.ordax_publish_artifact_v1(
  p_artifact_id uuid,
  p_producer_kind text,
  p_job_id uuid,
  p_device_id uuid,
  p_storage_path text,
  p_file_name text,
  p_kind text,
  p_content_type text,
  p_sha256 text,
  p_size_bytes bigint,
  p_metadata jsonb,
  p_read_token_sha256 text,
  p_read_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_existing private.ordax_artifact_records%rowtype;
  v_prefix text;
begin
  v_prefix := p_device_id::text || '/' || p_job_id::text || '/' || p_artifact_id::text || '-';

  if p_artifact_id is null
     or p_producer_kind not in ('product','engineering')
     or p_job_id is null
     or p_device_id is null
     or p_storage_path is null
     or char_length(p_storage_path) not between 1 and 1024
     or left(p_storage_path, char_length(v_prefix)) <> v_prefix
     or p_file_name is null
     or char_length(p_file_name) not between 1 and 180
     or p_file_name ~ '[[:cntrl:]]'
     or p_kind is null
     or char_length(p_kind) not between 1 and 80
     or p_kind ~ '[[:cntrl:]]'
     or p_content_type is null
     or char_length(p_content_type) not between 1 and 255
     or p_content_type ~ '[[:cntrl:]]'
     or p_sha256 is null
     or p_sha256 !~ '^[0-9a-f]{64}$'
     or p_size_bytes is null
     or p_size_bytes not between 0 and 966367641600
     or p_metadata is null
     or jsonb_typeof(p_metadata) <> 'object'
     or pg_catalog.octet_length(p_metadata::text) > 4096
     or p_read_token_sha256 is null
     or p_read_token_sha256 !~ '^[0-9a-f]{64}$'
     or p_read_expires_at is null
     or p_read_expires_at <= v_now
     or p_read_expires_at > v_now + interval '24 hours'
  then
    return jsonb_build_object('ok', false, 'error', 'artifact_metadata_invalid');
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext(p_artifact_id::text)
  );

  select *
    into v_existing
    from private.ordax_artifact_records
   where artifact_id = p_artifact_id
   for update;

  if found then
    if v_existing.producer_kind <> p_producer_kind
       or v_existing.producer_job_id <> p_job_id
       or v_existing.producer_device_id <> p_device_id
       or v_existing.object_key <> p_storage_path
       or v_existing.file_name <> p_file_name
       or v_existing.kind <> p_kind
       or v_existing.content_type <> p_content_type
       or v_existing.sha256 <> p_sha256
       or v_existing.size_bytes <> p_size_bytes
       or v_existing.metadata <> p_metadata
    then
      return jsonb_build_object('ok', false, 'error', 'artifact_replay_conflict');
    end if;

    update private.ordax_artifact_records
       set read_token_sha256 = p_read_token_sha256,
           read_expires_at = p_read_expires_at,
           updated_at = v_now
     where artifact_id = p_artifact_id;

    return jsonb_build_object(
      'ok', true,
      'replayed', true,
      'artifact_id', p_artifact_id,
      'storage_path', p_storage_path,
      'expires_at', p_read_expires_at
    );
  end if;

  insert into private.ordax_artifact_records(
    artifact_id,
    producer_kind,
    producer_job_id,
    producer_device_id,
    object_key,
    file_name,
    kind,
    content_type,
    sha256,
    size_bytes,
    metadata,
    read_token_sha256,
    read_expires_at,
    created_at,
    updated_at
  ) values (
    p_artifact_id,
    p_producer_kind,
    p_job_id,
    p_device_id,
    p_storage_path,
    p_file_name,
    p_kind,
    p_content_type,
    p_sha256,
    p_size_bytes,
    p_metadata,
    p_read_token_sha256,
    p_read_expires_at,
    v_now,
    v_now
  );

  return jsonb_build_object(
    'ok', true,
    'replayed', false,
    'artifact_id', p_artifact_id,
    'storage_path', p_storage_path,
    'expires_at', p_read_expires_at
  );
end;
$function$;

create or replace function public.ordax_get_artifact_upload_v1(
  p_artifact_id uuid,
  p_job_id uuid,
  p_device_id uuid
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $function$
  select jsonb_build_object(
    'ok', true,
    'upload',
    case
      when u.artifact_id is null then null
      else jsonb_build_object(
        'artifact_id', u.artifact_id,
        'producer_kind', u.producer_kind,
        'job_id', u.producer_job_id,
        'device_id', u.producer_device_id,
        'upload_id', u.r2_upload_id,
        'storage_path', u.object_key,
        'file_name', u.file_name,
        'kind', u.kind,
        'content_type', u.content_type,
        'sha256', u.sha256,
        'size_bytes', u.size_bytes,
        'metadata', u.metadata,
        'created_at', u.created_at,
        'expires_at', u.expires_at
      )
    end
  )
  from (select 1) seed
  left join private.ordax_artifact_upload_sessions u
    on u.artifact_id = p_artifact_id
   and u.producer_job_id = p_job_id
   and u.producer_device_id = p_device_id;
$function$;

create or replace function public.ordax_create_artifact_upload_v1(
  p_artifact_id uuid,
  p_producer_kind text,
  p_job_id uuid,
  p_device_id uuid,
  p_upload_id text,
  p_storage_path text,
  p_file_name text,
  p_kind text,
  p_content_type text,
  p_sha256 text,
  p_size_bytes bigint,
  p_metadata jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_existing private.ordax_artifact_upload_sessions%rowtype;
  v_prefix text;
  v_expires_at timestamptz := v_now + interval '8 days';
begin
  v_prefix := p_device_id::text || '/' || p_job_id::text || '/' || p_artifact_id::text || '-';

  if p_artifact_id is null
     or p_producer_kind not in ('product','engineering')
     or p_job_id is null
     or p_device_id is null
     or p_upload_id is null
     or char_length(p_upload_id) not between 1 and 512
     or p_storage_path is null
     or char_length(p_storage_path) not between 1 and 1024
     or left(p_storage_path, char_length(v_prefix)) <> v_prefix
     or p_file_name is null
     or char_length(p_file_name) not between 1 and 180
     or p_file_name ~ '[[:cntrl:]]'
     or p_kind is null
     or char_length(p_kind) not between 1 and 80
     or p_kind ~ '[[:cntrl:]]'
     or p_content_type is null
     or char_length(p_content_type) not between 1 and 255
     or p_content_type ~ '[[:cntrl:]]'
     or p_sha256 is null
     or p_sha256 !~ '^[0-9a-f]{64}$'
     or p_size_bytes is null
     or p_size_bytes not between 1 and 966367641600
     or p_metadata is null
     or jsonb_typeof(p_metadata) <> 'object'
     or pg_catalog.octet_length(p_metadata::text) > 4096
  then
    return jsonb_build_object('ok', false, 'error', 'multipart_upload_invalid');
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext(p_artifact_id::text)
  );

  delete from private.ordax_artifact_upload_sessions
   where artifact_id = p_artifact_id
     and expires_at <= v_now;

  select *
    into v_existing
    from private.ordax_artifact_upload_sessions
   where artifact_id = p_artifact_id
   for update;

  if found then
    if v_existing.producer_kind = p_producer_kind
       and v_existing.producer_job_id = p_job_id
       and v_existing.producer_device_id = p_device_id
       and v_existing.object_key = p_storage_path
       and v_existing.file_name = p_file_name
       and v_existing.kind = p_kind
       and v_existing.content_type = p_content_type
       and v_existing.sha256 = p_sha256
       and v_existing.size_bytes = p_size_bytes
       and v_existing.metadata = p_metadata
    then
      return jsonb_build_object(
        'ok', true,
        'resumed', true,
        'upload_id', v_existing.r2_upload_id,
        'storage_path', v_existing.object_key,
        'expires_at', v_existing.expires_at
      );
    end if;

    return jsonb_build_object('ok', false, 'error', 'multipart_upload_conflict');
  end if;

  insert into private.ordax_artifact_upload_sessions(
    artifact_id,
    producer_kind,
    producer_job_id,
    producer_device_id,
    r2_upload_id,
    object_key,
    file_name,
    kind,
    content_type,
    sha256,
    size_bytes,
    metadata,
    created_at,
    expires_at
  ) values (
    p_artifact_id,
    p_producer_kind,
    p_job_id,
    p_device_id,
    p_upload_id,
    p_storage_path,
    p_file_name,
    p_kind,
    p_content_type,
    p_sha256,
    p_size_bytes,
    p_metadata,
    v_now,
    v_expires_at
  );

  return jsonb_build_object(
    'ok', true,
    'resumed', false,
    'upload_id', p_upload_id,
    'storage_path', p_storage_path,
    'expires_at', v_expires_at
  );
end;
$function$;

create or replace function public.ordax_delete_artifact_upload_v1(
  p_artifact_id uuid,
  p_job_id uuid,
  p_device_id uuid,
  p_upload_id text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_count integer;
begin
  delete from private.ordax_artifact_upload_sessions
   where artifact_id = p_artifact_id
     and producer_job_id = p_job_id
     and producer_device_id = p_device_id
     and r2_upload_id = p_upload_id;

  get diagnostics v_count = row_count;

  return jsonb_build_object(
    'ok', true,
    'deleted', v_count = 1
  );
end;
$function$;

create or replace function public.ordax_authorize_artifact_download_v1(
  p_artifact_id uuid,
  p_read_token_sha256 text
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $function$
  select case
    when a.artifact_id is null then
      jsonb_build_object('ok', false, 'error', 'artifact_token_invalid_or_expired')
    else
      jsonb_build_object(
        'ok', true,
        'artifact_id', a.artifact_id,
        'storage_path', a.object_key,
        'file_name', a.file_name,
        'content_type', a.content_type,
        'sha256', a.sha256,
        'size_bytes', a.size_bytes
      )
    end
  from (select 1) seed
  left join lateral (
    select r.*
      from private.ordax_artifact_records r
     where r.artifact_id = p_artifact_id
       and r.read_token_sha256 = p_read_token_sha256
       and r.read_expires_at > pg_catalog.statement_timestamp()
     limit 1
  ) a on true;
$function$;

create or replace function public.ordax_list_artifact_device_objects_v1(
  p_device_id uuid
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $function$
  select jsonb_build_object(
    'ok', true,
    'artifacts', coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'artifact_id', r.artifact_id,
          'storage_path', r.object_key
        )
        order by r.created_at
      )
      from private.ordax_artifact_records r
      where r.producer_device_id = p_device_id
    ), '[]'::jsonb),
    'uploads', coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'artifact_id', u.artifact_id,
          'upload_id', u.r2_upload_id,
          'storage_path', u.object_key,
          'job_id', u.producer_job_id
        )
        order by u.created_at
      )
      from private.ordax_artifact_upload_sessions u
      where u.producer_device_id = p_device_id
    ), '[]'::jsonb)
  );
$function$;

create or replace function public.ordax_delete_artifact_record_v1(
  p_artifact_id uuid,
  p_storage_path text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_count integer;
begin
  delete from private.ordax_artifact_records
   where artifact_id = p_artifact_id
     and object_key = p_storage_path;

  get diagnostics v_count = row_count;
  return jsonb_build_object('ok', true, 'deleted', v_count = 1);
end;
$function$;

create or replace function public.ordax_list_artifact_retention_candidates_v1(
  p_ready_before timestamptz,
  p_upload_before timestamptz,
  p_limit integer default 100
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $function$
  select jsonb_build_object(
    'ok', true,
    'artifacts', coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'artifact_id', q.artifact_id,
          'storage_path', q.object_key
        )
        order by q.created_at
      )
      from (
        select r.artifact_id, r.object_key, r.created_at
        from private.ordax_artifact_records r
        where r.producer_kind = 'product'
          and r.created_at < p_ready_before
        order by r.created_at
        limit greatest(1, least(coalesce(p_limit, 100), 100))
      ) q
    ), '[]'::jsonb),
    'uploads', coalesce((
      select jsonb_agg(
        jsonb_build_object(
          'artifact_id', q.artifact_id,
          'job_id', q.producer_job_id,
          'device_id', q.producer_device_id,
          'upload_id', q.r2_upload_id,
          'storage_path', q.object_key
        )
        order by q.created_at
      )
      from (
        select
          u.artifact_id,
          u.producer_job_id,
          u.producer_device_id,
          u.r2_upload_id,
          u.object_key,
          u.created_at
        from private.ordax_artifact_upload_sessions u
        where u.producer_kind = 'product'
          and u.created_at < p_upload_before
        order by u.created_at
        limit greatest(1, least(coalesce(p_limit, 100), 100))
      ) q
    ), '[]'::jsonb)
  );
$function$;

revoke all on function public.ordax_artifact_lookup_v1(uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function public.ordax_rotate_artifact_read_token_v1(
  uuid, uuid, uuid, text, timestamptz
) from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function public.ordax_publish_artifact_v1(
  uuid, text, uuid, uuid, text, text, text, text, text, bigint, jsonb, text, timestamptz
) from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function public.ordax_get_artifact_upload_v1(uuid, uuid, uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function public.ordax_create_artifact_upload_v1(
  uuid, text, uuid, uuid, text, text, text, text, text, text, bigint, jsonb
) from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function public.ordax_delete_artifact_upload_v1(uuid, uuid, uuid, text)
  from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function public.ordax_authorize_artifact_download_v1(uuid, text)
  from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function public.ordax_list_artifact_device_objects_v1(uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function public.ordax_delete_artifact_record_v1(uuid, text)
  from public, anon, authenticated, service_role, ordax_edge_executor;
revoke all on function public.ordax_list_artifact_retention_candidates_v1(
  timestamptz, timestamptz, integer
) from public, anon, authenticated, service_role, ordax_edge_executor;

grant execute on function public.ordax_artifact_lookup_v1(uuid)
  to ordax_edge_executor;
grant execute on function public.ordax_rotate_artifact_read_token_v1(
  uuid, uuid, uuid, text, timestamptz
) to ordax_edge_executor;
grant execute on function public.ordax_publish_artifact_v1(
  uuid, text, uuid, uuid, text, text, text, text, text, bigint, jsonb, text, timestamptz
) to ordax_edge_executor;
grant execute on function public.ordax_get_artifact_upload_v1(uuid, uuid, uuid)
  to ordax_edge_executor;
grant execute on function public.ordax_create_artifact_upload_v1(
  uuid, text, uuid, uuid, text, text, text, text, text, text, bigint, jsonb
) to ordax_edge_executor;
grant execute on function public.ordax_delete_artifact_upload_v1(uuid, uuid, uuid, text)
  to ordax_edge_executor;
grant execute on function public.ordax_authorize_artifact_download_v1(uuid, text)
  to ordax_edge_executor;
grant execute on function public.ordax_list_artifact_device_objects_v1(uuid)
  to ordax_edge_executor;
grant execute on function public.ordax_delete_artifact_record_v1(uuid, text)
  to ordax_edge_executor;
grant execute on function public.ordax_list_artifact_retention_candidates_v1(
  timestamptz, timestamptz, integer
) to ordax_edge_executor;

do $postflight$
declare
  v_direct_table_grants integer;
  v_leaked_functions integer;
  v_edge_functions integer;
begin
  select count(*)
    into v_direct_table_grants
  from information_schema.role_table_grants
  where grantee in ('ordax_edge_executor', 'service_role')
    and table_schema = 'private'
    and table_name in ('ordax_artifact_records', 'ordax_artifact_upload_sessions');

  if v_direct_table_grants <> 0 then
    raise exception 'artifact authority leaked direct table privileges';
  end if;

  select count(*)
    into v_leaked_functions
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and p.proname in (
      'ordax_artifact_lookup_v1',
      'ordax_rotate_artifact_read_token_v1',
      'ordax_publish_artifact_v1',
      'ordax_get_artifact_upload_v1',
      'ordax_create_artifact_upload_v1',
      'ordax_delete_artifact_upload_v1',
      'ordax_authorize_artifact_download_v1',
      'ordax_list_artifact_device_objects_v1',
      'ordax_delete_artifact_record_v1',
      'ordax_list_artifact_retention_candidates_v1'
    )
    and (
      has_function_privilege('anon', p.oid, 'EXECUTE')
      or has_function_privilege('authenticated', p.oid, 'EXECUTE')
      or has_function_privilege('service_role', p.oid, 'EXECUTE')
    );

  if v_leaked_functions <> 0 then
    raise exception 'artifact authority RPC leaked outside edge executor';
  end if;

  select count(*)
    into v_edge_functions
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public'
    and p.proname in (
      'ordax_artifact_lookup_v1',
      'ordax_rotate_artifact_read_token_v1',
      'ordax_publish_artifact_v1',
      'ordax_get_artifact_upload_v1',
      'ordax_create_artifact_upload_v1',
      'ordax_delete_artifact_upload_v1',
      'ordax_authorize_artifact_download_v1',
      'ordax_list_artifact_device_objects_v1',
      'ordax_delete_artifact_record_v1',
      'ordax_list_artifact_retention_candidates_v1'
    )
    and has_function_privilege('ordax_edge_executor', p.oid, 'EXECUTE');

  if v_edge_functions <> 10 then
    raise exception 'artifact authority edge RPC ACL mismatch: %', v_edge_functions;
  end if;
end;
$postflight$;

commit;
