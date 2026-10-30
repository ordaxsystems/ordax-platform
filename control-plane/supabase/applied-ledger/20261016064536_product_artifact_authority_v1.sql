-- Canonical Product artifact authority.
-- R2 owns bytes; PostgreSQL owns authorization, metadata, multipart state and retention.
-- No D1 table or second durable authority participates in this path.

create table if not exists private.ordax_product_artifacts (
  artifact_id uuid primary key,
  request_id uuid not null references private.ordax_product_action_requests(request_id) on delete cascade,
  device_id uuid not null references public.ordax_product_devices(device_id) on delete cascade,
  storage_path text not null unique check (char_length(storage_path) between 8 and 1024),
  file_name text not null check (char_length(file_name) between 1 and 180),
  kind text not null check (char_length(kind) between 1 and 80),
  content_type text not null check (char_length(content_type) between 1 and 160),
  size_bytes bigint not null check (size_bytes >= 0),
  sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
  metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
  read_token_sha256 text not null check (read_token_sha256 ~ '^[0-9a-f]{64}$'),
  read_expires_at timestamptz not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default timezone('utc', now())
);

create index if not exists ordax_product_artifacts_request_idx
  on private.ordax_product_artifacts(request_id, created_at);
create index if not exists ordax_product_artifacts_expiry_idx
  on private.ordax_product_artifacts(expires_at, artifact_id);

create table if not exists private.ordax_product_artifact_uploads (
  artifact_id uuid primary key,
  request_id uuid not null references private.ordax_product_action_requests(request_id) on delete cascade,
  device_id uuid not null references public.ordax_product_devices(device_id) on delete cascade,
  upload_id text not null check (char_length(upload_id) between 1 and 1024),
  storage_path text not null unique check (char_length(storage_path) between 8 and 1024),
  file_name text not null check (char_length(file_name) between 1 and 180),
  kind text not null check (char_length(kind) between 1 and 80),
  content_type text not null check (char_length(content_type) between 1 and 160),
  size_bytes bigint not null check (size_bytes >= 0),
  sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'),
  metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
  read_token_sha256 text not null check (read_token_sha256 ~ '^[0-9a-f]{64}$'),
  read_expires_at timestamptz not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default timezone('utc', now())
);

create index if not exists ordax_product_artifact_uploads_expiry_idx
  on private.ordax_product_artifact_uploads(expires_at, artifact_id);

alter table private.ordax_product_artifacts enable row level security;
alter table private.ordax_product_artifact_uploads enable row level security;

revoke all on table private.ordax_product_artifacts from public, anon, authenticated, service_role;
revoke all on table private.ordax_product_artifact_uploads from public, anon, authenticated, service_role;

create or replace function private.ordax_product_execution_context_active_v1(
  p_device_id uuid,
  p_request_id uuid,
  p_effect_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_execution_epoch bigint,
  p_agent_instance_id uuid,
  p_boot_id text
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from private.ordax_product_action_requests r
    where r.request_id = p_request_id
      and r.device_id = p_device_id
      and r.effect_id = p_effect_id
      and r.attempt_id = p_attempt_id
      and r.lease_id = p_lease_id
      and r.execution_epoch = p_execution_epoch
      and r.agent_instance_id = p_agent_instance_id
      and r.boot_id = p_boot_id
      and r.status in ('leased','running')
      and r.lease_expires_at > pg_catalog.clock_timestamp()
  );
$$;

create or replace function public.ordax_begin_product_artifact_upload_v1(
  p_device_id uuid,
  p_request_id uuid,
  p_effect_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_execution_epoch bigint,
  p_agent_instance_id uuid,
  p_boot_id text,
  p_artifact_id uuid,
  p_upload_id text,
  p_storage_path text,
  p_file_name text,
  p_kind text,
  p_content_type text,
  p_size_bytes bigint,
  p_sha256 text,
  p_metadata jsonb,
  p_read_token_sha256 text,
  p_read_expires_at timestamptz,
  p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not private.ordax_product_execution_context_active_v1(
    p_device_id,p_request_id,p_effect_id,p_attempt_id,p_lease_id,p_execution_epoch,
    p_agent_instance_id,p_boot_id
  ) then
    return jsonb_build_object('ok',false,'error','lease_not_active');
  end if;
  if p_read_expires_at <= pg_catalog.clock_timestamp()
     or p_expires_at <= p_read_expires_at
     or p_expires_at > pg_catalog.clock_timestamp() + interval '8 days' then
    return jsonb_build_object('ok',false,'error','artifact_expiry_invalid');
  end if;
  if exists(select 1 from private.ordax_product_artifacts where artifact_id=p_artifact_id) then
    return jsonb_build_object('ok',false,'error','artifact_already_committed');
  end if;
  insert into private.ordax_product_artifact_uploads(
    artifact_id,request_id,device_id,upload_id,storage_path,file_name,kind,content_type,
    size_bytes,sha256,metadata,read_token_sha256,read_expires_at,expires_at
  ) values (
    p_artifact_id,p_request_id,p_device_id,p_upload_id,p_storage_path,p_file_name,p_kind,p_content_type,
    p_size_bytes,p_sha256,coalesce(p_metadata,'{}'::jsonb),p_read_token_sha256,p_read_expires_at,p_expires_at
  )
  on conflict (artifact_id) do nothing;
  return jsonb_build_object('ok',true,'artifact_id',p_artifact_id);
end;
$$;

create or replace function public.ordax_get_product_artifact_upload_v1(
  p_device_id uuid,
  p_request_id uuid,
  p_effect_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_execution_epoch bigint,
  p_agent_instance_id uuid,
  p_boot_id text,
  p_artifact_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare u private.ordax_product_artifact_uploads%rowtype;
begin
  if not private.ordax_product_execution_context_active_v1(
    p_device_id,p_request_id,p_effect_id,p_attempt_id,p_lease_id,p_execution_epoch,
    p_agent_instance_id,p_boot_id
  ) then
    return jsonb_build_object('ok',false,'error','lease_not_active');
  end if;
  select * into u from private.ordax_product_artifact_uploads
   where artifact_id=p_artifact_id and request_id=p_request_id and device_id=p_device_id;
  if not found then return jsonb_build_object('ok',false,'error','artifact_upload_not_found'); end if;
  return jsonb_build_object(
    'ok',true,'artifact_id',u.artifact_id,'upload_id',u.upload_id,'storage_path',u.storage_path,
    'file_name',u.file_name,'kind',u.kind,'content_type',u.content_type,'size_bytes',u.size_bytes,
    'sha256',u.sha256,'metadata',u.metadata,'read_token_sha256',u.read_token_sha256,
    'read_expires_at',u.read_expires_at,'expires_at',u.expires_at
  );
end;
$$;

create or replace function public.ordax_commit_product_artifact_v1(
  p_device_id uuid,
  p_request_id uuid,
  p_effect_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_execution_epoch bigint,
  p_agent_instance_id uuid,
  p_boot_id text,
  p_artifact_id uuid,
  p_storage_path text,
  p_file_name text,
  p_kind text,
  p_content_type text,
  p_size_bytes bigint,
  p_sha256 text,
  p_metadata jsonb,
  p_read_token_sha256 text,
  p_read_expires_at timestamptz,
  p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare a private.ordax_product_artifacts%rowtype;
begin
  if not private.ordax_product_execution_context_active_v1(
    p_device_id,p_request_id,p_effect_id,p_attempt_id,p_lease_id,p_execution_epoch,
    p_agent_instance_id,p_boot_id
  ) then
    return jsonb_build_object('ok',false,'error','lease_not_active');
  end if;
  select * into a from private.ordax_product_artifacts where artifact_id=p_artifact_id;
  if found then
    if a.request_id=p_request_id and a.device_id=p_device_id and a.storage_path=p_storage_path
       and a.sha256=p_sha256 and a.size_bytes=p_size_bytes then
      return jsonb_build_object('ok',true,'replayed',true,'artifact_id',a.artifact_id,'storage_path',a.storage_path);
    end if;
    return jsonb_build_object('ok',false,'error','artifact_replay_conflict');
  end if;
  insert into private.ordax_product_artifacts(
    artifact_id,request_id,device_id,storage_path,file_name,kind,content_type,size_bytes,sha256,
    metadata,read_token_sha256,read_expires_at,expires_at
  ) values (
    p_artifact_id,p_request_id,p_device_id,p_storage_path,p_file_name,p_kind,p_content_type,p_size_bytes,p_sha256,
    coalesce(p_metadata,'{}'::jsonb),p_read_token_sha256,p_read_expires_at,p_expires_at
  );
  delete from private.ordax_product_artifact_uploads where artifact_id=p_artifact_id;
  return jsonb_build_object('ok',true,'replayed',false,'artifact_id',p_artifact_id,'storage_path',p_storage_path);
end;
$$;

create or replace function public.ordax_abort_product_artifact_upload_v1(
  p_device_id uuid,
  p_request_id uuid,
  p_artifact_id uuid
)
returns boolean
language sql
security definer
set search_path = ''
as $$
  with deleted as (
    delete from private.ordax_product_artifact_uploads
    where artifact_id=p_artifact_id and request_id=p_request_id and device_id=p_device_id
    returning 1
  ) select exists(select 1 from deleted);
$$;

create or replace function public.ordax_resolve_product_artifact_download_v1(
  p_artifact_id uuid,
  p_read_token_sha256 text
)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce((
    select jsonb_build_object(
      'ok',true,'artifact_id',a.artifact_id,'storage_path',a.storage_path,
      'file_name',a.file_name,'content_type',a.content_type,'size_bytes',a.size_bytes,'sha256',a.sha256
    )
    from private.ordax_product_artifacts a
    where a.artifact_id=p_artifact_id
      and a.read_token_sha256=p_read_token_sha256
      and a.read_expires_at>pg_catalog.clock_timestamp()
      and a.expires_at>pg_catalog.clock_timestamp()
  ), jsonb_build_object('ok',false,'error','artifact_token_invalid_or_expired'));
$$;

create or replace function public.ordax_list_expired_product_artifacts_v1(p_limit integer default 100)
returns jsonb
language sql
security definer
set search_path = ''
as $$
  select coalesce(jsonb_agg(jsonb_build_object('artifact_id',x.artifact_id,'storage_path',x.storage_path)), '[]'::jsonb)
  from (
    select artifact_id,storage_path from private.ordax_product_artifacts
    where expires_at<=pg_catalog.clock_timestamp()
    order by expires_at,artifact_id limit least(greatest(p_limit,1),500)
  ) x;
$$;

create or replace function public.ordax_delete_expired_product_artifact_v1(p_artifact_id uuid)
returns boolean
language sql
security definer
set search_path = ''
as $$
  with deleted as (
    delete from private.ordax_product_artifacts
    where artifact_id=p_artifact_id and expires_at<=pg_catalog.clock_timestamp()
    returning 1
  ) select exists(select 1 from deleted);
$$;

create or replace function public.ordax_purge_expired_product_artifact_uploads_v1(p_limit integer default 100)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare result jsonb;
begin
  with doomed as (
    select artifact_id,storage_path,upload_id from private.ordax_product_artifact_uploads
    where expires_at<=pg_catalog.clock_timestamp()
    order by expires_at,artifact_id limit least(greatest(p_limit,1),500)
  ), deleted as (
    delete from private.ordax_product_artifact_uploads u using doomed d
    where u.artifact_id=d.artifact_id
    returning d.artifact_id,d.storage_path,d.upload_id
  ) select coalesce(jsonb_agg(jsonb_build_object('artifact_id',artifact_id,'storage_path',storage_path,'upload_id',upload_id)), '[]'::jsonb)
    into result from deleted;
  return result;
end;
$$;

revoke all on function private.ordax_product_execution_context_active_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text)
  from public, anon, authenticated, service_role;
revoke all on function public.ordax_begin_product_artifact_upload_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid,text,text,text,text,text,bigint,text,jsonb,text,timestamptz,timestamptz)
  from public, anon, authenticated, service_role;
revoke all on function public.ordax_get_product_artifact_upload_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid)
  from public, anon, authenticated, service_role;
revoke all on function public.ordax_commit_product_artifact_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid,text,text,text,text,bigint,text,jsonb,text,timestamptz,timestamptz)
  from public, anon, authenticated, service_role;
revoke all on function public.ordax_abort_product_artifact_upload_v1(uuid,uuid,uuid)
  from public, anon, authenticated, service_role;
revoke all on function public.ordax_resolve_product_artifact_download_v1(uuid,text)
  from public, anon, authenticated, service_role;
revoke all on function public.ordax_list_expired_product_artifacts_v1(integer)
  from public, anon, authenticated, service_role;
revoke all on function public.ordax_delete_expired_product_artifact_v1(uuid)
  from public, anon, authenticated, service_role;
revoke all on function public.ordax_purge_expired_product_artifact_uploads_v1(integer)
  from public, anon, authenticated, service_role;

grant execute on function public.ordax_begin_product_artifact_upload_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid,text,text,text,text,text,bigint,text,jsonb,text,timestamptz,timestamptz) to ordax_edge_runtime;
grant execute on function public.ordax_get_product_artifact_upload_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid) to ordax_edge_runtime;
grant execute on function public.ordax_commit_product_artifact_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid,text,text,text,text,bigint,text,jsonb,text,timestamptz,timestamptz) to ordax_edge_runtime;
grant execute on function public.ordax_abort_product_artifact_upload_v1(uuid,uuid,uuid) to ordax_edge_runtime;
grant execute on function public.ordax_resolve_product_artifact_download_v1(uuid,text) to ordax_edge_runtime;
grant execute on function public.ordax_list_expired_product_artifacts_v1(integer) to ordax_edge_runtime;
grant execute on function public.ordax_delete_expired_product_artifact_v1(uuid) to ordax_edge_runtime;
grant execute on function public.ordax_purge_expired_product_artifact_uploads_v1(integer) to ordax_edge_runtime;

create or replace function public.ordax_refresh_product_artifact_read_v1(
  p_device_id uuid,
  p_request_id uuid,
  p_artifact_id uuid,
  p_read_token_sha256 text,
  p_read_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare a private.ordax_product_artifacts%rowtype;
begin
  update private.ordax_product_artifacts
     set read_token_sha256=p_read_token_sha256, read_expires_at=p_read_expires_at
   where artifact_id=p_artifact_id and request_id=p_request_id and device_id=p_device_id
     and expires_at>pg_catalog.clock_timestamp()
   returning * into a;
  if not found then return jsonb_build_object('ok',false,'error','artifact_not_found'); end if;
  return jsonb_build_object('ok',true,'artifact_id',a.artifact_id,'storage_path',a.storage_path,
    'file_name',a.file_name,'kind',a.kind,'content_type',a.content_type,'size_bytes',a.size_bytes,
    'sha256',a.sha256,'metadata',a.metadata,'expires_at',a.expires_at);
end;
$$;

revoke all on function public.ordax_refresh_product_artifact_read_v1(uuid,uuid,uuid,text,timestamptz)
  from public, anon, authenticated, service_role;
grant execute on function public.ordax_refresh_product_artifact_read_v1(uuid,uuid,uuid,text,timestamptz)
  to ordax_edge_runtime;