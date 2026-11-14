begin;

create table if not exists private.ordax_forge_instances (
  instance_id uuid primary key,
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  display_name text not null,
  app_version text not null,
  catalog jsonb not null,
  catalog_digest text not null,
  reported_online boolean not null default false,
  last_seen_at timestamptz,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  updated_at timestamptz not null default pg_catalog.clock_timestamp(),
  revoked_at timestamptz,
  constraint ordax_forge_instance_name_chk check (
    char_length(display_name) between 1 and 160 and display_name = btrim(display_name)
  ),
  constraint ordax_forge_instance_version_chk check (
    char_length(app_version) between 1 and 80 and app_version = btrim(app_version)
  ),
  constraint ordax_forge_instance_catalog_chk check (
    jsonb_typeof(catalog) = 'array' and jsonb_array_length(catalog) between 1 and 64
  ),
  constraint ordax_forge_instance_digest_chk check (catalog_digest ~ '^[0-9a-f]{64}$')
);

create index if not exists ordax_forge_instances_owner_idx
  on private.ordax_forge_instances(owner_user_id, created_at);

create table if not exists private.ordax_forge_mcp_bindings (
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  client_id text not null,
  instance_id uuid not null references private.ordax_forge_instances(instance_id) on delete cascade,
  bound_at timestamptz not null default pg_catalog.clock_timestamp(),
  revoked_at timestamptz,
  primary key(owner_user_id, client_id),
  constraint ordax_forge_binding_client_chk check (
    client_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  )
);

create index if not exists ordax_forge_bindings_instance_idx
  on private.ordax_forge_mcp_bindings(instance_id)
  where revoked_at is null;

create table if not exists private.ordax_forge_action_requests (
  request_id uuid primary key default gen_random_uuid(),
  effect_id uuid not null default gen_random_uuid(),
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  client_id text not null,
  instance_id uuid not null references private.ordax_forge_instances(instance_id) on delete cascade,
  tool_name text not null,
  access_mode text not null,
  arguments jsonb not null,
  idempotency_key text not null,
  status text not null default 'queued',
  attempt_id uuid,
  lease_id uuid,
  agent_instance_id uuid,
  boot_id text,
  lease_expires_at timestamptz,
  expires_at timestamptz not null,
  result jsonb,
  error_code text,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  started_at timestamptz,
  finished_at timestamptz,
  constraint ordax_forge_action_client_chk check (
    client_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  ),
  constraint ordax_forge_action_tool_chk check (
    char_length(tool_name) between 1 and 120 and tool_name ~ '^forge_[a-z0-9_]+$'
  ),
  constraint ordax_forge_action_mode_chk check (access_mode in ('read','write')),
  constraint ordax_forge_action_args_chk check (jsonb_typeof(arguments) = 'object'),
  constraint ordax_forge_action_key_chk check (
    char_length(idempotency_key) between 16 and 180
    and idempotency_key ~ '^[A-Za-z0-9:_-]+$'
  ),
  constraint ordax_forge_action_status_chk check (
    status in ('queued','leased','running','succeeded','failed','cancelled','expired')
  ),
  unique(owner_user_id, client_id, idempotency_key)
);

create index if not exists ordax_forge_action_claim_idx
  on private.ordax_forge_action_requests(instance_id, status, created_at)
  where status in ('queued','leased','running');

create index if not exists ordax_forge_action_owner_idx
  on private.ordax_forge_action_requests(owner_user_id, client_id, created_at desc);

create or replace function private.ordax_forge_oauth_client_authorized_v1(
  p_owner_user_id uuid, p_client_id text
)
returns boolean
language sql
security definer
set search_path = ''
stable
as $$
  select exists (
    select 1
    from auth.oauth_consents consent
    join auth.oauth_clients client on client.id = consent.client_id
    where consent.user_id = p_owner_user_id
      and client.id::text = p_client_id
      and consent.revoked_at is null
      and client.deleted_at is null
  );
$$;

revoke all on function private.ordax_forge_oauth_client_authorized_v1(uuid,text)
  from public,anon,authenticated,service_role,ordax_edge_runtime,ordax_edge_executor;

create or replace function public.ordax_register_forge_instance_v1(
  p_owner_user_id uuid,
  p_instance_id uuid,
  p_display_name text,
  p_app_version text,
  p_catalog jsonb,
  p_catalog_digest text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_existing private.ordax_forge_instances%rowtype;
  v_now timestamptz := pg_catalog.clock_timestamp();
begin
  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
     or p_instance_id is null
     or p_display_name is null or char_length(p_display_name) not between 1 and 160
     or p_display_name <> btrim(p_display_name)
     or p_app_version is null or char_length(p_app_version) not between 1 and 80
     or p_app_version <> btrim(p_app_version)
     or p_catalog is null or jsonb_typeof(p_catalog) <> 'array'
     or jsonb_array_length(p_catalog) not between 1 and 64
     or p_catalog_digest !~ '^[0-9a-f]{64}$'
  then
    return jsonb_build_object('ok',false,'error','forge_instance_registration_invalid');
  end if;

  select * into v_existing
  from private.ordax_forge_instances
  where instance_id = p_instance_id
  for update;

  if found then
    if v_existing.owner_user_id <> p_owner_user_id then
      return jsonb_build_object('ok',false,'error','forge_instance_owner_mismatch');
    end if;
    if v_existing.revoked_at is not null then
      return jsonb_build_object('ok',false,'error','forge_instance_revoked');
    end if;
    update private.ordax_forge_instances
    set display_name=p_display_name, app_version=p_app_version,
        catalog=p_catalog, catalog_digest=p_catalog_digest,
        reported_online=true, last_seen_at=v_now, updated_at=v_now
    where instance_id=p_instance_id;
  else
    insert into private.ordax_forge_instances(
      instance_id,owner_user_id,display_name,app_version,catalog,catalog_digest,
      reported_online,last_seen_at,created_at,updated_at
    ) values(
      p_instance_id,p_owner_user_id,p_display_name,p_app_version,p_catalog,p_catalog_digest,
      true,v_now,v_now,v_now
    );
  end if;

  return jsonb_build_object(
    'ok',true,'instance_id',p_instance_id,'registered',true,'last_seen_at',v_now
  );
end;
$$;

create or replace function public.ordax_update_forge_presence_v1(
  p_owner_user_id uuid,
  p_instance_id uuid,
  p_online boolean,
  p_app_version text,
  p_catalog jsonb,
  p_catalog_digest text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_updated integer;
begin
  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
     or p_instance_id is null
     or p_online is null
     or p_app_version is null or char_length(p_app_version) not between 1 and 80
     or p_app_version <> btrim(p_app_version)
     or p_catalog is null or jsonb_typeof(p_catalog) <> 'array'
     or jsonb_array_length(p_catalog) not between 1 and 64
     or p_catalog_digest !~ '^[0-9a-f]{64}$'
  then
    return jsonb_build_object('ok',false,'error','forge_presence_invalid');
  end if;

  update private.ordax_forge_instances
  set reported_online=p_online, app_version=p_app_version,
      catalog=p_catalog, catalog_digest=p_catalog_digest,
      last_seen_at=v_now, updated_at=v_now
  where instance_id=p_instance_id
    and owner_user_id=p_owner_user_id
    and revoked_at is null;

  get diagnostics v_updated = row_count;
  if v_updated <> 1 then
    return jsonb_build_object('ok',false,'error','forge_instance_not_found');
  end if;

  return jsonb_build_object('ok',true,'instance_id',p_instance_id,
    'online',p_online,'last_seen_at',v_now);
end;
$$;

create or replace function public.ordax_resolve_forge_mcp_instance_v1(
  p_owner_user_id uuid,
  p_client_id text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_binding private.ordax_forge_mcp_bindings%rowtype;
  v_instance private.ordax_forge_instances%rowtype;
  v_count integer := 0;
  v_now timestamptz := pg_catalog.clock_timestamp();
begin
  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
     or p_client_id is null
     or p_client_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     or not private.ordax_forge_oauth_client_authorized_v1(p_owner_user_id,p_client_id)
  then
    return jsonb_build_object('ok',false,'error','forge_mcp_authorization_required');
  end if;

  select b.* into v_binding
  from private.ordax_forge_mcp_bindings b
  join private.ordax_forge_instances i on i.instance_id=b.instance_id
  where b.owner_user_id=p_owner_user_id
    and b.client_id=p_client_id
    and b.revoked_at is null
    and i.revoked_at is null
    and i.owner_user_id=p_owner_user_id
  for update of b;

  if found then
    select * into v_instance from private.ordax_forge_instances
      where instance_id=v_binding.instance_id;
  else
    select count(*)::integer into v_count
    from private.ordax_forge_instances
    where owner_user_id=p_owner_user_id and revoked_at is null;

    if v_count = 0 then
      return jsonb_build_object('ok',false,'error','forge_instance_unavailable');
    end if;
    if v_count > 1 then
      return jsonb_build_object('ok',false,'error','forge_instance_selection_required',
        'candidate_count',v_count);
    end if;

    select * into v_instance
    from private.ordax_forge_instances
    where owner_user_id=p_owner_user_id and revoked_at is null
    limit 1
    for update;

    insert into private.ordax_forge_mcp_bindings(owner_user_id,client_id,instance_id,bound_at,revoked_at)
    values(p_owner_user_id,p_client_id,v_instance.instance_id,v_now,null)
    on conflict(owner_user_id,client_id) do update
      set instance_id=excluded.instance_id,bound_at=excluded.bound_at,revoked_at=null;
  end if;

  return jsonb_build_object(
    'ok',true,
    'instance_id',v_instance.instance_id,
    'display_name',v_instance.display_name,
    'app_version',v_instance.app_version,
    'catalog',v_instance.catalog,
    'catalog_digest',v_instance.catalog_digest,
    'online',(
      v_instance.reported_online
      and v_instance.last_seen_at is not null
      and v_instance.last_seen_at > v_now - interval '90 seconds'
    ),
    'last_seen_at',v_instance.last_seen_at
  );
end;
$$;

create or replace function public.ordax_enqueue_forge_action_v1(
  p_owner_user_id uuid,
  p_client_id text,
  p_instance_id uuid,
  p_tool_name text,
  p_access_mode text,
  p_arguments jsonb,
  p_idempotency_key text,
  p_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_existing private.ordax_forge_action_requests%rowtype;
  v_request_id uuid := gen_random_uuid();
  v_effect_id uuid := gen_random_uuid();
  v_now timestamptz := pg_catalog.clock_timestamp();
begin
  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
     or p_client_id is null
     or not private.ordax_forge_oauth_client_authorized_v1(p_owner_user_id,p_client_id)
     or p_instance_id is null
     or p_tool_name is null or p_tool_name !~ '^forge_[a-z0-9_]+$'
     or p_access_mode not in ('read','write')
     or p_arguments is null or jsonb_typeof(p_arguments) <> 'object'
     or p_idempotency_key is null or char_length(p_idempotency_key) not between 16 and 180
     or p_idempotency_key !~ '^[A-Za-z0-9:_-]+$'
     or p_expires_at is null or p_expires_at <= v_now or p_expires_at > v_now + interval '5 minutes'
  then
    return jsonb_build_object('ok',false,'error','forge_action_invalid');
  end if;

  if not exists(
    select 1
    from private.ordax_forge_mcp_bindings b
    join private.ordax_forge_instances i on i.instance_id=b.instance_id
    where b.owner_user_id=p_owner_user_id and b.client_id=p_client_id
      and b.instance_id=p_instance_id and b.revoked_at is null
      and i.owner_user_id=p_owner_user_id and i.revoked_at is null
  ) then
    return jsonb_build_object('ok',false,'error','forge_instance_binding_required');
  end if;

  select * into v_existing
  from private.ordax_forge_action_requests
  where owner_user_id=p_owner_user_id
    and client_id=p_client_id
    and idempotency_key=p_idempotency_key
  for update;

  if found then
    if v_existing.instance_id<>p_instance_id
       or v_existing.tool_name<>p_tool_name
       or v_existing.access_mode<>p_access_mode
       or v_existing.arguments<>p_arguments
    then
      return jsonb_build_object('ok',false,'error','idempotency_conflict');
    end if;
    return jsonb_build_object(
      'ok',true,'replayed',true,'request_id',v_existing.request_id,
      'effect_id',v_existing.effect_id,'status',v_existing.status
    );
  end if;

  insert into private.ordax_forge_action_requests(
    request_id,effect_id,owner_user_id,client_id,instance_id,tool_name,
    access_mode,arguments,idempotency_key,status,expires_at,created_at
  ) values(
    v_request_id,v_effect_id,p_owner_user_id,p_client_id,p_instance_id,p_tool_name,
    p_access_mode,p_arguments,p_idempotency_key,'queued',p_expires_at,v_now
  );

  return jsonb_build_object(
    'ok',true,'replayed',false,'request_id',v_request_id,
    'effect_id',v_effect_id,'status','queued'
  );
end;
$$;

create or replace function public.ordax_claim_forge_action_v1(
  p_owner_user_id uuid,
  p_instance_id uuid,
  p_agent_instance_id uuid,
  p_boot_id text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_job private.ordax_forge_action_requests%rowtype;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_attempt uuid := gen_random_uuid();
  v_lease uuid := gen_random_uuid();
begin
  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
     or p_instance_id is null or p_agent_instance_id is null
     or p_boot_id is null or char_length(p_boot_id) not between 1 and 160
     or not exists(
       select 1 from private.ordax_forge_instances
       where instance_id=p_instance_id and owner_user_id=p_owner_user_id
         and revoked_at is null
     )
  then
    return jsonb_build_object('ok',false,'error','forge_instance_unauthorized');
  end if;

  update private.ordax_forge_action_requests
  set status='expired',finished_at=v_now,error_code='action_expired'
  where instance_id=p_instance_id and status='queued' and expires_at<=v_now;

  update private.ordax_forge_action_requests
  set status='queued',attempt_id=null,lease_id=null,agent_instance_id=null,
      boot_id=null,lease_expires_at=null
  where instance_id=p_instance_id and status='leased'
    and lease_expires_at<=v_now and expires_at>v_now;

  update private.ordax_forge_action_requests
  set status='failed',finished_at=v_now,error_code='execution_outcome_unconfirmed'
  where instance_id=p_instance_id and status='running' and lease_expires_at<=v_now;

  select * into v_job
  from private.ordax_forge_action_requests
  where instance_id=p_instance_id and owner_user_id=p_owner_user_id
    and status='queued' and expires_at>v_now
  order by created_at
  for update skip locked
  limit 1;

  if not found then
    return jsonb_build_object('ok',true,'job',null);
  end if;

  update private.ordax_forge_action_requests
  set status='leased',attempt_id=v_attempt,lease_id=v_lease,
      agent_instance_id=p_agent_instance_id,boot_id=p_boot_id,
      lease_expires_at=least(v_job.expires_at,v_now+interval '30 seconds')
  where request_id=v_job.request_id;

  return jsonb_build_object('ok',true,'job',jsonb_build_object(
    'request_id',v_job.request_id,'effect_id',v_job.effect_id,
    'tool_name',v_job.tool_name,'access_mode',v_job.access_mode,
    'arguments',v_job.arguments,'attempt_id',v_attempt,'lease_id',v_lease,
    'lease_expires_at',least(v_job.expires_at,v_now+interval '30 seconds')
  ));
end;
$$;

create or replace function public.ordax_start_forge_action_v1(
  p_owner_user_id uuid,
  p_instance_id uuid,
  p_request_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_agent_instance_id uuid,
  p_boot_id text
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_updated integer;
begin
  update private.ordax_forge_action_requests
  set status='running',started_at=coalesce(started_at,v_now)
  where request_id=p_request_id and instance_id=p_instance_id
    and owner_user_id=p_owner_user_id
    and status='leased' and attempt_id=p_attempt_id and lease_id=p_lease_id
    and agent_instance_id=p_agent_instance_id and boot_id=p_boot_id
    and lease_expires_at>v_now and expires_at>v_now;
  get diagnostics v_updated=row_count;
  return v_updated=1;
end;
$$;

create or replace function public.ordax_renew_forge_action_v1(
  p_owner_user_id uuid,
  p_instance_id uuid,
  p_request_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_agent_instance_id uuid,
  p_boot_id text
)
returns timestamptz
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_until timestamptz;
begin
  update private.ordax_forge_action_requests
  set lease_expires_at=least(expires_at,v_now+interval '30 seconds')
  where request_id=p_request_id and instance_id=p_instance_id
    and owner_user_id=p_owner_user_id
    and status='running' and attempt_id=p_attempt_id and lease_id=p_lease_id
    and agent_instance_id=p_agent_instance_id and boot_id=p_boot_id
    and expires_at>v_now
  returning lease_expires_at into v_until;
  return v_until;
end;
$$;

create or replace function public.ordax_report_forge_action_v1(
  p_owner_user_id uuid,
  p_instance_id uuid,
  p_request_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_agent_instance_id uuid,
  p_boot_id text,
  p_succeeded boolean,
  p_result jsonb,
  p_error_code text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_row private.ordax_forge_action_requests%rowtype;
begin
  select * into v_row
  from private.ordax_forge_action_requests
  where request_id=p_request_id and instance_id=p_instance_id
    and owner_user_id=p_owner_user_id
  for update;

  if not found
     or v_row.status<>'running'
     or v_row.attempt_id<>p_attempt_id or v_row.lease_id<>p_lease_id
     or v_row.agent_instance_id<>p_agent_instance_id or v_row.boot_id<>p_boot_id
  then
    return jsonb_build_object('ok',false,'error','forge_action_receipt_rejected');
  end if;

  update private.ordax_forge_action_requests
  set status=case when p_succeeded then 'succeeded' else 'failed' end,
      result=p_result,
      error_code=case when p_succeeded then null else coalesce(nullif(p_error_code,''),'forge_action_failed') end,
      finished_at=v_now,
      lease_expires_at=null
  where request_id=p_request_id;

  return jsonb_build_object('ok',true,'request_id',p_request_id,
    'status',case when p_succeeded then 'succeeded' else 'failed' end);
end;
$$;

create or replace function public.ordax_get_forge_action_v1(
  p_owner_user_id uuid,
  p_client_id text,
  p_request_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_row private.ordax_forge_action_requests%rowtype;
  v_now timestamptz := pg_catalog.clock_timestamp();
begin
  if not private.ordax_forge_oauth_client_authorized_v1(p_owner_user_id,p_client_id) then
    return jsonb_build_object('ok',false,'error','forge_mcp_authorization_required');
  end if;

  select * into v_row
  from private.ordax_forge_action_requests
  where request_id=p_request_id and owner_user_id=p_owner_user_id and client_id=p_client_id
  for update;

  if not found then
    return jsonb_build_object('ok',false,'error','forge_action_not_found');
  end if;

  if v_row.status='queued' and v_row.expires_at<=v_now then
    update private.ordax_forge_action_requests
      set status='expired',finished_at=v_now,error_code='action_expired'
      where request_id=p_request_id;
    v_row.status:='expired';v_row.finished_at:=v_now;v_row.error_code:='action_expired';
  elsif v_row.status='leased' and v_row.lease_expires_at<=v_now then
    if v_row.expires_at<=v_now then
      update private.ordax_forge_action_requests
        set status='expired',finished_at=v_now,error_code='action_expired'
        where request_id=p_request_id;
      v_row.status:='expired';v_row.finished_at:=v_now;v_row.error_code:='action_expired';
    else
      update private.ordax_forge_action_requests
        set status='queued',attempt_id=null,lease_id=null,agent_instance_id=null,
            boot_id=null,lease_expires_at=null
        where request_id=p_request_id;
      v_row.status:='queued';
    end if;
  elsif v_row.status='running' and v_row.lease_expires_at<=v_now then
    update private.ordax_forge_action_requests
      set status='failed',finished_at=v_now,error_code='execution_outcome_unconfirmed'
      where request_id=p_request_id;
    v_row.status:='failed';v_row.finished_at:=v_now;v_row.error_code:='execution_outcome_unconfirmed';
  end if;

  return jsonb_build_object(
    'ok',true,'request_id',v_row.request_id,'effect_id',v_row.effect_id,
    'status',v_row.status,'result',v_row.result,'error_code',v_row.error_code,
    'created_at',v_row.created_at,'started_at',v_row.started_at,'finished_at',v_row.finished_at
  );
end;
$$;

revoke all on function public.ordax_register_forge_instance_v1(uuid,uuid,text,text,jsonb,text)
  from public,anon,authenticated,service_role;
revoke all on function public.ordax_update_forge_presence_v1(uuid,uuid,boolean,text,jsonb,text)
  from public,anon,authenticated,service_role;
revoke all on function public.ordax_resolve_forge_mcp_instance_v1(uuid,text)
  from public,anon,authenticated,service_role;
revoke all on function public.ordax_enqueue_forge_action_v1(uuid,text,uuid,text,text,jsonb,text,timestamptz)
  from public,anon,authenticated,service_role;
revoke all on function public.ordax_claim_forge_action_v1(uuid,uuid,uuid,text)
  from public,anon,authenticated,service_role;
revoke all on function public.ordax_start_forge_action_v1(uuid,uuid,uuid,uuid,uuid,uuid,text)
  from public,anon,authenticated,service_role;
revoke all on function public.ordax_renew_forge_action_v1(uuid,uuid,uuid,uuid,uuid,uuid,text)
  from public,anon,authenticated,service_role;
revoke all on function public.ordax_report_forge_action_v1(uuid,uuid,uuid,uuid,uuid,uuid,text,boolean,jsonb,text)
  from public,anon,authenticated,service_role;
revoke all on function public.ordax_get_forge_action_v1(uuid,text,uuid)
  from public,anon,authenticated,service_role;

grant execute on function public.ordax_register_forge_instance_v1(uuid,uuid,text,text,jsonb,text)
  to ordax_edge_runtime,ordax_edge_executor;
grant execute on function public.ordax_update_forge_presence_v1(uuid,uuid,boolean,text,jsonb,text)
  to ordax_edge_runtime,ordax_edge_executor;
grant execute on function public.ordax_resolve_forge_mcp_instance_v1(uuid,text)
  to ordax_edge_runtime,ordax_edge_executor;
grant execute on function public.ordax_enqueue_forge_action_v1(uuid,text,uuid,text,text,jsonb,text,timestamptz)
  to ordax_edge_runtime,ordax_edge_executor;
grant execute on function public.ordax_claim_forge_action_v1(uuid,uuid,uuid,text)
  to ordax_edge_runtime,ordax_edge_executor;
grant execute on function public.ordax_start_forge_action_v1(uuid,uuid,uuid,uuid,uuid,uuid,text)
  to ordax_edge_runtime,ordax_edge_executor;
grant execute on function public.ordax_renew_forge_action_v1(uuid,uuid,uuid,uuid,uuid,uuid,text)
  to ordax_edge_runtime,ordax_edge_executor;
grant execute on function public.ordax_report_forge_action_v1(uuid,uuid,uuid,uuid,uuid,uuid,text,boolean,jsonb,text)
  to ordax_edge_runtime,ordax_edge_executor;
grant execute on function public.ordax_get_forge_action_v1(uuid,text,uuid)
  to ordax_edge_runtime,ordax_edge_executor;

commit;
