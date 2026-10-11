-- OrdaX Product owns the ONLY mapping between Central requests, ChatGPT
-- conversations and signed MCP OAuth clients. This is not a grant/executor.
-- NO model, browser JS, OAuth request body, or legacy D1 route can insert.
-- Registration is a privileged server-only capability: the trusted Central
-- host MUST authenticate the originating request and independently attest
-- the provider conversation/session BEFORE invoking it.
begin;

do $preflight$
begin
  if to_regclass('private.ordax_central_conversation_bindings') is not null
     or to_regprocedure('public.ordax_bind_central_conversation_v1(uuid,text,uuid,uuid,uuid,uuid,text,text,timestamptz)') is not null
     or to_regprocedure('public.ordax_verify_central_conversation_v1(uuid,text,uuid,uuid,uuid,uuid,text,text)') is not null
     or to_regprocedure('public.ordax_revoke_central_conversation_v1(uuid,text,uuid)') is not null
     or not exists(select 1 from pg_roles where rolname='ordax_edge_executor')
     or to_regprocedure('private.ordax_trusted_actor_auth_eligible_v1(uuid)') is null
  then raise exception 'central_binding_preflight_failed'; end if;
end;
$preflight$;

create table private.ordax_central_conversation_bindings (
  request_id uuid primary key,
  owner_user_id uuid not null,
  client_id text not null,
  device_id uuid not null references public.ordax_product_devices(device_id) on delete cascade,
  space_id uuid,
  project_id uuid,
  conversation_id text not null,
  -- Hash of the provider correlation marker, never the marker or OAuth token.
  session_sha256 text not null,
  state text not null default 'active' check(state in ('active','revoked')),
  expires_at timestamptz not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  revoked_at timestamptz,
  constraint central_binding_scope_pair check (
    (space_id is null and project_id is null) or
    (space_id is not null and project_id is not null)
  ),
  constraint central_binding_client_shape check (
    char_length(client_id) between 8 and 160
    and client_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
  ),
  constraint central_binding_chat_shape check (
    char_length(conversation_id) between 8 and 128
    and conversation_id ~ '^[A-Za-z0-9_-]+$'
  ),
  constraint central_binding_session_hash_shape check (
    session_sha256 ~ '^[0-9a-f]{64}$'
  ),
  constraint central_binding_revocation_shape check (
    (state='active' and revoked_at is null) or
    (state='revoked' and revoked_at is not null)
  ),
  -- A session marker and a Web conversation cannot be assigned to another
  -- request under the same OAuth client, even after cancellation.
  constraint central_binding_unique_session unique(owner_user_id,client_id,session_sha256),
  constraint central_binding_unique_web_chat unique(owner_user_id,client_id,conversation_id)
);
create index central_binding_expiry_idx
  on private.ordax_central_conversation_bindings(expires_at)
  where state='active';

alter table private.ordax_central_conversation_bindings enable row level security;
alter table private.ordax_central_conversation_bindings force row level security;
revoke all on table private.ordax_central_conversation_bindings
  from public,anon,authenticated,service_role,ordax_edge_executor,ordax_edge_runtime;

-- Common source of truth for current read grants. The registration and
-- verifier both call this, so revocation/deletion/expiry take effect
-- immediately, without a cached permission or a second grant ledger.
create function private.ordax_central_read_grant_eligible_v1(
  p_owner_user_id uuid,p_client_id text,p_device_id uuid,
  p_space_id uuid,p_project_id uuid
)
returns boolean language sql volatile security definer set search_path = ''
as $$
 select exists (
  select 1 from public.ordax_remote_capability_grants g
  join public.ordax_product_devices d
    on d.device_id=g.device_id and d.owner_user_id=g.owner_user_id
  where g.owner_user_id=p_owner_user_id
    and g.client_kind='product-mcp'
    and g.client_id=p_client_id
    and g.device_id=p_device_id
    and g.space_id is not distinct from p_space_id
    and g.project_id is not distinct from p_project_id
    and g.state='active' and d.state='active'
    and (g.valid_until is null or g.valid_until>pg_catalog.clock_timestamp())
    and g.access_mode='read'
    and (
      (p_space_id is null and p_project_id is null and g.scope_kind='device'
        and g.capability = any(array[
          'computer.access_status','computer.active_window',
          'computer.processes','computer.screen_info','computer.windows'
        ]))
      or
      (p_space_id is not null and p_project_id is not null and g.scope_kind='project'
        and g.capability = any(array[
          'project.text_read','workspace.directory_list',
          'workspace.file_stat','workspace.text_read'
        ]))
    )
 )
$$;

-- This is intentionally an INTERNAL RPC only for the trusted Cloudflare
-- host. Its input must come from independently verified host facts. A
-- correlation marker, even hashed, is not a signed provider attestation.
create function public.ordax_bind_central_conversation_v1(
  p_owner_user_id uuid,p_client_id text,p_device_id uuid,
  p_space_id uuid,p_project_id uuid,p_request_id uuid,
  p_conversation_id text,p_session_sha256 text,p_expires_at timestamptz
)
returns boolean language plpgsql volatile security definer set search_path = ''
as $$
declare v_now timestamptz:=pg_catalog.clock_timestamp();
begin
 if p_owner_user_id is null or p_device_id is null or p_request_id is null
    or p_client_id is null or char_length(p_client_id) not between 8 and 160
    or p_client_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
    or p_conversation_id is null
    or char_length(p_conversation_id) not between 8 and 128
    or p_conversation_id !~ '^[A-Za-z0-9_-]+$'
    or p_session_sha256 is null or p_session_sha256 !~ '^[0-9a-f]{64}$'
    or not ((p_space_id is null and p_project_id is null)
         or (p_space_id is not null and p_project_id is not null))
    or p_expires_at is null or p_expires_at <= v_now
    or p_expires_at > v_now + interval '30 minutes'
 then return false; end if;
 if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
    or not private.ordax_central_read_grant_eligible_v1(
      p_owner_user_id,p_client_id,p_device_id,p_space_id,p_project_id)
 then return false; end if;

 insert into private.ordax_central_conversation_bindings(
   request_id,owner_user_id,client_id,device_id,space_id,project_id,
   conversation_id,session_sha256,state,expires_at
 ) values (
   p_request_id,p_owner_user_id,p_client_id,p_device_id,p_space_id,p_project_id,
   p_conversation_id,p_session_sha256,'active',p_expires_at
 ) on conflict do nothing;

 -- Exact idempotent replay is allowed; rebinding a request, a Web chat, or
 -- a provider session to another PC/client/request is never allowed.
 return exists(select 1 from private.ordax_central_conversation_bindings b
    where b.request_id=p_request_id and b.owner_user_id=p_owner_user_id
      and b.client_id=p_client_id and b.device_id=p_device_id
      and b.space_id is not distinct from p_space_id
      and b.project_id is not distinct from p_project_id
      and b.conversation_id=p_conversation_id
      and b.session_sha256=p_session_sha256
      and b.state='active' and b.expires_at>v_now
      and b.expires_at=p_expires_at);
end;
$$;

create function public.ordax_verify_central_conversation_v1(
  p_owner_user_id uuid,p_client_id text,p_device_id uuid,
  p_space_id uuid,p_project_id uuid,p_request_id uuid,
  p_conversation_id text,p_session_sha256 text
)
returns boolean language sql volatile security definer set search_path = ''
as $$
 select
   p_owner_user_id is not null and p_device_id is not null
   and p_request_id is not null
   and p_client_id is not null
   and p_session_sha256 ~ '^[0-9a-f]{64}$'
   and private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
   and exists(
    select 1 from private.ordax_central_conversation_bindings b
    where b.request_id=p_request_id
      and b.owner_user_id=p_owner_user_id
      and b.client_id=p_client_id
      and b.device_id=p_device_id
      and b.space_id is not distinct from p_space_id
      and b.project_id is not distinct from p_project_id
      and b.conversation_id=p_conversation_id
      and b.session_sha256=p_session_sha256
      and b.state='active' and b.expires_at>pg_catalog.clock_timestamp()
   )
   and private.ordax_central_read_grant_eligible_v1(
     p_owner_user_id,p_client_id,p_device_id,p_space_id,p_project_id)
$$;

create function public.ordax_revoke_central_conversation_v1(
  p_owner_user_id uuid,p_client_id text,p_request_id uuid
)
returns boolean language plpgsql volatile security definer set search_path = ''
as $$
begin
 update private.ordax_central_conversation_bindings b
 set state='revoked',revoked_at=pg_catalog.clock_timestamp()
 where b.request_id=p_request_id
   and b.owner_user_id=p_owner_user_id
   and b.client_id=p_client_id
   and b.state='active';
 return found;
end;
$$;

revoke all on function private.ordax_central_read_grant_eligible_v1(uuid,text,uuid,uuid,uuid)
  from public,anon,authenticated,service_role,ordax_edge_executor,ordax_edge_runtime;
revoke all on function public.ordax_bind_central_conversation_v1(uuid,text,uuid,uuid,uuid,uuid,text,text,timestamptz)
  from public,anon,authenticated,service_role,ordax_edge_runtime;
revoke all on function public.ordax_verify_central_conversation_v1(uuid,text,uuid,uuid,uuid,uuid,text,text)
  from public,anon,authenticated,service_role,ordax_edge_runtime;
revoke all on function public.ordax_revoke_central_conversation_v1(uuid,text,uuid)
  from public,anon,authenticated,service_role,ordax_edge_runtime;

-- Existing Cloudflare Product owner is the only caller. No direct table
-- SELECT/INSERT/UPDATE is granted, and no model-facing route is introduced.
grant execute on function public.ordax_bind_central_conversation_v1(uuid,text,uuid,uuid,uuid,uuid,text,text,timestamptz)
  to ordax_edge_executor;
grant execute on function public.ordax_verify_central_conversation_v1(uuid,text,uuid,uuid,uuid,uuid,text,text)
  to ordax_edge_executor;
grant execute on function public.ordax_revoke_central_conversation_v1(uuid,text,uuid)
  to ordax_edge_executor;

commit;
