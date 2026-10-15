-- Device-attested Central session handshake.
--
-- Goal: bind one ChatGPT Product-MCP session marker to exactly one already
-- authorized ORDAX device without trusting model arguments and without giving
-- the public edge role generic central-conversation bind/revoke authority.
--
-- Flow:
--   signed Product-MCP OAuth client opens a short-lived challenge
--   -> PostgreSQL selects the only eligible device (no model-selected device)
--   -> that exact device polls using its existing Product device credential
--   -> device confirms the challenge
--   -> SECURITY DEFINER writes/renews the durable Central binding
--   -> MCP resolves the session marker to the exact device on every operation.
--
-- The generic ordax_bind_central_conversation_v1 remains restricted to the
-- dedicated central attestor role. This migration exposes only constrained
-- challenge RPCs whose final confirmation requires the exact device token hash.

begin;

do $preflight$
begin
  if to_regclass('private.ordax_central_conversation_bindings') is null
     or to_regclass('private.ordax_product_device_credentials') is null
     or to_regclass('private.ordax_central_device_session_challenges') is not null
     or to_regprocedure('private.ordax_central_device_grant_eligible_v1(uuid,text,uuid)') is not null
     or to_regprocedure('public.ordax_open_central_device_session_v1(uuid,text,text)') is not null
     or to_regprocedure('public.ordax_poll_central_device_session_v1(uuid,text)') is not null
     or to_regprocedure('public.ordax_confirm_central_device_session_v1(uuid,text,uuid)') is not null
     or to_regprocedure('public.ordax_resolve_central_device_session_v1(uuid,text,text)') is not null
     or not exists(select 1 from pg_roles where rolname='ordax_edge_executor')
     or to_regprocedure('private.ordax_trusted_actor_auth_eligible_v1(uuid)') is null
  then raise exception 'central_device_session_preflight_failed'; end if;
end;
$preflight$;

create table private.ordax_central_device_session_challenges (
  challenge_id uuid primary key,
  owner_user_id uuid not null,
  client_id text not null,
  device_id uuid not null
    references public.ordax_product_devices(device_id) on delete cascade,
  session_sha256 text not null,
  state text not null default 'pending'
    check(state in ('pending','confirmed','expired')),
  binding_request_id uuid,
  expires_at timestamptz not null,
  binding_expires_at timestamptz not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  confirmed_at timestamptz,
  constraint central_device_session_client_shape check (
    char_length(client_id) between 8 and 160
    and client_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
  ),
  constraint central_device_session_hash_shape check (
    session_sha256 ~ '^[0-9a-f]{64}$'
  ),
  constraint central_device_session_expiry_shape check (
    binding_expires_at > expires_at
  ),
  constraint central_device_session_confirmation_shape check (
    (state='pending' and confirmed_at is null and binding_request_id is null)
    or (state='expired' and confirmed_at is null and binding_request_id is null)
    or (state='confirmed' and confirmed_at is not null and binding_request_id is not null)
  )
);

create unique index central_device_session_pending_unique
  on private.ordax_central_device_session_challenges(
    owner_user_id,client_id,session_sha256
  ) where state='pending';
create index central_device_session_device_pending
  on private.ordax_central_device_session_challenges(device_id,created_at)
  where state='pending';
create index central_device_session_expiry
  on private.ordax_central_device_session_challenges(expires_at)
  where state='pending';

alter table private.ordax_central_device_session_challenges enable row level security;
alter table private.ordax_central_device_session_challenges force row level security;
revoke all on table private.ordax_central_device_session_challenges
  from public,anon,authenticated,service_role,ordax_edge_executor;

-- A Central session binding grants nothing by itself. It only identifies one
-- exact already-authorized device. Every later action must still resolve its
-- own current Product capability grant. Therefore any active exact-client
-- device grant is enough to establish the binding.
create function private.ordax_central_device_grant_eligible_v1(
  p_owner_user_id uuid,p_client_id text,p_device_id uuid
)
returns boolean language sql volatile security definer set search_path = ''
as $$
 select p_owner_user_id is not null and p_device_id is not null
   and p_client_id is not null
   and private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
   and exists (
    select 1
      from public.ordax_remote_capability_grants g
      join public.ordax_product_devices d
        on d.device_id=g.device_id
       and d.owner_user_id=g.owner_user_id
     where g.owner_user_id=p_owner_user_id
       and g.client_kind='product-mcp'
       and g.client_id=p_client_id
       and g.device_id=p_device_id
       and g.scope_kind='device'
       and g.space_id is null
       and g.project_id is null
       and g.state='active'
       and d.state='active'
       and (g.valid_until is null or g.valid_until>pg_catalog.clock_timestamp())
   )
$$;

-- Opens a challenge only when PostgreSQL can resolve ONE exact eligible device
-- for this owner + signed OAuth client. There is intentionally no device_id
-- argument, so the model cannot select authority by supplying a UUID.
create function public.ordax_open_central_device_session_v1(
  p_owner_user_id uuid,p_client_id text,p_session_sha256 text
)
returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_now timestamptz:=pg_catalog.clock_timestamp();
  v_devices uuid[];
  v_device_id uuid;
  v_existing private.ordax_central_conversation_bindings%rowtype;
  v_challenge private.ordax_central_device_session_challenges%rowtype;
  v_challenge_id uuid;
  v_expires timestamptz;
  v_binding_expires timestamptz;
begin
 if p_owner_user_id is null
    or p_client_id is null or char_length(p_client_id) not between 8 and 160
    or p_client_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
    or p_session_sha256 is null or p_session_sha256 !~ '^[0-9a-f]{64}$'
    or not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
 then return jsonb_build_object('ok',false,'error','central_session_invalid'); end if;

 perform pg_catalog.pg_advisory_xact_lock(
   pg_catalog.hashtext(p_owner_user_id::text||':'||p_client_id||':'||p_session_sha256)
 );

 select pg_catalog.array_agg(x.device_id order by x.device_id)
   into v_devices
   from (
     select distinct g.device_id
       from public.ordax_remote_capability_grants g
       join public.ordax_product_devices d
         on d.device_id=g.device_id and d.owner_user_id=g.owner_user_id
      where g.owner_user_id=p_owner_user_id
        and g.client_kind='product-mcp'
        and g.client_id=p_client_id
        and g.scope_kind='device'
        and g.space_id is null and g.project_id is null
        and g.state='active' and d.state='active'
        and (g.valid_until is null or g.valid_until>v_now)
   ) x;

 if v_devices is null or pg_catalog.cardinality(v_devices)=0 then
   return jsonb_build_object('ok',false,'error','central_device_target_missing');
 end if;
 if pg_catalog.cardinality(v_devices)<>1 then
   return jsonb_build_object('ok',false,'error','central_device_target_ambiguous');
 end if;
 v_device_id:=v_devices[1];

 select b.* into v_existing
   from private.ordax_central_conversation_bindings b
  where b.owner_user_id=p_owner_user_id
    and b.client_id=p_client_id
    and b.session_sha256=p_session_sha256
  limit 1;
 if found then
   if v_existing.device_id<>v_device_id
      or v_existing.space_id is not null or v_existing.project_id is not null then
     return jsonb_build_object('ok',false,'error','central_session_target_mismatch');
   end if;
   if v_existing.state='revoked' then
     return jsonb_build_object('ok',false,'error','central_session_revoked');
   end if;
   if v_existing.expires_at>v_now then
     return jsonb_build_object(
       'ok',true,'status','bound','device_id',v_device_id,
       'request_id',v_existing.request_id,'expires_at',v_existing.expires_at
     );
   end if;
 end if;

 update private.ordax_central_device_session_challenges
    set state='expired'
  where owner_user_id=p_owner_user_id and client_id=p_client_id
    and session_sha256=p_session_sha256 and state='pending' and expires_at<=v_now;

 select c.* into v_challenge
   from private.ordax_central_device_session_challenges c
  where c.owner_user_id=p_owner_user_id and c.client_id=p_client_id
    and c.session_sha256=p_session_sha256 and c.state='pending'
    and c.expires_at>v_now
  limit 1;
 if found then
   if v_challenge.device_id<>v_device_id then
     return jsonb_build_object('ok',false,'error','central_session_target_mismatch');
   end if;
   return jsonb_build_object(
     'ok',true,'status','pending','device_id',v_device_id,
     'challenge_id',v_challenge.challenge_id,'expires_at',v_challenge.expires_at
   );
 end if;

 v_challenge_id:=extensions.gen_random_uuid();
 v_expires:=v_now+interval '2 minutes';
 v_binding_expires:=v_now+interval '30 minutes';
 insert into private.ordax_central_device_session_challenges(
   challenge_id,owner_user_id,client_id,device_id,session_sha256,
   state,expires_at,binding_expires_at
 ) values (
   v_challenge_id,p_owner_user_id,p_client_id,v_device_id,p_session_sha256,
   'pending',v_expires,v_binding_expires
 );
 return jsonb_build_object(
   'ok',true,'status','pending','device_id',v_device_id,
   'challenge_id',v_challenge_id,'expires_at',v_expires
 );
end;
$$;

-- Device-side poll. The raw token is never stored; caller sends SHA-256 and
-- PostgreSQL proves it belongs to the exact active Product device.
create function public.ordax_poll_central_device_session_v1(
  p_device_id uuid,p_token_sha256 text
)
returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_now timestamptz:=pg_catalog.clock_timestamp();
  v_challenge private.ordax_central_device_session_challenges%rowtype;
begin
 if p_device_id is null or p_token_sha256 is null
    or p_token_sha256 !~ '^[0-9a-f]{64}$'
    or not exists(
      select 1
        from private.ordax_product_device_credentials c
        join public.ordax_product_devices d on d.device_id=c.device_id
       where c.device_id=p_device_id and c.token_sha256=p_token_sha256
         and c.revoked_at is null and d.state='active'
    ) then
   return jsonb_build_object('ok',false,'error','product_device_unauthorized');
 end if;

 update private.ordax_central_device_session_challenges
    set state='expired'
  where device_id=p_device_id and state='pending' and expires_at<=v_now;

 select c.* into v_challenge
   from private.ordax_central_device_session_challenges c
  where c.device_id=p_device_id and c.state='pending' and c.expires_at>v_now
  order by c.created_at asc
  limit 1;
 if not found then
   return jsonb_build_object('ok',true,'pending',false);
 end if;
 return jsonb_build_object(
   'ok',true,'pending',true,
   'challenge_id',v_challenge.challenge_id,
   'expires_at',v_challenge.expires_at
 );
end;
$$;

-- Final binding can only be produced by possession of the exact Product device
-- credential for the exact device selected by PostgreSQL when the challenge
-- was opened. Generic Central bind/revoke authority is not used or widened.
create function public.ordax_confirm_central_device_session_v1(
  p_device_id uuid,p_token_sha256 text,p_challenge_id uuid
)
returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_now timestamptz:=pg_catalog.clock_timestamp();
  v_challenge private.ordax_central_device_session_challenges%rowtype;
  v_existing private.ordax_central_conversation_bindings%rowtype;
  v_binding_request_id uuid;
  v_conversation_id text;
begin
 if p_device_id is null or p_challenge_id is null
    or p_token_sha256 is null or p_token_sha256 !~ '^[0-9a-f]{64}$'
    or not exists(
      select 1
        from private.ordax_product_device_credentials c
        join public.ordax_product_devices d on d.device_id=c.device_id
       where c.device_id=p_device_id and c.token_sha256=p_token_sha256
         and c.revoked_at is null and d.state='active'
    ) then
   return jsonb_build_object('ok',false,'error','product_device_unauthorized');
 end if;

 perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext(p_challenge_id::text));
 select c.* into v_challenge
   from private.ordax_central_device_session_challenges c
  where c.challenge_id=p_challenge_id
  for update;
 if not found or v_challenge.device_id<>p_device_id then
   return jsonb_build_object('ok',false,'error','central_session_challenge_invalid');
 end if;
 if v_challenge.state='confirmed' then
   return jsonb_build_object(
     'ok',true,'status','bound','request_id',v_challenge.binding_request_id
   );
 end if;
 if v_challenge.state<>'pending' or v_challenge.expires_at<=v_now then
   if v_challenge.state='pending' then
     update private.ordax_central_device_session_challenges
        set state='expired' where challenge_id=p_challenge_id;
   end if;
   return jsonb_build_object('ok',false,'error','central_session_challenge_expired');
 end if;
 if not private.ordax_central_device_grant_eligible_v1(
   v_challenge.owner_user_id,v_challenge.client_id,v_challenge.device_id
 ) then
   return jsonb_build_object('ok',false,'error','central_device_grant_revoked');
 end if;

 select b.* into v_existing
   from private.ordax_central_conversation_bindings b
  where b.owner_user_id=v_challenge.owner_user_id
    and b.client_id=v_challenge.client_id
    and b.session_sha256=v_challenge.session_sha256
  limit 1
  for update;
 if found then
   if v_existing.device_id<>v_challenge.device_id
      or v_existing.space_id is not null or v_existing.project_id is not null then
     return jsonb_build_object('ok',false,'error','central_session_target_mismatch');
   end if;
   if v_existing.state='revoked' then
     return jsonb_build_object('ok',false,'error','central_session_revoked');
   end if;
   update private.ordax_central_conversation_bindings
      set expires_at=v_challenge.binding_expires_at
    where request_id=v_existing.request_id;
   v_binding_request_id:=v_existing.request_id;
 else
   v_binding_request_id:=v_challenge.challenge_id;
   v_conversation_id:='ordax-'||pg_catalog.replace(v_challenge.challenge_id::text,'-','');
   insert into private.ordax_central_conversation_bindings(
     request_id,owner_user_id,client_id,device_id,space_id,project_id,
     conversation_id,session_sha256,state,expires_at
   ) values (
     v_binding_request_id,v_challenge.owner_user_id,v_challenge.client_id,
     v_challenge.device_id,null,null,v_conversation_id,
     v_challenge.session_sha256,'active',v_challenge.binding_expires_at
   );
 end if;

 update private.ordax_central_device_session_challenges
    set state='confirmed',confirmed_at=v_now,binding_request_id=v_binding_request_id
  where challenge_id=v_challenge.challenge_id;
 return jsonb_build_object(
   'ok',true,'status','bound','device_id',v_challenge.device_id,
   'request_id',v_binding_request_id,'expires_at',v_challenge.binding_expires_at
 );
end;
$$;

-- Resolve by OAuth owner + exact client + hashed provider session marker. The
-- marker alone is not authority: only a device-confirmed durable binding plus
-- a CURRENT device grant can resolve a target.
create function public.ordax_resolve_central_device_session_v1(
  p_owner_user_id uuid,p_client_id text,p_session_sha256 text
)
returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_now timestamptz:=pg_catalog.clock_timestamp();
  v_binding private.ordax_central_conversation_bindings%rowtype;
begin
 if p_owner_user_id is null
    or p_client_id is null or char_length(p_client_id) not between 8 and 160
    or p_client_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]+$'
    or p_session_sha256 is null or p_session_sha256 !~ '^[0-9a-f]{64}$'
    or not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
 then return jsonb_build_object('ok',false,'error','central_session_invalid'); end if;

 select b.* into v_binding
   from private.ordax_central_conversation_bindings b
  where b.owner_user_id=p_owner_user_id and b.client_id=p_client_id
    and b.session_sha256=p_session_sha256
    and b.space_id is null and b.project_id is null
    and b.state='active' and b.expires_at>v_now
  limit 1;
 if not found then
   return jsonb_build_object('ok',false,'error','central_session_unbound');
 end if;
 if not private.ordax_central_device_grant_eligible_v1(
   p_owner_user_id,p_client_id,v_binding.device_id
 ) then
   return jsonb_build_object('ok',false,'error','central_device_grant_revoked');
 end if;
 return jsonb_build_object(
   'ok',true,'device_id',v_binding.device_id,
   'request_id',v_binding.request_id,'expires_at',v_binding.expires_at
 );
end;
$$;

revoke all on function private.ordax_central_device_grant_eligible_v1(uuid,text,uuid)
  from public,anon,authenticated,service_role,ordax_edge_executor;
revoke all on function public.ordax_open_central_device_session_v1(uuid,text,text)
  from public,anon,authenticated,service_role;
revoke all on function public.ordax_poll_central_device_session_v1(uuid,text)
  from public,anon,authenticated,service_role;
revoke all on function public.ordax_confirm_central_device_session_v1(uuid,text,uuid)
  from public,anon,authenticated,service_role;
revoke all on function public.ordax_resolve_central_device_session_v1(uuid,text,text)
  from public,anon,authenticated,service_role;

grant execute on function public.ordax_open_central_device_session_v1(uuid,text,text)
  to ordax_edge_executor;
grant execute on function public.ordax_poll_central_device_session_v1(uuid,text)
  to ordax_edge_executor;
grant execute on function public.ordax_confirm_central_device_session_v1(uuid,text,uuid)
  to ordax_edge_executor;
grant execute on function public.ordax_resolve_central_device_session_v1(uuid,text,text)
  to ordax_edge_executor;

-- The constrained handshake must not weaken the original P0 role boundary.
do $postflight$
declare
  v_bind regprocedure:=to_regprocedure(
    'public.ordax_bind_central_conversation_v1(uuid,text,uuid,uuid,uuid,uuid,text,text,timestamptz)');
  v_revoke regprocedure:=to_regprocedure(
    'public.ordax_revoke_central_conversation_v1(uuid,text,uuid)');
  v_confirm regprocedure:=to_regprocedure(
    'public.ordax_confirm_central_device_session_v1(uuid,text,uuid)');
begin
 if has_function_privilege('ordax_edge_executor',v_bind,'EXECUTE')
    or has_function_privilege('ordax_edge_executor',v_revoke,'EXECUTE')
    or not has_function_privilege('ordax_edge_executor',v_confirm,'EXECUTE')
 then raise exception 'central_device_session_role_boundary_failed'; end if;
end;
$postflight$;

commit;
