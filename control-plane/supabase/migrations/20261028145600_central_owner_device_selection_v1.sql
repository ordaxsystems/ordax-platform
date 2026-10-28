-- Owner selection migration: extension of
-- the existing Central device-attested challenge; no parallel authority or grant.
-- REVIEW GATES: PGlite tests, signed Owner E2E, Runtime
-- device confirmation, security review and controlled rollout are required before FLAG enablement.
begin;

do $preflight$
begin
  if to_regclass('private.ordax_central_device_session_challenges') is null
    or to_regprocedure('private.ordax_central_device_grant_eligible_v1(uuid,text,uuid)') is null
    or to_regprocedure('private.ordax_product_presence_online_v1(boolean,timestamptz,timestamptz)') is null
    or to_regprocedure('public.ordax_open_central_device_session_v1(uuid,text,text)') is null
    or to_regprocedure('public.ordax_confirm_central_device_session_v1(uuid,text,uuid)') is null
    or to_regprocedure('public.ordax_owner_select_central_device_v1(uuid,text,uuid,uuid)') is not null
    or to_regprocedure('public.ordax_owner_list_central_selections_v1(uuid,text)') is not null
    or not exists(select 1 from pg_roles where rolname='ordax_edge_executor')
  then raise exception 'central_owner_selection_preflight_failed'; end if;
end; $preflight$;

-- Reuse the SAME table, row uniqueness, expiry and device credential lifecycle.
-- Waiting has a NULL device, cannot be polled by the Runtime and is not a grant.
alter table private.ordax_central_device_session_challenges
  alter column device_id drop not null;
alter table private.ordax_central_device_session_challenges
  drop constraint ordax_central_device_session_challenges_state_check,
  drop constraint central_device_session_confirmation_shape;
alter table private.ordax_central_device_session_challenges
  add constraint ordax_central_device_session_challenges_state_check
    check (state in ('awaiting_owner','pending','confirmed','expired')),
  add constraint central_device_session_confirmation_shape check (
    (state='awaiting_owner' and device_id is null
      and confirmed_at is null and binding_request_id is null)
    or (state='pending' and device_id is not null
      and confirmed_at is null and binding_request_id is null)
    or (state='expired' and confirmed_at is null and binding_request_id is null)
    or (state='confirmed' and device_id is not null
      and confirmed_at is not null and binding_request_id is not null)
  );
drop index private.central_device_session_pending_unique;
create unique index central_device_session_pending_unique
  on private.ordax_central_device_session_challenges(
    owner_user_id,client_id,session_sha256
  ) where state in ('awaiting_owner','pending');

-- The existing Device poll/confirm functions remain the ONLY way to create
-- a binding. They see pending only after Owner explicitly chooses a device.
-- Rebase the current availability/digest-aware OPEN RPC from
-- 20261022154600_central_session_runtime_heartbeat_preflight_v1.sql.
create or replace function public.ordax_open_central_device_session_v1(
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

 -- Owner+client queue is serialized with the Owner selector. A second
 -- session opening while a choice is being made must not evade ambiguity.
 perform pg_catalog.pg_advisory_xact_lock(
   pg_catalog.hashtext('central-owner-queue:'||p_owner_user_id::text||':'||p_client_id)
 );
 v_now:=pg_catalog.clock_timestamp();
 perform pg_catalog.pg_advisory_xact_lock(
   pg_catalog.hashtext(p_owner_user_id::text||':'||p_client_id||':'||p_session_sha256)
 );

 -- Single authority for active, non-discovery grants. Opening a session
 -- and later resolving/reconfirming it MUST enforce the same predicate.
 -- Never duplicate grant filters here: a future grant type must not drift.
 select pg_catalog.array_agg(d.device_id order by d.device_id)
   into v_devices
   from public.ordax_product_devices d
  where d.owner_user_id=p_owner_user_id
    and d.state='active'
    and private.ordax_central_device_grant_eligible_v1(
      p_owner_user_id,p_client_id,d.device_id
    );

 if v_devices is null or pg_catalog.cardinality(v_devices)=0 then
   return jsonb_build_object('ok',false,'error','central_device_target_missing');
 end if;

 -- Multi-device choice must originate from the signed Owner route, never from
 -- MCP action arguments, online presence, or the first grant in the list.
 if pg_catalog.cardinality(v_devices)<>1 then
   select b.* into v_existing
     from private.ordax_central_conversation_bindings b
    where b.owner_user_id=p_owner_user_id and b.client_id=p_client_id
      and b.session_sha256=p_session_sha256
    limit 1;
   if found then
     if v_existing.state='revoked' then
       return jsonb_build_object('ok',false,'error','central_session_revoked');
     end if;
     if v_existing.space_id is not null or v_existing.project_id is not null then
       return jsonb_build_object('ok',false,'error','central_session_target_mismatch');
     end if;
     if v_existing.state='active' and v_existing.expires_at>v_now then
       if not private.ordax_central_device_grant_eligible_v1(
         p_owner_user_id,p_client_id,v_existing.device_id) then
         return jsonb_build_object('ok',false,'error','central_device_grant_revoked');
       end if;
       -- An already device-confirmed unexpired binding never changes target
       -- merely because the Owner granted the same client a second device.
       return jsonb_build_object('ok',true,'status','bound',
         'device_id',v_existing.device_id,
         'request_id',v_existing.request_id,'expires_at',v_existing.expires_at);
     end if;
   end if;
   update private.ordax_central_device_session_challenges
      set state='expired'
    where owner_user_id=p_owner_user_id and client_id=p_client_id
      and session_sha256=p_session_sha256
      and state in ('awaiting_owner','pending') and expires_at<=v_now;
   select c.* into v_challenge
     from private.ordax_central_device_session_challenges c
    where c.owner_user_id=p_owner_user_id and c.client_id=p_client_id
      and c.session_sha256=p_session_sha256
      and c.state in ('awaiting_owner','pending') and c.expires_at>v_now
    limit 1 for update;
   if found then
     if v_challenge.state='awaiting_owner' then
       return jsonb_build_object('ok',true,'status','awaiting_owner',
         'challenge_id',v_challenge.challenge_id,'expires_at',v_challenge.expires_at);
     end if;
     if not private.ordax_central_device_grant_eligible_v1(
       p_owner_user_id,p_client_id,v_challenge.device_id) then
       return jsonb_build_object('ok',false,'error','central_device_grant_revoked');
     end if;
     return jsonb_build_object('ok',true,'status','pending',
       'device_id',v_challenge.device_id,
       'challenge_id',v_challenge.challenge_id,'expires_at',v_challenge.expires_at);
   end if;
   v_challenge_id:=extensions.gen_random_uuid();
   -- A waiting ticket grants NOTHING and has no device id.
   insert into private.ordax_central_device_session_challenges(
     challenge_id,owner_user_id,client_id,device_id,session_sha256,
     state,expires_at,binding_expires_at
   ) values (
     v_challenge_id,p_owner_user_id,p_client_id,null,p_session_sha256,
     'awaiting_owner',v_now+interval '5 minutes',v_now+interval '30 minutes'
   );
   return jsonb_build_object('ok',true,'status','awaiting_owner',
     'challenge_id',v_challenge_id,'expires_at',v_now+interval '5 minutes');
 end if;
 v_device_id:=v_devices[1];

 -- Presence is availability only, never authority or a target selector.
 -- Keep ambiguity/revocation decisions independent of which PC is online.

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
 end if;

 if not exists (
   select 1 from public.ordax_device_presence p
   where p.device_id=v_device_id
     and private.ordax_product_presence_online_v1(p.online,p.last_seen_at,v_now)
 ) then
   return jsonb_build_object('ok',false,'error','central_device_offline');
 end if;

 -- Discovery-only OrdaX OS presence has NULL capability_digest. An
 -- action-capable Runtime supplies the canonical SHA-256 action-list digest.
 -- This is a readiness preflight, NOT session attestation or a grant.
 if not exists (
   select 1 from public.ordax_device_presence p
    where p.device_id=v_device_id
      and p.agent_version is not null
      and p.capability_digest ~ '^[0-9a-f]{64}$'
 ) then
   return jsonb_build_object('ok',false,'error','central_device_runtime_not_ready');
 end if;

 if v_existing.device_id is not null then
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
    and session_sha256=p_session_sha256 and state in ('awaiting_owner','pending')
    and expires_at<=v_now;

 select c.* into v_challenge
   from private.ordax_central_device_session_challenges c
  where c.owner_user_id=p_owner_user_id and c.client_id=p_client_id
    and c.session_sha256=p_session_sha256 and c.state in ('awaiting_owner','pending')
    and c.expires_at>v_now
  limit 1;
 if found then
   if v_challenge.state='awaiting_owner' then
     return jsonb_build_object('ok',true,'status','awaiting_owner',
       'challenge_id',v_challenge.challenge_id,'expires_at',v_challenge.expires_at);
   end if;
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

-- Owner route lists at most 25 unexpired WAITING choices for the explicit
-- OAuth client. It does not disclose the provider session hash or raw token.
create function public.ordax_owner_list_central_selections_v1(
  p_owner_user_id uuid,p_client_id text
) returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare v_total bigint; v_list jsonb;
begin
  if p_owner_user_id is null or p_client_id is null
    or p_client_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    or not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
  then return jsonb_build_object('ok',false,'error','owner_central_selection_invalid'); end if;
  if not exists(
    select 1 from auth.oauth_consents c
    join auth.oauth_clients client on client.id=c.client_id and client.deleted_at is null
    where c.user_id=p_owner_user_id and c.client_id=p_client_id::uuid
      and c.revoked_at is null
  ) then return jsonb_build_object('ok',false,'error','owner_central_client_not_consented'); end if;
  select count(*),coalesce(jsonb_agg(jsonb_build_object(
    'challenge_id',c.challenge_id,'created_at',c.created_at,
    'expires_at',c.expires_at
  ) order by c.created_at desc),'[]'::jsonb)
  into v_total,v_list
  from private.ordax_central_device_session_challenges c
  where c.owner_user_id=p_owner_user_id and c.client_id=p_client_id
    and c.state='awaiting_owner' and c.expires_at>pg_catalog.clock_timestamp();
  if v_total>25 then
    return jsonb_build_object('ok',false,'error','owner_central_selection_list_too_large');
  end if;
  return jsonb_build_object('ok',true,'pending_selections',v_list,
    'count',v_total,'attested',false,'dispatch_authorized',false);
end;
$$;

-- The only selector: Owner-signed actor (verified by Worker), exact consented
-- OAuth client, challenge UUID generated by a trusted MCP session opener,
-- CURRENT grant and an action-ready device. It never creates/revokes grants.
create function public.ordax_owner_select_central_device_v1(
  p_owner_user_id uuid,p_client_id text,p_challenge_id uuid,p_device_id uuid
) returns jsonb language plpgsql volatile security definer set search_path = ''
as $$
declare
  v_now timestamptz:=pg_catalog.clock_timestamp();
  v_challenge private.ordax_central_device_session_challenges%rowtype;
  v_binding private.ordax_central_conversation_bindings%rowtype;
begin
  if p_owner_user_id is null or p_challenge_id is null or p_device_id is null
    or p_client_id is null
    or p_client_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    or not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)
  then return jsonb_build_object('ok',false,'error','owner_central_selection_invalid'); end if;
  if not exists(
    select 1 from auth.oauth_consents c
    join auth.oauth_clients client on client.id=c.client_id and client.deleted_at is null
    where c.user_id=p_owner_user_id and c.client_id=p_client_id::uuid
      and c.revoked_at is null
  ) then return jsonb_build_object('ok',false,'error','owner_central_client_not_consented'); end if;

  -- Use the same queue lock as challenge opening. When two different
  -- provider sessions are waiting, no Owner screen currently proves which
  -- belongs to which conversation. Never pick an arbitrary UUID.
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext('central-owner-queue:'||p_owner_user_id::text||':'||p_client_id)
  );
  v_now:=pg_catalog.clock_timestamp();
  -- Locks serialize two browsers choosing two different PCs for one challenge.
  select c.* into v_challenge
  from private.ordax_central_device_session_challenges c
  where c.challenge_id=p_challenge_id and c.owner_user_id=p_owner_user_id
    and c.client_id=p_client_id
  for update;
  if not found then return jsonb_build_object('ok',false,'error','owner_central_selection_not_found'); end if;
  if v_challenge.state<>'awaiting_owner' or v_challenge.device_id is not null
    or v_challenge.expires_at<=v_now
  then return jsonb_build_object('ok',false,'error','owner_central_selection_not_pending'); end if;
  if (
    select pg_catalog.count(*)
      from private.ordax_central_device_session_challenges c
     where c.owner_user_id=p_owner_user_id and c.client_id=p_client_id
       and c.state='awaiting_owner' and c.expires_at>v_now
  )<>1 then
    return jsonb_build_object('ok',false,
      'error','owner_central_selection_ambiguous');
  end if;

  select b.* into v_binding from private.ordax_central_conversation_bindings b
  where b.owner_user_id=p_owner_user_id and b.client_id=p_client_id
    and b.session_sha256=v_challenge.session_sha256
  for update;
  if found and (
    v_binding.state='revoked'
    or v_binding.device_id<>p_device_id
    or v_binding.space_id is not null or v_binding.project_id is not null
  ) then return jsonb_build_object('ok',false,'error','central_session_target_mismatch'); end if;

  if not private.ordax_central_device_grant_eligible_v1(
    p_owner_user_id,p_client_id,p_device_id
  ) then return jsonb_build_object('ok',false,'error','central_device_grant_revoked'); end if;
  if not exists(
    select 1 from public.ordax_device_presence p
    where p.device_id=p_device_id
      and private.ordax_product_presence_online_v1(p.online,p.last_seen_at,v_now)
      and p.agent_version is not null and p.capability_digest ~ '^[0-9a-f]{64}$'
  ) then return jsonb_build_object('ok',false,'error','central_device_runtime_not_ready'); end if;

  -- Fresh two-minute window starts only AFTER the Owner selects; Device
  -- credential attestation and current grant are verified on confirmation.
  update private.ordax_central_device_session_challenges
     set device_id=p_device_id,state='pending',
         expires_at=v_now+interval '2 minutes',
         binding_expires_at=v_now+interval '30 minutes'
   where challenge_id=p_challenge_id and state='awaiting_owner';
  return jsonb_build_object('ok',true,'status','pending',
    'device_id',p_device_id,'challenge_id',p_challenge_id,
    'expires_at',v_now+interval '2 minutes',
    'attested',false,'dispatch_authorized',false);
end;
$$;

revoke all on function public.ordax_open_central_device_session_v1(uuid,text,text)
  from public,anon,authenticated,service_role;
revoke all on function public.ordax_owner_list_central_selections_v1(uuid,text)
  from public,anon,authenticated,service_role;
revoke all on function public.ordax_owner_select_central_device_v1(uuid,text,uuid,uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.ordax_open_central_device_session_v1(uuid,text,text)
  to ordax_edge_executor;
grant execute on function public.ordax_owner_list_central_selections_v1(uuid,text)
  to ordax_edge_executor;
grant execute on function public.ordax_owner_select_central_device_v1(uuid,text,uuid,uuid)
  to ordax_edge_executor;
commit;
