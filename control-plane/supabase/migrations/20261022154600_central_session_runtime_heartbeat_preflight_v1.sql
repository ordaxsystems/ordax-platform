-- A discovery-only online OrdaX Native device must not cause a 24-second
-- pending loop for every Product MCP action. The existing Product presence
-- table owns the distinction: discovery sends NULL capability_digest while
-- the canonical action Runtime heartbeat sends a capabilities SHA-256.
--
-- This is a *readiness diagnostic*, not a new grant, action, heartbeat,
-- attestation method, or alternate target selector. The exact device still
-- MUST confirm the server-issued challenge with its enrolled token.
begin;

do $preflight$
begin
  if to_regprocedure('public.ordax_open_central_device_session_v1(uuid,text,text)') is null
    or to_regprocedure('private.ordax_product_presence_online_v1(boolean,timestamptz,timestamptz)') is null
    or to_regclass('public.ordax_device_presence') is null
  then raise exception 'central_runtime_heartbeat_preflight_missing'; end if;
end;
$preflight$;

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
 if pg_catalog.cardinality(v_devices)<>1 then
   return jsonb_build_object('ok',false,'error','central_device_target_ambiguous');
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

 -- Presence is discoverability, not evidence that the device can poll and
 -- confirm a Central challenge. OrdaX Native discovery deliberately reports
 -- capability_digest=NULL; the canonical action Runtime heartbeat sends its
 -- SHA-256 capabilities fingerprint. The fingerprint is only a *liveness
 -- preflight hint*, NEVER attestation/permission. Token-signed device challenge
 -- confirmation and current grants remain mandatory.
 if not exists (
   select 1 from public.ordax_device_presence p
    where p.device_id=v_device_id
      and p.agent_version is not null
      and p.capability_digest ~ '^[0-9a-f]{64}
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
 ) then
   return jsonb_build_object(
     'ok',false,'error','central_device_runtime_not_ready'
   );
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

-- Keep the existing edge-only executor boundary. Function replacement must
-- never grant authority to anon, authenticated or service_role.
revoke all on function public.ordax_open_central_device_session_v1(uuid,text,text)
  from public,anon,authenticated,service_role;
grant execute on function public.ordax_open_central_device_session_v1(uuid,text,text)
  to ordax_edge_executor;

commit;
