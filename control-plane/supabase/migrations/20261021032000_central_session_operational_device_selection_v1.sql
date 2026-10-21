-- Bind a Product MCP Central session only to an operationally granted device.
-- Discovery grants are automatically created for every enrolled device, so they
-- must not make the handshake ambiguous when exactly one device has an explicit
-- remote-action grant. Two operationally granted devices remain ambiguous and
-- fail closed, as does any missing/expired grant. The model never selects a PC.
-- This migration does not mint grants or weaken device-token confirmation.
begin;

do $preflight$
begin
  if to_regprocedure('private.ordax_central_device_grant_eligible_v1(uuid,text,uuid)') is null
    or to_regprocedure('public.ordax_open_central_device_session_v1(uuid,text,text)') is null
  then raise exception 'central_operational_device_preflight_failed'; end if;
end;
$preflight$;

create or replace function private.ordax_central_device_grant_eligible_v1(
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
       -- Visibility grants are not remote-operation authority.
       and g.profile_key <> 'mcp-discovery'
       and g.capability <> 'product.target.read'
       and g.space_id is null
       and g.project_id is null
       and g.state='active'
       and d.state='active'
       and (g.valid_until is null or g.valid_until>pg_catalog.clock_timestamp())
   )
$$;

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

-- REPLACE preserves existing ACLs; assert that anonymous callers cannot mint
-- challenges and only the pre-authorized edge executor can invoke the RPC.
revoke all on function public.ordax_open_central_device_session_v1(uuid,text,text)
  from public,anon,authenticated,service_role;
grant execute on function public.ordax_open_central_device_session_v1(uuid,text,text)
  to ordax_edge_executor;

commit;
