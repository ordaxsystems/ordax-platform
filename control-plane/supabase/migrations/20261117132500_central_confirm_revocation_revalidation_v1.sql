-- Recheck original authority on idempotent Device confirmations.
-- Applied migrations are immutable; redefine only the existing confirmation RPC.
-- An already-confirmed challenge is not an independent grant, durable binding,
-- or substitute for live OAuth consent and Product device authorization.
begin;

do $preflight$
begin
  if to_regprocedure('public.ordax_confirm_central_device_session_v1(uuid,text,uuid)') is null
     or to_regprocedure('private.ordax_central_device_grant_eligible_v1(uuid,text,uuid)') is null
     or to_regclass('private.ordax_central_conversation_bindings') is null
     or to_regclass('private.ordax_central_device_session_challenges') is null
     or not exists (select 1 from pg_roles where rolname='ordax_edge_executor')
  then raise exception 'central_confirm_revocation_preflight_failed'; end if;
end;
$preflight$;

create or replace function public.ordax_confirm_central_device_session_v1(
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
 -- A confirmed ticket is an idempotency reference, never permanent
 -- authorization. Every replay must have current OAuth consent and grant;
 -- a revoked or missing durable binding must not be reported as bound.
 if v_challenge.state in ('confirmed','pending') and not exists (
   select 1 from auth.oauth_consents c
   join auth.oauth_clients client
     on client.id=c.client_id and client.deleted_at is null
   where c.user_id=v_challenge.owner_user_id
     and c.client_id::text=v_challenge.client_id and c.revoked_at is null
 ) then
   return jsonb_build_object('ok',false,'error','owner_central_client_not_consented');
 end if;
 if v_challenge.state='confirmed' then
   select b.* into v_existing
     from private.ordax_central_conversation_bindings b
    where b.request_id=v_challenge.binding_request_id
    for update;
   if not found
      or v_existing.state<>'active'
      or v_existing.expires_at<=v_now
      or v_existing.owner_user_id is distinct from v_challenge.owner_user_id
      or v_existing.client_id is distinct from v_challenge.client_id
      or v_existing.session_sha256 is distinct from v_challenge.session_sha256
      or v_existing.device_id is distinct from v_challenge.device_id
      or v_existing.space_id is not null or v_existing.project_id is not null
   then
     return jsonb_build_object('ok',false,'error','central_session_revoked');
   end if;
   if not private.ordax_central_device_grant_eligible_v1(
     v_challenge.owner_user_id,v_challenge.client_id,v_challenge.device_id
   ) then
     return jsonb_build_object('ok',false,'error','central_device_grant_revoked');
   end if;
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
      set expires_at='infinity'::timestamptz
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
     v_challenge.session_sha256,'active','infinity'::timestamptz
   );
 end if;

 update private.ordax_central_device_session_challenges
    set state='confirmed',confirmed_at=v_now,binding_request_id=v_binding_request_id
  where challenge_id=v_challenge.challenge_id;
 return jsonb_build_object(
   'ok',true,'status','bound','device_id',v_challenge.device_id,
   'request_id',v_binding_request_id,'expires_at','infinity'::timestamptz
 );
end;
$$;

revoke all on function public.ordax_confirm_central_device_session_v1(uuid,text,uuid)
  from public,anon,authenticated,service_role;
grant execute on function public.ordax_confirm_central_device_session_v1(uuid,text,uuid)
  to ordax_edge_executor;

commit;
