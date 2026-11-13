-- Refresh an already-attested Central conversation lease on real tool use.
-- Resolution still requires the exact owner/client/session binding and a current
-- eligible device grant. This changes no target, grant, consent or device identity.
begin;

do $preflight$
begin
  if to_regprocedure('public.ordax_resolve_central_device_session_v1(uuid,text,text)') is null
     or to_regprocedure('private.ordax_central_device_grant_eligible_v1(uuid,text,uuid)') is null
     or to_regclass('private.ordax_central_conversation_bindings') is null
     or not exists(select 1 from pg_roles where rolname='ordax_edge_executor')
  then raise exception 'central_session_activity_lease_preflight_failed'; end if;
end;
$preflight$;

create or replace function public.ordax_resolve_central_device_session_v1(
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

 update private.ordax_central_conversation_bindings b
    set expires_at=greatest(b.expires_at,v_now+interval '30 minutes')
  where b.request_id=v_binding.request_id
    and b.owner_user_id=p_owner_user_id
    and b.client_id=p_client_id
    and b.session_sha256=p_session_sha256
    and b.device_id=v_binding.device_id
    and b.space_id is null and b.project_id is null
    and b.state='active' and b.expires_at>v_now
  returning b.* into v_binding;
 if not found then
   return jsonb_build_object('ok',false,'error','central_session_unbound');
 end if;

 return jsonb_build_object(
   'ok',true,'device_id',v_binding.device_id,
   'request_id',v_binding.request_id,'expires_at',v_binding.expires_at
 );
end;
$$;

revoke all on function public.ordax_resolve_central_device_session_v1(uuid,text,text)
  from public,anon,authenticated,service_role;
grant execute on function public.ordax_resolve_central_device_session_v1(uuid,text,text)
  to ordax_edge_executor;

commit;
