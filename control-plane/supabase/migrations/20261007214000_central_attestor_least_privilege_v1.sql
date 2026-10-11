-- SECURITY P0: ordax_edge_runtime inherits ordax_edge_executor.
-- Therefore WRITE RPCs for Central session binding must not be granted to
-- the general Product edge executor. This migration atomically narrows them.
-- A dedicated NOLOGIN attestor role has no login password, no inherited
-- Runtime membership and is NOT provisioned to a public Worker.
begin;
do $preflight$
begin
 if to_regprocedure('public.ordax_bind_central_conversation_v1(uuid,text,uuid,uuid,uuid,uuid,text,text,timestamptz)') is null
 or to_regprocedure('public.ordax_verify_central_conversation_v1(uuid,text,uuid,uuid,uuid,uuid,text,text)') is null
 or to_regprocedure('public.ordax_revoke_central_conversation_v1(uuid,text,uuid)') is null
 or exists(select 1 from pg_roles where rolname='ordax_central_attestation_executor')
 then raise exception 'central_attestor_hardening_preflight_failed'; end if;
end;
$preflight$;

create role ordax_central_attestation_executor
  nologin noinherit nobypassrls;

revoke execute on function
  public.ordax_bind_central_conversation_v1(uuid,text,uuid,uuid,uuid,uuid,text,text,timestamptz)
  from ordax_edge_executor,ordax_edge_runtime,public,anon,authenticated,service_role;
revoke execute on function
  public.ordax_revoke_central_conversation_v1(uuid,text,uuid)
  from ordax_edge_executor,ordax_edge_runtime,public,anon,authenticated,service_role;

grant usage on schema public to ordax_central_attestation_executor;
grant execute on function
  public.ordax_bind_central_conversation_v1(uuid,text,uuid,uuid,uuid,uuid,text,text,timestamptz)
  to ordax_central_attestation_executor;
grant execute on function
  public.ordax_revoke_central_conversation_v1(uuid,text,uuid)
  to ordax_central_attestation_executor;

-- Verification only is safe for the canonical edge executor. The
-- actual read still rechecks full owner + client + PC + current grant.
-- Runtime currently inherits edge_executor, so it can verify an *already*
-- bound marker but cannot register, rebind or revoke anyone's session.
-- Model-facing transport has no public bind/revoke endpoint.
do $postflight$
declare v_bind regprocedure := to_regprocedure(
 'public.ordax_bind_central_conversation_v1(uuid,text,uuid,uuid,uuid,uuid,text,text,timestamptz)');
 v_revoke regprocedure := to_regprocedure(
 'public.ordax_revoke_central_conversation_v1(uuid,text,uuid)');
 v_verify regprocedure := to_regprocedure(
 'public.ordax_verify_central_conversation_v1(uuid,text,uuid,uuid,uuid,uuid,text,text)');
begin
 if not has_function_privilege('ordax_central_attestation_executor',v_bind,'EXECUTE')
    or not has_function_privilege('ordax_central_attestation_executor',v_revoke,'EXECUTE')
    or has_function_privilege('ordax_edge_executor',v_bind,'EXECUTE')
    or has_function_privilege('ordax_edge_runtime',v_bind,'EXECUTE')
    or has_function_privilege('ordax_edge_executor',v_revoke,'EXECUTE')
    or has_function_privilege('ordax_edge_runtime',v_revoke,'EXECUTE')
    or not has_function_privilege('ordax_edge_executor',v_verify,'EXECUTE')
 then raise exception 'central_attestor_role_leak'; end if;
end;
$postflight$;
commit;
