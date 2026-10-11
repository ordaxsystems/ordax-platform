-- LIVE, READ-ONLY postflight for the installed Central conversation authority.
-- No users, clients, grants, sessions, fixtures or actions are created.
do $postflight$
declare
  v_table regclass := to_regclass('private.ordax_central_conversation_bindings');
  v_bind regprocedure := to_regprocedure(
    'public.ordax_bind_central_conversation_v1(uuid,text,uuid,uuid,uuid,uuid,text,text,timestamptz)');
  v_verify regprocedure := to_regprocedure(
    'public.ordax_verify_central_conversation_v1(uuid,text,uuid,uuid,uuid,uuid,text,text)');
  v_revoke regprocedure := to_regprocedure(
    'public.ordax_revoke_central_conversation_v1(uuid,text,uuid)');
  v_source text;
  v_count bigint;
  v_false boolean;
begin
  if v_table is null or v_bind is null or v_verify is null or v_revoke is null
     or not (select relrowsecurity and relforcerowsecurity from pg_class where oid=v_table::oid)
  then raise exception 'central_session_schema_or_rls_missing'; end if;
  if has_table_privilege('anon',v_table,'SELECT')
     or has_table_privilege('authenticated',v_table,'SELECT')
     or has_table_privilege('service_role',v_table,'SELECT')
     or has_table_privilege('ordax_edge_executor',v_table,'SELECT')
     or has_table_privilege('ordax_edge_runtime',v_table,'SELECT')
  then raise exception 'central_session_table_acl_exposed'; end if;
  for v_source in select unnest(array[
    'anon','authenticated','service_role','ordax_edge_runtime'
  ]) loop
    if has_function_privilege(v_source,v_bind,'EXECUTE')
       or has_function_privilege(v_source,v_verify,'EXECUTE')
       or has_function_privilege(v_source,v_revoke,'EXECUTE')
    then raise exception 'central_session_rpc_exposed_to_%',v_source; end if;
  end loop;
  if not has_function_privilege('ordax_edge_executor',v_bind,'EXECUTE')
     or not has_function_privilege('ordax_edge_executor',v_verify,'EXECUTE')
     or not has_function_privilege('ordax_edge_executor',v_revoke,'EXECUTE')
  then raise exception 'central_session_worker_execute_missing'; end if;
  v_source:=pg_get_functiondef(v_verify::oid);
  if strpos(v_source,'b.owner_user_id=p_owner_user_id')=0
    or strpos(v_source,'b.client_id=p_client_id')=0
    or strpos(v_source,'b.device_id=p_device_id')=0
    or strpos(v_source,'b.space_id is not distinct from p_space_id')=0
    or strpos(v_source,'b.project_id is not distinct from p_project_id')=0
    or strpos(v_source,'b.conversation_id=p_conversation_id')=0
    or strpos(v_source,'b.session_sha256=p_session_sha256')=0
    or strpos(v_source,'''active'' and b.expires_at>pg_catalog.clock_timestamp()')=0
    or strpos(v_source,'private.ordax_central_read_grant_eligible_v1')=0
  then raise exception 'central_session_verify_not_exact'; end if;
  v_source:=pg_get_functiondef(v_bind::oid);
  if strpos(v_source,'private.ordax_trusted_actor_auth_eligible_v1')=0
    or strpos(v_source,'private.ordax_central_read_grant_eligible_v1')=0
    or strpos(v_source,'on conflict do nothing')=0
  then raise exception 'central_session_registration_not_guarded'; end if;
  select count(*) into v_count from private.ordax_central_conversation_bindings;
  -- This assertion is intentionally boolean-only and works even if real
  -- users exist; no insertion, update, or request is triggered.
  select public.ordax_verify_central_conversation_v1(
    'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,'synthetic-oauth-client-0001',
    'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid,null,null,
    'cccccccc-cccc-4ccc-8ccc-cccccccccccc'::uuid,
    'synthetic-chat-0001',repeat('a',64)
  ) into v_false;
  if v_false is distinct from false
  then raise exception 'central_session_missing_binding_was_authorized'; end if;
  raise notice 'CENTRAL_PERSISTED_SESSION_POSTFLIGHT=PASS bound_rows=%',v_count;
end;
$postflight$;
