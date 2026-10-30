-- Read-only verification after deployment by the existing migration owner.
-- Does not create a grant, task, installation, token or session.
begin read only;
do $check$
declare
  v_oid regprocedure := to_regprocedure(
    'public.ordax_orchestrator_read_authorization_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text)');
  v_definition text;
  v_role text;
begin
  if v_oid is null then raise exception 'orchestrator_authorization_rpc_missing'; end if;
  select pg_catalog.pg_get_functiondef(v_oid::oid) into v_definition;
  if not exists(select 1 from pg_catalog.pg_proc where oid=v_oid::oid and prosecdef
    and proconfig @> array['search_path=""'])
    or v_definition not like '%ordax_resolve_product_remote_grant_v1%'
    or v_definition not like '%ordax_trusted_actor_auth_eligible_v1%'
    or v_definition not like '%consent.revoked_at is null%'
    or v_definition not like '%r.lease_id = p_lease_id%'
    or v_definition not like '%r.execution_epoch = p_execution_epoch%'
  then raise exception 'orchestrator_authorization_contract_mismatch'; end if;
  foreach v_role in array array['anon','authenticated','service_role'] loop
    if has_function_privilege(v_role,v_oid,'EXECUTE') then
      raise exception 'orchestrator_authorization_public_execute';
    end if;
  end loop;
  if not has_function_privilege('ordax_edge_executor',v_oid,'EXECUTE')
     or not has_function_privilege('ordax_edge_runtime',v_oid,'EXECUTE') then
    raise exception 'orchestrator_authorization_executor_missing';
  end if;
end;
$check$;
rollback;
