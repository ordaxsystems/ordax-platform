-- Execute after the migration. This postflight leaves all data unchanged.
-- Probe a real expired queued request only inside a rolled-back transaction.
begin;

do $postflight$
declare
  v_get regprocedure := pg_catalog.to_regprocedure(
    'public.ordax_get_product_action_v1(uuid,text,text,uuid)');
  v_claim regprocedure := pg_catalog.to_regprocedure(
    'public.ordax_claim_product_action_v1(uuid,uuid,text,integer)');
  v_expire regprocedure := pg_catalog.to_regprocedure(
    'private.ordax_expire_queued_product_actions_v1(uuid,uuid)');
  v_expired private.ordax_product_action_requests%rowtype;
  v_result jsonb;
  v_stored private.ordax_product_action_requests%rowtype;
begin
  if v_get is null or v_claim is null or v_expire is null then
    raise exception 'product_action_expiry_rpc_missing';
  end if;
  if not pg_catalog.has_function_privilege('ordax_edge_executor',v_get::oid,'EXECUTE')
     or not pg_catalog.has_function_privilege('ordax_edge_executor',v_claim::oid,'EXECUTE')
     or pg_catalog.has_function_privilege('anon',v_get::oid,'EXECUTE')
     or pg_catalog.has_function_privilege('authenticated',v_get::oid,'EXECUTE')
     or pg_catalog.has_function_privilege('service_role',v_get::oid,'EXECUTE')
     or pg_catalog.has_function_privilege('ordax_edge_executor',v_expire::oid,'EXECUTE')
  then
    raise exception 'product_action_expiry_rpc_acl_mismatch';
  end if;

  select * into v_expired
    from private.ordax_product_action_requests
   where status = 'queued'
     and expires_at <= pg_catalog.clock_timestamp()
     and client_kind in ('ordax-web','ordax-mobile','product-mcp')
     and client_id is not null
   order by created_at
   limit 1;

  if not found then
    raise notice 'No expired queued fixture available; ACL/definition assertions passed';
    return;
  end if;

  v_result := public.ordax_get_product_action_v1(
    v_expired.owner_user_id,v_expired.client_kind,
    v_expired.client_id,v_expired.request_id);

  if v_result->>'status' <> 'failed'
     or v_result->>'error_code' <> 'action_expired'
  then
    raise exception 'product_action_expiry_not_terminal';
  end if;

  select * into v_stored from private.ordax_product_action_requests
    where request_id=v_expired.request_id;
  if v_stored.status <> 'failed'
     or v_stored.execution_epoch <> v_expired.execution_epoch
     or v_stored.report_id is distinct from v_expired.report_id
     or v_stored.attempt_id is distinct from v_expired.attempt_id
  then
    raise exception 'product_action_expiry_mutated_execution_provenance';
  end if;

  -- Different OAuth client must never retrieve or alter the request.
  if public.ordax_get_product_action_v1(
       v_expired.owner_user_id,v_expired.client_kind,
       v_expired.client_id || '-different',v_expired.request_id
     ) is not null
  then
    raise exception 'product_action_expiry_client_isolation_failed';
  end if;
end;
$postflight$;

rollback;
