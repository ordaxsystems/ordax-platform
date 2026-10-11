-- Read-only postflight for 20261007202500_product_client_grant_isolation_v1.
-- Run only AFTER this migration has been applied and the ledger version recorded.
-- This script does not create test grants, mutate permissions or write rows.
do $postflight$
declare
  v_old_rpc regprocedure;
  v_new_rpc regprocedure;
  v_old_resolver regprocedure;
  v_new_resolver regprocedure;
  v_resolver_source text;
  v_enqueue_source text;
begin
  v_old_rpc := pg_catalog.to_regprocedure(
    'public.ordax_enqueue_product_action_v1(uuid,uuid,uuid,uuid,text,text,text,jsonb,text,timestamptz)'
  );
  v_new_rpc := pg_catalog.to_regprocedure(
    'public.ordax_enqueue_product_action_v1(uuid,uuid,uuid,uuid,text,text,text,text,jsonb,text,timestamptz)'
  );
  v_old_resolver := pg_catalog.to_regprocedure(
    'private.ordax_resolve_product_remote_grant_v1(uuid,uuid,uuid,uuid,text,text,text)'
  );
  v_new_resolver := pg_catalog.to_regprocedure(
    'private.ordax_resolve_product_remote_grant_v1(uuid,uuid,uuid,uuid,text,text,text,text)'
  );

  if v_old_rpc is not null or v_old_resolver is not null
     or v_new_rpc is null or v_new_resolver is null then
    raise exception 'product_client_contract_signature_mismatch';
  end if;

  if not pg_catalog.has_function_privilege(
      'ordax_edge_executor', v_new_rpc::oid, 'EXECUTE'
    ) or pg_catalog.has_function_privilege(
      'authenticated', v_new_rpc::oid, 'EXECUTE'
    ) or pg_catalog.has_function_privilege(
      'anon', v_new_rpc::oid, 'EXECUTE'
    ) or pg_catalog.has_function_privilege(
      'service_role', v_new_rpc::oid, 'EXECUTE'
    ) or pg_catalog.has_function_privilege(
      'ordax_edge_executor', v_new_resolver::oid, 'EXECUTE'
    )
  then
    raise exception 'product_client_contract_acl_mismatch';
  end if;

  v_resolver_source := pg_catalog.pg_get_functiondef(v_new_resolver::oid);
  v_enqueue_source := pg_catalog.pg_get_functiondef(v_new_rpc::oid);

  if pg_catalog.strpos(v_resolver_source, 'and g.client_id = p_client_id') = 0
     or pg_catalog.strpos(v_enqueue_source, 'v_existing.client_id = p_client_id') = 0 then
    raise exception 'product_client_contract_missing_client_match';
  end if;

  -- P0 #118: the actual, installed PostgreSQL function must compare an
  -- explicitly supplied Space EXACTLY. A NULL/global grant must not be
  -- usable when the caller supplied another UUID. Check pg_get_functiondef,
  -- NOT only the migration file or a test copy of the SQL.
  if pg_catalog.strpos(
       v_resolver_source, 'g.space_id is not distinct from p_space_id'
     ) = 0
     or pg_catalog.strpos(
       v_enqueue_source, 'v_existing.space_id is not distinct from p_space_id'
     ) = 0
     or pg_catalog.strpos(
       v_resolver_source, 'g.state = ''active'''
     ) = 0
     or pg_catalog.strpos(
       v_resolver_source, 'g.valid_until > pg_catalog.clock_timestamp()'
     ) = 0
     or pg_catalog.strpos(
       v_resolver_source, 'd.state = ''active'''
     ) = 0 then
    raise exception 'product_space_contract_wildcard_or_revocation_regression';
  end if;

  if not exists (
    select 1 from information_schema.columns
    where table_schema='private' and table_name='ordax_product_action_requests'
      and column_name='client_id'
  ) or not exists (
    select 1 from information_schema.columns
    where table_schema='private' and table_name='ordax_product_action_audit'
      and column_name='client_id'
  ) then
    raise exception 'product_client_contract_missing_client_audit';
  end if;
end;
$postflight$;
