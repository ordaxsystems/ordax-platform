begin;

-- Account-owned observational Product MCP usage, not a quota or invoice.
-- This read path reuses the same private aggregate written by the canonical
-- shadow meter. The signed account identity is resolved by the Product Worker,
-- never accepted from the browser query/body.
do $preflight$
begin
  if to_regprocedure('public.ordax_get_product_mcp_usage_v1(uuid)') is not null
  then raise exception 'Product MCP usage self read: unexpected existing RPC'; end if;
  if to_regclass('private.ordax_product_mcp_usage_monthly') is null
     or to_regprocedure('private.ordax_trusted_actor_auth_eligible_v1(uuid)') is null
     or not exists (select 1 from pg_roles
         where rolname = 'ordax_edge_executor' and not rolcanlogin and not rolbypassrls)
  then raise exception 'Product MCP usage self read: canonical prerequisites missing'; end if;
end;
$preflight$;

create function public.ordax_get_product_mcp_usage_v1(p_owner_user_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $function$
declare
  v_current_month date := pg_catalog.date_trunc('month', pg_catalog.now() at time zone 'UTC')::date;
  v_previous_month date;
  v_entries jsonb;
begin
  if p_owner_user_id is null then
    return pg_catalog.jsonb_build_object('ok', false, 'error', 'product_mcp_usage_owner_invalid');
  end if;
  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return pg_catalog.jsonb_build_object('ok', false, 'error', 'product_owner_auth_ineligible');
  end if;

  v_previous_month := (v_current_month - interval '1 month')::date;
  select coalesce(
    pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
      'month', m.usage_month, 'tool_name', m.tool_name, 'tool_calls', m.tool_calls
    ) order by m.usage_month desc, m.tool_name),
    '[]'::jsonb
  ) into v_entries
  from private.ordax_product_mcp_usage_monthly m
  where m.owner_user_id = p_owner_user_id
    and m.usage_month between v_previous_month and v_current_month;

  return pg_catalog.jsonb_build_object(
    'ok', true,
    'schema', 'ordax.product-mcp-usage/1',
    'observed_only', true,
    'billable', false,
    'current_month', v_current_month,
    'previous_month', v_previous_month,
    'entries', v_entries
  );
end;
$function$;

revoke all on function public.ordax_get_product_mcp_usage_v1(uuid)
  from public, anon, authenticated, service_role, ordax_edge_runtime;
grant execute on function public.ordax_get_product_mcp_usage_v1(uuid)
  to ordax_edge_executor;

do $postflight$
begin
  if has_function_privilege('anon', 'public.ordax_get_product_mcp_usage_v1(uuid)', 'EXECUTE')
     or has_function_privilege('authenticated', 'public.ordax_get_product_mcp_usage_v1(uuid)', 'EXECUTE')
     or has_function_privilege('service_role', 'public.ordax_get_product_mcp_usage_v1(uuid)', 'EXECUTE')
     or not has_function_privilege('ordax_edge_executor', 'public.ordax_get_product_mcp_usage_v1(uuid)', 'EXECUTE')
     or has_table_privilege('ordax_edge_executor', 'private.ordax_product_mcp_usage_monthly', 'SELECT')
  then raise exception 'Product MCP usage self read: privileged access mismatch'; end if;
end;
$postflight$;

commit;
