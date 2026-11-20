begin;

-- Read the existing receipts for one authenticated Product client and its
-- device. The Worker derives those inputs from the persisted binding.
create function public.ordax_list_product_mcp_recent_actions_v1(
  p_owner_user_id uuid,
  p_client_id uuid,
  p_device_id uuid,
  p_pending_only boolean,
  p_limit integer
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
begin
  if p_owner_user_id is null or p_client_id is null or p_device_id is null
    or p_pending_only is null or p_limit is null or p_limit not between 1 and 20 then
    return pg_catalog.jsonb_build_object('ok', false, 'error', 'product_action_history_invalid');
  end if;

  if not private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id) then
    return pg_catalog.jsonb_build_object('ok', false, 'error', 'product_owner_auth_ineligible');
  end if;

  return (
    select pg_catalog.jsonb_build_object('ok', true, 'actions',
      coalesce(pg_catalog.jsonb_agg(pg_catalog.to_jsonb(recent)
        order by recent.created_at desc, recent.request_id desc), '[]'::jsonb))
    from (
      select r.request_id, r.device_id, r.project_id, r.capability as name,
             r.status, r.error_code, r.created_at
        from private.ordax_product_action_requests r
       where r.owner_user_id = p_owner_user_id
         and r.client_kind = 'product-mcp'
         and r.client_id = p_client_id::text
         and r.device_id = p_device_id
         and r.created_at >= pg_catalog.statement_timestamp() - interval '7 days'
         and (not p_pending_only or r.status in ('queued', 'leased', 'running'))
         and private.ordax_product_action_grant_current_v1(r.request_id)
       order by r.created_at desc, r.request_id desc
       limit p_limit
    ) recent
  );
end;
$function$;

revoke all on function public.ordax_list_product_mcp_recent_actions_v1(uuid,uuid,uuid,boolean,integer)
  from public, anon, authenticated, service_role, ordax_edge_executor;
grant execute on function public.ordax_list_product_mcp_recent_actions_v1(uuid,uuid,uuid,boolean,integer)
  to ordax_edge_executor;

commit;
