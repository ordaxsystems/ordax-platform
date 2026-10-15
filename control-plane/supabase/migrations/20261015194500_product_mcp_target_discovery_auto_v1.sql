begin;

create or replace function public.ordax_ensure_product_mcp_target_discovery_v1(
  p_owner_user_id uuid,
  p_oauth_client_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_client_id text;
  v_device record;
  v_result jsonb;
  v_granted integer := 0;
begin
  if p_owner_user_id is null or p_oauth_client_id is null then
    return pg_catalog.jsonb_build_object('ok', false, 'error', 'product_mcp_target_grant_invalid');
  end if;

  select c.id::text
    into v_client_id
    from auth.oauth_clients c
    join auth.oauth_consents consent
      on consent.client_id = c.id
     and consent.user_id = p_owner_user_id
     and consent.revoked_at is null
   where c.id = p_oauth_client_id
     and c.deleted_at is null
     and c.client_type::text = 'public'
   limit 1;

  if v_client_id is null then
    return pg_catalog.jsonb_build_object('ok', false, 'error', 'product_mcp_oauth_consent_required');
  end if;

  for v_device in
    select d.device_id
      from public.ordax_product_devices d
     where d.owner_user_id = p_owner_user_id
       and d.state = 'active'
     order by d.device_id
  loop
    v_result := public.ordax_authorize_product_mcp_target_discovery_v1(
      p_owner_user_id,
      v_device.device_id,
      p_oauth_client_id
    );
    if coalesce((v_result->>'ok')::boolean, false) is not true then
      return v_result;
    end if;
    v_granted := v_granted + 1;
  end loop;

  return pg_catalog.jsonb_build_object(
    'ok', true,
    'client_kind', 'product-mcp',
    'client_id', v_client_id,
    'capability', 'product.target.read',
    'access_mode', 'read',
    'devices_granted', v_granted
  );
end;
$function$;

revoke all on function public.ordax_ensure_product_mcp_target_discovery_v1(uuid, uuid) from public;
revoke all on function public.ordax_ensure_product_mcp_target_discovery_v1(uuid, uuid) from anon;
revoke all on function public.ordax_ensure_product_mcp_target_discovery_v1(uuid, uuid) from authenticated;
revoke all on function public.ordax_ensure_product_mcp_target_discovery_v1(uuid, uuid) from service_role;
grant execute on function public.ordax_ensure_product_mcp_target_discovery_v1(uuid, uuid) to ordax_edge_executor;

commit;
