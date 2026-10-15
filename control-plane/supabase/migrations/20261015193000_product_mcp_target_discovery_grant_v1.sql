begin;

create or replace function public.ordax_authorize_product_mcp_target_discovery_v1(
  p_owner_user_id uuid,
  p_device_id uuid,
  p_oauth_client_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
  v_client_id text;
  v_result jsonb;
begin
  if p_owner_user_id is null
     or p_device_id is null
     or p_oauth_client_id is null
  then
    return pg_catalog.jsonb_build_object(
      'ok', false,
      'error', 'product_mcp_target_grant_invalid'
    );
  end if;

  -- The Worker proves the owner bearer token. This RPC independently proves
  -- that the delegated MCP OAuth client is real, public, not deleted and was
  -- explicitly consented by the same owner before any Product authority is
  -- mutated.
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
    return pg_catalog.jsonb_build_object(
      'ok', false,
      'error', 'product_mcp_oauth_consent_required'
    );
  end if;

  v_result := public.ordax_replace_remote_grant_group_v1(
    p_owner_user_id,
    null,
    null,
    p_device_id,
    'product-mcp',
    v_client_id,
    'mcp-discovery',
    array['product.target.read']::text[],
    array['read']::text[],
    null
  );

  if coalesce((v_result->>'ok')::boolean, false) is not true then
    return v_result;
  end if;

  return v_result || pg_catalog.jsonb_build_object(
    'client_kind', 'product-mcp',
    'client_id', v_client_id,
    'profile_key', 'mcp-discovery',
    'capability', 'product.target.read',
    'access_mode', 'read'
  );
end;
$function$;

revoke all on function public.ordax_authorize_product_mcp_target_discovery_v1(
  uuid, uuid, uuid
) from public;
revoke all on function public.ordax_authorize_product_mcp_target_discovery_v1(
  uuid, uuid, uuid
) from anon;
revoke all on function public.ordax_authorize_product_mcp_target_discovery_v1(
  uuid, uuid, uuid
) from authenticated;
revoke all on function public.ordax_authorize_product_mcp_target_discovery_v1(
  uuid, uuid, uuid
) from service_role;
grant execute on function public.ordax_authorize_product_mcp_target_discovery_v1(
  uuid, uuid, uuid
) to ordax_edge_executor;

commit;
