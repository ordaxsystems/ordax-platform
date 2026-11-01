-- Keep MCP target discovery consent-bound while avoiding grant churn.
-- The original discovery ensure called replace_remote_grant_group for EVERY
-- active device on EVERY ordax_targets read, revoking a valid read-only grant
-- and inserting another identical row. This grew the grant ledger and caused
-- needless writes/locks even when no device or authorization had changed.
--
-- Only PostgreSQL owns this decision. No edge cache, fallback authority,
-- new credential, new grant type, migration backfill or production scan.
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
  v_active_count bigint;
  v_exact_count bigint;
begin
  if p_owner_user_id is null or p_oauth_client_id is null then
    return pg_catalog.jsonb_build_object('ok', false, 'error', 'product_mcp_target_grant_invalid');
  end if;

  -- Serialize *auto-discovery* for one owner/client. Concurrent GETs must not
  -- all observe an absent grant and repeatedly rotate the same grant group.
  -- The lower-level replace RPC still owns its existing device-grant lock.
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext(
    'ordax-mcp-discovery-v1|' || p_owner_user_id::text || '|' || p_oauth_client_id::text
  ));

  -- Consent is checked by the SQL authority on EVERY discovery read; no
  -- cached owner/client grant survives revoked OAuth consent.
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
    -- Skip only when the WHOLE active group is exactly the canonical
    -- owner-approved, unbounded, device-scoped read grant. A mismatched,
    -- expired or extra active capability must be reconciled, never silently
    -- treated as an acceptable discovery grant.
    select count(*),
           count(*) filter (where
             g.capability = 'product.target.read'
             and g.access_mode = 'read'
             and g.scope_kind = 'device'
             and g.space_id is null
             and g.project_id is null
             and g.valid_until is null
             and g.approved_by_user_id = p_owner_user_id
           )
      into v_active_count, v_exact_count
      from public.ordax_remote_capability_grants g
     where g.owner_user_id = p_owner_user_id
       and g.device_id = v_device.device_id
       and g.client_kind = 'product-mcp'
       and g.client_id = v_client_id
       and g.profile_key = 'mcp-discovery'
       and g.space_id is null
       and g.project_id is null
       and g.state = 'active';

    if v_active_count <> 1 or v_exact_count <> 1 then
      -- Reuse the sole audited/owner-checked grant replacement RPC; NEVER
      -- hand-write grants or remove a revoked Owner/consent check.
      v_result := public.ordax_authorize_product_mcp_target_discovery_v1(
        p_owner_user_id,
        v_device.device_id,
        p_oauth_client_id
      );
      if coalesce((v_result->>'ok')::boolean, false) is not true then
        return v_result;
      end if;
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

-- Retain the exact original least-privilege execution boundary.
revoke all on function public.ordax_ensure_product_mcp_target_discovery_v1(uuid, uuid)
  from public, anon, authenticated, service_role;
grant execute on function public.ordax_ensure_product_mcp_target_discovery_v1(uuid, uuid)
  to ordax_edge_executor;

commit;
