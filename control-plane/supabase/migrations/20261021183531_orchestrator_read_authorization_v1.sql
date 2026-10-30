begin;

-- Read the existing Product authority, never mint an App grant or trust caller
-- identity from a device payload. Only the authenticated transport supplies
-- device_id; all subject/client/grant fields come from the fenced action row.
create function public.ordax_orchestrator_read_authorization_v1(
  p_device_id uuid, p_request_id uuid, p_effect_id uuid, p_attempt_id uuid,
  p_lease_id uuid, p_execution_epoch bigint, p_agent_instance_id uuid, p_boot_id text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_row private.ordax_product_action_requests%rowtype;
  v_grant public.ordax_remote_capability_grants%rowtype;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_until timestamptz;
begin
  select * into v_row from private.ordax_product_action_requests r
  where r.request_id = p_request_id and r.device_id = p_device_id
    and r.effect_id = p_effect_id and r.attempt_id = p_attempt_id
    and r.lease_id = p_lease_id and r.execution_epoch = p_execution_epoch
    and r.agent_instance_id = p_agent_instance_id and r.boot_id = p_boot_id
    and r.status = 'running' and r.lease_expires_at > v_now and r.expires_at > v_now
    and r.capability = 'orchestrator.app_read' and r.access_mode = 'read'
    and r.client_kind = 'product-mcp' and r.client_id is not null
    and r.space_id is null and r.project_id is null;

  if not found or not private.ordax_trusted_actor_auth_eligible_v1(v_row.owner_user_id) then
    return jsonb_build_object('ok',false,'error','orchestrator_authorization_required');
  end if;

  -- Consent revocation is live; a still-valid historical token or action is
  -- insufficient. No model-supplied owner/client IDs reach these predicates.
  if not exists (
    select 1 from auth.oauth_consents consent
    join auth.oauth_clients client on client.id = consent.client_id
    where consent.user_id = v_row.owner_user_id and client.id::text = v_row.client_id
      and consent.revoked_at is null and client.deleted_at is null
  ) then
    return jsonb_build_object('ok',false,'error','orchestrator_authorization_required');
  end if;

  select * into v_grant from public.ordax_remote_capability_grants g
  where g.grant_id = v_row.grant_id and g.profile_key = 'orchestrator-app-read'
    and g.grant_id = private.ordax_resolve_product_remote_grant_v1(
      v_row.owner_user_id,null,null,p_device_id,'product-mcp',v_row.client_id,
      'orchestrator.app_read','read');
  if not found then
    return jsonb_build_object('ok',false,'error','orchestrator_authorization_required');
  end if;

  v_until := least(v_row.lease_expires_at,v_row.expires_at,v_grant.valid_until,
                   v_now + interval '5 minutes');
  if v_until <= pg_catalog.clock_timestamp() then
    return jsonb_build_object('ok',false,'error','orchestrator_authorization_required');
  end if;
  return jsonb_build_object('ok',true,'authorization',jsonb_build_object(
    'schema','ordax.orchestrator-read-authorization/1',
    'subject_id',v_row.owner_user_id,'client_id',v_row.client_id,
    'device_id',p_device_id,'grant_id',v_row.grant_id,
    'app_id','br.com.ordax.orchestrator.lab','capability','orchestrator.app_read',
    'expires_at_ms',floor(extract(epoch from v_until)*1000)::bigint));
end;
$$;

-- Follows the canonical edge-only Product RPC boundary, not a Data API for
-- browsers. No table, grant row, installation or public tool is created.
revoke all on function public.ordax_orchestrator_read_authorization_v1(
  uuid,uuid,uuid,uuid,uuid,bigint,uuid,text
) from public,anon,authenticated,service_role,ordax_edge_runtime;
grant execute on function public.ordax_orchestrator_read_authorization_v1(
  uuid,uuid,uuid,uuid,uuid,bigint,uuid,text
) to ordax_edge_executor;

commit;
