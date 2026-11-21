begin;
-- Device-authenticated start in one Hyperdrive SQL statement. The existing
-- atomic start RPC is the only lease/provenance authority; do not duplicate it.
create or replace function public.ordax_authenticated_start_product_action_v1(
  p_device_id uuid,
  p_token_sha256 text,
  p_request_id uuid,
  p_effect_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_execution_epoch bigint,
  p_agent_instance_id uuid,
  p_boot_id text,
  p_runtime_kind text,
  p_agent_version text
) returns jsonb
language plpgsql security definer set search_path to ''
as $function$
begin
  if p_device_id is null or p_token_sha256 is null
    or p_token_sha256 !~ '^[0-9a-f]{64}$'
    or not coalesce(public.ordax_authenticate_product_device_v1(
      p_device_id,p_token_sha256),false)
  then
    return pg_catalog.jsonb_build_object('ok',false,'error','invalid_device_token');
  end if;
  -- Existing transaction enforces active lease, current grant, agent fencing,
  -- execution epoch and atomic Runtime provenance. Never bypass it.
  return public.ordax_start_product_action_atomic_v1(
    p_device_id,p_request_id,p_effect_id,p_attempt_id,p_lease_id,
    p_execution_epoch,p_agent_instance_id,p_boot_id,p_runtime_kind,p_agent_version
  );
end;
$function$;
revoke all on function public.ordax_authenticated_start_product_action_v1(
  uuid,text,uuid,uuid,uuid,uuid,bigint,uuid,text,text,text
) from public,anon,authenticated,service_role,ordax_edge_executor;
grant execute on function public.ordax_authenticated_start_product_action_v1(
  uuid,text,uuid,uuid,uuid,uuid,bigint,uuid,text,text,text
) to ordax_edge_executor;
comment on function public.ordax_authenticated_start_product_action_v1(
  uuid,text,uuid,uuid,uuid,uuid,bigint,uuid,text,text,text
) is 'Single authenticated device start: delegates current lease, fencing and provenance to existing atomic authority.';
commit;
