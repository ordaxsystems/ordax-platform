begin;

-- Authenticate and commit a terminal receipt through one Hyperdrive query.
-- Existing atomic receipt/provenance authority retains all fencing and replay rules.
create or replace function public.ordax_authenticated_report_product_action_v1(
  p_device_id uuid,
  p_token_sha256 text,
  p_request_id uuid,
  p_effect_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_execution_epoch bigint,
  p_agent_instance_id uuid,
  p_boot_id text,
  p_report_id uuid,
  p_status text,
  p_result jsonb,
  p_result_sha256 text,
  p_error_code text,
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
  return public.ordax_report_product_action_atomic_v1(
    p_device_id,p_request_id,p_effect_id,p_attempt_id,p_lease_id,
    p_execution_epoch,p_agent_instance_id,p_boot_id,p_report_id,
    p_status,p_result,p_result_sha256,p_error_code,p_runtime_kind,p_agent_version
  );
end;
$function$;

revoke all on function public.ordax_authenticated_report_product_action_v1(
  uuid,text,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid,text,jsonb,text,text,text,text
) from public,anon,authenticated,service_role,ordax_edge_executor;
grant execute on function public.ordax_authenticated_report_product_action_v1(
  uuid,text,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid,text,jsonb,text,text,text,text
) to ordax_edge_executor;
comment on function public.ordax_authenticated_report_product_action_v1(
  uuid,text,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid,text,jsonb,text,text,text,text
) is 'One authenticated terminal report: existing atomic receipt/provenance authority retains fencing and replay.';
commit;
