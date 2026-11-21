begin;

-- Authenticate and delegate to the existing fenced operation in one round trip.

create or replace function public.ordax_authenticated_renew_product_action_lease_v1(
  p_device_id uuid,
  p_token_sha256 text,
  p_request_id uuid,
  p_effect_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_execution_epoch bigint,
  p_agent_instance_id uuid,
  p_boot_id text,
  p_lease_seconds integer
) returns jsonb
language plpgsql security definer set search_path to ''
as $function$

declare v_until timestamptz;

begin
  if p_device_id is null or p_token_sha256 is null
    or p_token_sha256 !~ '^[0-9a-f]{64}$'
    or not coalesce(public.ordax_authenticate_product_device_v1(p_device_id,p_token_sha256),false)
  then
    return pg_catalog.jsonb_build_object('ok',false,'error','invalid_device_token');
  end if;

  v_until := public.ordax_renew_product_action_lease_v1(p_device_id,p_request_id,p_effect_id,p_attempt_id,p_lease_id,p_execution_epoch,p_agent_instance_id,p_boot_id,p_lease_seconds);
  return pg_catalog.jsonb_build_object('ok',v_until is not null,'lease_expires_at',v_until::text);

end;
$function$;

revoke all on function public.ordax_authenticated_renew_product_action_lease_v1(uuid,text,uuid,uuid,uuid,uuid,bigint,uuid,text,integer) from public,anon,authenticated,service_role,ordax_edge_executor;

grant execute on function public.ordax_authenticated_renew_product_action_lease_v1(uuid,text,uuid,uuid,uuid,uuid,bigint,uuid,text,integer) to ordax_edge_executor;

create or replace function public.ordax_authenticated_progress_product_action_v1(
  p_device_id uuid,
  p_token_sha256 text,
  p_request_id uuid,
  p_effect_id uuid,
  p_attempt_id uuid,
  p_lease_id uuid,
  p_execution_epoch bigint,
  p_agent_instance_id uuid,
  p_boot_id text,
  p_stage text,
  p_message text,
  p_progress_percent smallint
) returns jsonb
language plpgsql security definer set search_path to ''
as $function$

begin
  if p_device_id is null or p_token_sha256 is null
    or p_token_sha256 !~ '^[0-9a-f]{64}$'
    or not coalesce(public.ordax_authenticate_product_device_v1(p_device_id,p_token_sha256),false)
  then
    return pg_catalog.jsonb_build_object('ok',false,'error','invalid_device_token');
  end if;

  return pg_catalog.jsonb_build_object('ok',coalesce(public.ordax_progress_product_action_v1(p_device_id,p_request_id,p_effect_id,p_attempt_id,p_lease_id,p_execution_epoch,p_agent_instance_id,p_boot_id,p_stage,p_message,p_progress_percent),false));

end;
$function$;

revoke all on function public.ordax_authenticated_progress_product_action_v1(uuid,text,uuid,uuid,uuid,uuid,bigint,uuid,text,text,text,smallint) from public,anon,authenticated,service_role,ordax_edge_executor;

grant execute on function public.ordax_authenticated_progress_product_action_v1(uuid,text,uuid,uuid,uuid,uuid,bigint,uuid,text,text,text,smallint) to ordax_edge_executor;

commit;
