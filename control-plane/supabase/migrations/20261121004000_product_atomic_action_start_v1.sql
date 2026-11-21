begin;
-- Fix the canonical /start handshake: the Worker previously invoked an
-- unimported provenance binder and always returned an unexplained HTTP 503.
-- Even with a valid import, two independent SQL transactions could leave
-- partially recorded provenance when the start confirmation failed.
-- Preserve existing lease/fencing/grant and provenance authorities.
create or replace function public.ordax_start_product_action_atomic_v1(
  p_device_id uuid, p_request_id uuid, p_effect_id uuid,
  p_attempt_id uuid, p_lease_id uuid, p_execution_epoch bigint,
  p_agent_instance_id uuid, p_boot_id text,
  p_runtime_kind text, p_agent_version text
) returns jsonb language plpgsql security definer set search_path to ''
as $function$
declare
  v_started boolean;
begin
  if (p_runtime_kind is null) <> (p_agent_version is null) then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'runtime_provenance_conflict');
  end if;
  begin
    v_started := public.ordax_start_product_action_v1(
      p_device_id, p_request_id, p_effect_id, p_attempt_id, p_lease_id,
      p_execution_epoch, p_agent_instance_id, p_boot_id);
    if not coalesce(v_started, false) then
      return pg_catalog.jsonb_build_object(
        'ok', false, 'error', 'lease_not_active');
    end if;
    if p_runtime_kind is not null
      and not coalesce(public.ordax_bind_product_action_runtime_provenance_v1(
        p_device_id, p_request_id, p_effect_id, p_attempt_id, p_lease_id,
        p_execution_epoch, p_agent_instance_id, p_boot_id,
        p_runtime_kind, p_agent_version), false)
    then
      -- The exception subtransaction reverts the running transition,
      -- leaving the original lease eligible for a correct retry.
      raise exception 'atomic start provenance rejected' using errcode='P4103';
    end if;
    return pg_catalog.jsonb_build_object('ok', true);
  exception when sqlstate 'P4103' then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'runtime_provenance_conflict');
  end;
end;
$function$;
revoke all on function public.ordax_start_product_action_atomic_v1(
  uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,text,text
) from public,anon,authenticated,service_role,ordax_edge_executor;
grant execute on function public.ordax_start_product_action_atomic_v1(
  uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,text,text
) to ordax_edge_executor;
comment on function public.ordax_start_product_action_atomic_v1(
  uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,text,text
) is 'One atomic Device start/Runtime provenance receipt; original grant and epoch fencing retained.';
commit;
