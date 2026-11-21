begin;

-- The existing terminal report and immutable execution provenance must be one
-- PostgreSQL transaction, not two HTTP/Hyperdrive round trips. An error from
-- binding rolls back the report, result, finished_at, and audit row together.
-- The canonical queue, fencing, report_id idempotency and grant authority stay
-- in the existing functions; this is only their atomic composition.
create or replace function public.ordax_report_product_action_atomic_v1(
  p_device_id uuid,
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
)
returns jsonb
language plpgsql
security definer
set search_path to ''
as $function$
declare
  v_receipt jsonb;
begin
  -- Either both provenance fields are present or neither is. Old runtimes
  -- may omit both, but partial identity must never be accepted.
  if (p_runtime_kind is null) <> (p_agent_version is null) then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'runtime_provenance_conflict');
  end if;

  begin
    v_receipt := public.ordax_report_product_action_v1(
      p_device_id, p_request_id, p_effect_id, p_attempt_id, p_lease_id,
      p_execution_epoch, p_agent_instance_id, p_boot_id, p_report_id,
      p_status, p_result, p_result_sha256, p_error_code
    );
    if v_receipt is null then
      return pg_catalog.jsonb_build_object(
        'ok', false, 'error', 'product_postgres_invalid_response');
    end if;
    if v_receipt->>'ok' is distinct from 'true' then
      return v_receipt;
    end if;

    if p_runtime_kind is not null
       and not coalesce(public.ordax_bind_product_action_runtime_provenance_v1(
         p_device_id, p_request_id, p_effect_id, p_attempt_id, p_lease_id,
         p_execution_epoch, p_agent_instance_id, p_boot_id,
         p_runtime_kind, p_agent_version
       ), false) then
      -- An exception subtransaction rolls back the preceding report. Do not
      -- return an error after committing a successful terminal receipt.
      raise exception 'atomic terminal provenance rejected' using errcode = 'P4101';
    end if;
    return v_receipt;
  exception when sqlstate 'P4101' then
    return pg_catalog.jsonb_build_object(
      'ok', false, 'error', 'runtime_provenance_conflict');
  end;
end;
$function$;

revoke all on function public.ordax_report_product_action_atomic_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, uuid,
  text, jsonb, text, text, text, text
) from public, anon, authenticated, service_role, ordax_edge_executor;

grant execute on function public.ordax_report_product_action_atomic_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, uuid,
  text, jsonb, text, text, text, text
) to ordax_edge_executor;

comment on function public.ordax_report_product_action_atomic_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, uuid,
  text, jsonb, text, text, text, text
) is 'Single atomic terminal receipt and execution-time Runtime provenance; original report_id replay remains idempotent.';

commit;
