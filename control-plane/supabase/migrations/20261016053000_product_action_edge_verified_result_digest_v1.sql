begin;

-- The device transport sends the exact canonical UTF-8 result bytes plus SHA-256.
-- The Cloudflare boundary validates that digest before parsing JSON and calling
-- this RPC. PostgreSQL stores the already-verified digest together with JSONB.
-- Do not hash jsonb::text here: PostgreSQL textual JSONB formatting is not the
-- wire canonicalization used by the Runtime and would reject valid reports.
create or replace function public.ordax_report_product_action_v1(
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
  p_error_code text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_row private.ordax_product_action_requests%rowtype;
begin
  if p_status not in ('succeeded','failed','cancelled')
     or p_result is null
     or pg_catalog.octet_length(p_result::text) > 524288
     or p_result_sha256 is null
     or p_result_sha256 !~ '^[0-9a-f]{64}$'
     or (p_error_code is not null and char_length(p_error_code) > 120)
  then
    return jsonb_build_object('ok', false, 'error', 'report_invalid');
  end if;

  select *
    into v_row
    from private.ordax_product_action_requests
   where request_id = p_request_id
     and device_id = p_device_id
   for update;

  if not found then
    return jsonb_build_object('ok', false, 'error', 'product_action_not_found');
  end if;

  if v_row.status in ('succeeded','failed','cancelled') then
    if v_row.effect_id = p_effect_id
       and v_row.attempt_id = p_attempt_id
       and v_row.lease_id = p_lease_id
       and v_row.execution_epoch = p_execution_epoch
       and v_row.agent_instance_id = p_agent_instance_id
       and v_row.boot_id = p_boot_id
       and v_row.report_id = p_report_id
       and v_row.status = p_status
       and v_row.result_sha256 = pg_catalog.lower(p_result_sha256)
       and v_row.result = p_result
       and v_row.error_code is not distinct from p_error_code
    then
      return jsonb_build_object('ok', true, 'replayed', true, 'status', v_row.status);
    end if;
    return jsonb_build_object('ok', false, 'error', 'terminal_report_conflict');
  end if;

  if v_row.effect_id <> p_effect_id
     or v_row.attempt_id <> p_attempt_id
     or v_row.lease_id <> p_lease_id
     or v_row.execution_epoch <> p_execution_epoch
     or v_row.agent_instance_id <> p_agent_instance_id
     or v_row.boot_id <> p_boot_id
     or v_row.status not in ('leased','running')
     or v_row.report_id is not null
  then
    return jsonb_build_object('ok', false, 'error', 'lease_not_active');
  end if;

  update private.ordax_product_action_requests
     set status = p_status,
         report_id = p_report_id,
         result = p_result,
         result_sha256 = pg_catalog.lower(p_result_sha256),
         error_code = p_error_code,
         finished_at = v_now,
         lease_expires_at = null
   where request_id = p_request_id;

  insert into private.ordax_product_action_audit(
    request_id, owner_user_id, space_id, project_id, device_id, grant_id,
    client_kind, capability, access_mode, phase, decision, reason, result_ok
  ) values (
    v_row.request_id, v_row.owner_user_id, v_row.space_id, v_row.project_id,
    v_row.device_id, v_row.grant_id, v_row.client_kind, v_row.capability,
    v_row.access_mode, 'result', 'allow', 'terminal_report_committed',
    p_status = 'succeeded'
  );

  return jsonb_build_object(
    'ok', true,
    'replayed', false,
    'status', p_status,
    'result_sha256', pg_catalog.lower(p_result_sha256)
  );
end;
$$;

comment on function public.ordax_report_product_action_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, uuid, text, jsonb, text, text
) is 'Commits one fenced Product action terminal report. result_sha256 is verified against canonical result bytes by the authenticated edge transport before this RPC; JSONB text serialization is never used as a wire digest.';

-- Preserve the least-privilege executor boundary explicitly.
revoke all on function public.ordax_report_product_action_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, uuid, text, jsonb, text, text
) from public, anon, authenticated, service_role;
grant execute on function public.ordax_report_product_action_v1(
  uuid, uuid, uuid, uuid, uuid, bigint, uuid, text, uuid, text, jsonb, text, text
) to ordax_edge_executor;

commit;
