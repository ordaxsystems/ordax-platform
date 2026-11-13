-- Reconcile orphaned already-running Product MCP actions at the fenced lease
-- boundary. The original execution may still submit one late terminal report
-- because ordax_report_product_action_v1 verifies the exact original
-- effect/attempt/lease/epoch/agent/boot tuple. Never reclaim or re-execute it.
begin;

create or replace function private.ordax_retire_orphaned_running_product_actions_v1(
  p_device_id uuid,
  p_request_id uuid default null
)
returns integer
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_count integer := 0;
begin
  if p_device_id is null then return 0; end if;

  -- A live Runtime renews this fenced lease. Once the lease has expired the
  -- Product authority no longer has a confirmed active executor, so keeping
  -- the receipt in "running" would be false state. Retire it immediately as
  -- outcome-unconfirmed; the identical original fenced attempt can still
  -- reconcile a persisted terminal report through the existing report RPC.
  with retired as (
    update private.ordax_product_action_requests r
       set status = 'failed',
           error_code = 'execution_outcome_unconfirmed',
           finished_at = pg_catalog.clock_timestamp(),
           lease_expires_at = null
     where r.device_id = p_device_id
       and (p_request_id is null or r.request_id = p_request_id)
       and r.status = 'running'
       and r.report_id is null
       and r.lease_expires_at is not null
       and r.lease_expires_at < pg_catalog.clock_timestamp()
     returning r.*
  )
  insert into private.ordax_product_action_audit(
    request_id, owner_user_id, space_id, project_id, device_id, grant_id,
    client_kind, capability, access_mode, phase, decision, reason, result_ok
  )
  select
    r.request_id, r.owner_user_id, r.space_id, r.project_id,
    r.device_id, r.grant_id, r.client_kind, r.capability,
    r.access_mode, 'result', 'deny', 'execution_outcome_unconfirmed', false
    from retired r;

  get diagnostics v_count = row_count;
  return v_count;
end;
$function$;

revoke all on function private.ordax_retire_orphaned_running_product_actions_v1(uuid,uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;

commit;
