-- Make queued TTL expiration a distinct Product action state.
-- Only actions that never started may become expired. Running execution loss
-- remains failed/execution_outcome_unconfirmed and device terminal reports
-- remain succeeded/failed/cancelled.
begin;

alter table private.ordax_product_action_requests
  drop constraint ordax_product_action_requests_status_check;

alter table private.ordax_product_action_requests
  add constraint ordax_product_action_requests_status_check
  check (status = any (array[
    'queued'::text,
    'leased'::text,
    'running'::text,
    'succeeded'::text,
    'failed'::text,
    'cancelled'::text,
    'expired'::text
  ]));

create or replace function private.ordax_expire_queued_product_actions_v1(
  p_device_id uuid,
  p_request_id uuid default null
)
returns integer
language plpgsql
security invoker
set search_path = ''
as $function$
declare
  v_count integer;
begin
  if p_device_id is null then return 0; end if;

  with expired as (
    update private.ordax_product_action_requests r
       set status = 'expired',
           error_code = 'action_expired',
           finished_at = pg_catalog.clock_timestamp()
     where r.device_id = p_device_id
       and (p_request_id is null or r.request_id = p_request_id)
       and r.status = 'queued'
       and r.expires_at <= pg_catalog.clock_timestamp()
     returning r.request_id
  )
  select count(*) into v_count from expired;

  return v_count;
end;
$function$;

-- Historical action_expired rows were produced only by the queued-expiration
-- helper. Backfill only records that provably never entered an execution fence.
update private.ordax_product_action_requests
   set status = 'expired'
 where status = 'failed'
   and error_code = 'action_expired'
   and started_at is null
   and attempt_id is null
   and lease_id is null
   and report_id is null;

revoke all on function private.ordax_expire_queued_product_actions_v1(uuid,uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;

commit;
