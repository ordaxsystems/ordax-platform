-- End the false pending state of Product actions that were claimed but never
-- started and whose queue TTL *and* lease have both expired. This extends the
-- existing expiration authority: no new queue, scheduler, RPC or retry path.
-- Started actions remain owned by their fenced execution/report lifecycle.
begin;

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
  v_now timestamptz := pg_catalog.clock_timestamp();
begin
  if p_device_id is null then return 0; end if;

  with expired as (
    update private.ordax_product_action_requests r
       set status = 'expired',
           error_code = 'action_expired',
           finished_at = v_now
     where r.device_id = p_device_id
       and (p_request_id is null or r.request_id = p_request_id)
       and r.expires_at <= v_now
       and (
         r.status = 'queued'
         or (
           r.status = 'leased'
           and r.started_at is null
           and r.report_id is null
           and r.lease_expires_at is not null
           and r.lease_expires_at < v_now
         )
       )
     returning r.request_id
  )
  select pg_catalog.count(*)::integer into v_count from expired;

  return v_count;
end;
$function$;

-- Preserve the existing private-only authority boundary. The exact
-- owner/client-scoped status RPC and the device claim RPC already call this
-- helper; the claimed attempt, lease and execution epoch stay in the receipt.
revoke all on function private.ordax_expire_queued_product_actions_v1(uuid,uuid)
  from public, anon, authenticated, service_role, ordax_edge_executor;

-- Reconcile historical never-started records once. No running/succeeded/failed
-- effect can be re-executed or terminalized by this migration.
do $backfill$
declare
  v_device_id uuid;
begin
  for v_device_id in
    select distinct r.device_id
      from private.ordax_product_action_requests r
     where r.expires_at <= pg_catalog.clock_timestamp()
       and (
         r.status = 'queued'
         or (
           r.status = 'leased'
           and r.started_at is null
           and r.report_id is null
           and r.lease_expires_at is not null
           and r.lease_expires_at < pg_catalog.clock_timestamp()
         )
       )
  loop
    perform private.ordax_expire_queued_product_actions_v1(v_device_id, null);
  end loop;
end;
$backfill$;

commit;
