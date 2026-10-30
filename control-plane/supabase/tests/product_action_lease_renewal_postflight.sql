-- Postflight for product leases: only a historical terminal action is reused.
-- Every change, including audit rows, is inside a mandatory ROLLBACK.
-- This is NOT a migration and must never be committed against production.
begin;
do $lease_postflight$
declare
  v_old private.ordax_product_action_requests%rowtype;
  v_now timestamptz;
  v_until timestamptz;
  v_retired integer;
  v_current private.ordax_product_action_requests%rowtype;
begin
  select * into v_old
    from private.ordax_product_action_requests r
   where r.status = 'succeeded'
     and r.report_id is not null
     and r.attempt_id is not null
     and r.lease_id is not null
     and r.effect_id is not null
     and r.agent_instance_id is not null
     and r.boot_id is not null
   order by r.finished_at desc
   limit 1 for update;
  if not found then
    raise exception 'lease_postflight_no_historical_fixture';
  end if;

  -- A lease that was never started is reassignable only after the claim
  -- transaction has fenced it. An authenticated original attempt may renew
  -- until that reassignment, and cannot resurrect an already retired action.
  update private.ordax_product_action_requests
     set status = 'leased', report_id = null, result = null,
         result_sha256 = null, error_code = null, finished_at = null,
         lease_expires_at = pg_catalog.clock_timestamp() - interval '1 minute'
   where request_id = v_old.request_id;

  if public.ordax_renew_product_action_lease_v1(
       v_old.device_id, v_old.request_id, v_old.effect_id,
       extensions.gen_random_uuid(), v_old.lease_id, v_old.execution_epoch,
       v_old.agent_instance_id, v_old.boot_id, 120) is not null then
    raise exception 'lease_postflight_wrong_attempt_accepted';
  end if;
  if public.ordax_renew_product_action_lease_v1(
       v_old.device_id, v_old.request_id, v_old.effect_id,
       v_old.attempt_id, extensions.gen_random_uuid(), v_old.execution_epoch,
       v_old.agent_instance_id, v_old.boot_id, 120) is not null then
    raise exception 'lease_postflight_wrong_lease_accepted';
  end if;
  if public.ordax_renew_product_action_lease_v1(
       v_old.device_id, v_old.request_id, v_old.effect_id,
       v_old.attempt_id, v_old.lease_id, v_old.execution_epoch + 1,
       v_old.agent_instance_id, v_old.boot_id, 120) is not null then
    raise exception 'lease_postflight_wrong_epoch_accepted';
  end if;
  if public.ordax_renew_product_action_lease_v1(
       v_old.device_id, v_old.request_id, v_old.effect_id,
       v_old.attempt_id, v_old.lease_id, v_old.execution_epoch,
       extensions.gen_random_uuid(), v_old.boot_id, 120) is not null then
    raise exception 'lease_postflight_wrong_agent_accepted';
  end if;
  if public.ordax_renew_product_action_lease_v1(
       v_old.device_id, v_old.request_id, v_old.effect_id,
       v_old.attempt_id, v_old.lease_id, v_old.execution_epoch,
       v_old.agent_instance_id, v_old.boot_id || '-old', 120) is not null then
    raise exception 'lease_postflight_wrong_boot_accepted';
  end if;
  if public.ordax_renew_product_action_lease_v1(
       v_old.device_id, v_old.request_id, extensions.gen_random_uuid(),
       v_old.attempt_id, v_old.lease_id, v_old.execution_epoch,
       v_old.agent_instance_id, v_old.boot_id, 120) is not null then
    raise exception 'lease_postflight_wrong_effect_accepted';
  end if;
  if public.ordax_renew_product_action_lease_v1(
       v_old.device_id, v_old.request_id, v_old.effect_id,
       v_old.attempt_id, v_old.lease_id, v_old.execution_epoch,
       v_old.agent_instance_id, v_old.boot_id, 10) is not null then
    raise exception 'lease_postflight_invalid_duration_accepted';
  end if;

  v_now := pg_catalog.clock_timestamp();
  v_until := public.ordax_renew_product_action_lease_v1(
    v_old.device_id, v_old.request_id, v_old.effect_id,
    v_old.attempt_id, v_old.lease_id, v_old.execution_epoch,
    v_old.agent_instance_id, v_old.boot_id, 120);
  if v_until is null or v_until < v_now + interval '110 seconds' then
    raise exception 'lease_postflight_valid_leased_renewal_failed';
  end if;
  select * into v_current from private.ordax_product_action_requests
   where request_id = v_old.request_id;
  if v_current.status <> 'leased'
     or v_current.attempt_id is distinct from v_old.attempt_id
     or v_current.execution_epoch <> v_old.execution_epoch
     or v_current.lease_id is distinct from v_old.lease_id then
    raise exception 'lease_postflight_renewal_modified_fencing';
  end if;

  -- Running work remains fenced through a short outage. The same attempt
  -- can renew during the grace period without dispatching it again.
  update private.ordax_product_action_requests
     set status = 'running',
         lease_expires_at = pg_catalog.clock_timestamp() - interval '1 minute'
   where request_id = v_old.request_id;
  v_until := public.ordax_renew_product_action_lease_v1(
    v_old.device_id, v_old.request_id, v_old.effect_id,
    v_old.attempt_id, v_old.lease_id, v_old.execution_epoch,
    v_old.agent_instance_id, v_old.boot_id, 120);
  if v_until is null or v_until < pg_catalog.clock_timestamp() + interval '110 seconds' then
    raise exception 'lease_postflight_running_grace_renewal_failed';
  end if;

  -- After retirement, even the original agent must not revive the lease.
  update private.ordax_product_action_requests
     set lease_expires_at = pg_catalog.clock_timestamp() - interval '7 minutes'
   where request_id = v_old.request_id;
  v_retired := private.ordax_retire_orphaned_running_product_actions_v1(
    v_old.device_id, v_old.request_id);
  if v_retired <> 1 then
    raise exception 'lease_postflight_orphan_not_retired';
  end if;
  if public.ordax_renew_product_action_lease_v1(
       v_old.device_id, v_old.request_id, v_old.effect_id,
       v_old.attempt_id, v_old.lease_id, v_old.execution_epoch,
       v_old.agent_instance_id, v_old.boot_id, 120) is not null then
    raise exception 'lease_postflight_retired_action_revived';
  end if;
  if private.ordax_retire_orphaned_running_product_actions_v1(
       v_old.device_id, v_old.request_id) <> 0 then
    raise exception 'lease_postflight_retirement_not_idempotent';
  end if;
  raise notice 'ORDAX_PRODUCT_LEASE_POSTFLIGHT_PASS';
end;
$lease_postflight$;
rollback;
