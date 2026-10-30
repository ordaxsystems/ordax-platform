-- Safe live-db verification: temporarily modify one historical completed action
-- only inside a transaction that is always rolled back.
begin;
do $postflight$
declare
  v_old private.ordax_product_action_requests%rowtype;
  v_get jsonb;
  v_report jsonb;
  v_row private.ordax_product_action_requests%rowtype;
begin
  if pg_catalog.to_regprocedure(
     'private.ordax_retire_orphaned_running_product_actions_v1(uuid,uuid)') is null then
    raise exception 'orphan_running_helper_missing';
  end if;
  if pg_catalog.has_function_privilege('anon',
       'private.ordax_retire_orphaned_running_product_actions_v1(uuid,uuid)'::regprocedure,
       'execute')
    or pg_catalog.has_function_privilege('authenticated',
       'private.ordax_retire_orphaned_running_product_actions_v1(uuid,uuid)'::regprocedure,
       'execute')
    or pg_catalog.has_function_privilege('ordax_edge_executor',
       'private.ordax_retire_orphaned_running_product_actions_v1(uuid,uuid)'::regprocedure,
       'execute') then
    raise exception 'orphan_running_helper_exposed';
  end if;
  select * into v_old
    from private.ordax_product_action_requests r
   where r.status='succeeded' and r.report_id is not null
     and r.result is not null and r.lease_id is not null
     and r.attempt_id is not null and r.agent_instance_id is not null
     and r.client_kind='product-mcp' and r.client_id is not null
   order by r.finished_at desc
   limit 1 for update;
  if not found then
    raise notice 'No historical completed action for safe rollback fixture';
    return;
  end if;
  update private.ordax_product_action_requests
     set status='running', report_id=null, result=null,
         result_sha256=null, error_code=null, finished_at=null,
         lease_expires_at=pg_catalog.clock_timestamp()-interval '7 minutes'
   where request_id=v_old.request_id;

  -- The request's original OAuth client must be verified before mutation.
  if public.ordax_get_product_action_v1(
    v_old.owner_user_id,v_old.client_kind,v_old.client_id||'-foreign',v_old.request_id
  ) is not null then raise exception 'orphan_running_cross_client_read'; end if;

  v_get:=public.ordax_get_product_action_v1(
    v_old.owner_user_id,v_old.client_kind,v_old.client_id,v_old.request_id);
  if v_get->>'status' <> 'failed'
     or v_get->>'error_code' <> 'execution_outcome_unconfirmed' then
    raise exception 'orphan_running_not_retired';
  end if;
  select * into v_row from private.ordax_product_action_requests
   where request_id=v_old.request_id;
  if v_row.execution_epoch<>v_old.execution_epoch
     or v_row.lease_id is distinct from v_old.lease_id
     or v_row.attempt_id is distinct from v_old.attempt_id
     or v_row.agent_instance_id is distinct from v_old.agent_instance_id
     or v_row.report_id is not null
     or v_row.lease_expires_at is not null then
    raise exception 'orphan_running_fencing_provenance_changed';
  end if;

  -- Late reports are permitted ONLY from the identical fenced execution.
  v_report:=public.ordax_report_product_action_v1(
    v_old.device_id,v_old.request_id,v_old.effect_id,
    extensions.gen_random_uuid(),v_old.lease_id,v_old.execution_epoch,
    v_old.agent_instance_id,v_old.boot_id,v_old.report_id,
    v_old.status,v_old.result,v_old.result_sha256,v_old.error_code);
  if v_report->>'ok'<>'false' then
    raise exception 'orphan_running_wrong_attempt_accepted';
  end if;

  v_report:=public.ordax_report_product_action_v1(
    v_old.device_id,v_old.request_id,v_old.effect_id,v_old.attempt_id,
    v_old.lease_id,v_old.execution_epoch,v_old.agent_instance_id,
    v_old.boot_id,v_old.report_id,v_old.status,v_old.result,
    v_old.result_sha256,v_old.error_code);
  if v_report->>'ok'<>'true' or v_report->>'replayed'<>'false' then
    raise exception 'orphan_running_legitimate_late_report_denied';
  end if;
  v_report:=public.ordax_report_product_action_v1(
    v_old.device_id,v_old.request_id,v_old.effect_id,v_old.attempt_id,
    v_old.lease_id,v_old.execution_epoch,v_old.agent_instance_id,
    v_old.boot_id,v_old.report_id,v_old.status,v_old.result,
    v_old.result_sha256,v_old.error_code);
  if v_report->>'ok'<>'true' or v_report->>'replayed'<>'true' then
    raise exception 'orphan_running_late_report_not_idempotent';
  end if;

  -- Do not retire a live operation on a mere short network outage.
  update private.ordax_product_action_requests
     set status='running', report_id=null, result=null,
         result_sha256=null, error_code=null, finished_at=null,
         lease_expires_at=pg_catalog.clock_timestamp()-interval '1 minute'
   where request_id=v_old.request_id;
  v_get:=public.ordax_get_product_action_v1(
    v_old.owner_user_id,v_old.client_kind,v_old.client_id,v_old.request_id);
  if v_get->>'status'<>'running' then
    raise exception 'orphan_running_lease_grace_violated';
  end if;
  raise notice 'ORPHAN_RUNNING_LEASE_ROLLBACK_PASS';
end;
$postflight$;
rollback;
