-- Isolated PostgreSQL 17 integration proof only; NEVER run on canonical Supabase.
-- Execute AFTER food_action_policy_fixture.sql and BOTH private Food proposals
-- have been installed in a fresh ephemeral database.
-- This proves the SQL policy + durability contract together, NOT the JS
-- Food domain, trusted network transport or a production executor role.
\set ON_ERROR_STOP on

insert into private.ordax_food_space_state(space_id,revision,document)
values
  ('11111111-1111-4111-8111-111111111111',0,
   '{"schema":"ordax.food-pizzeria-state/6","revision":0}'::jsonb),
  ('22222222-2222-4222-8222-222222222222',0,
   '{"schema":"ordax.food-pizzeria-state/6","revision":0}'::jsonb);

-- One connection, one serializable transaction, a live permission decision,
-- CAS mutation and the durable receipt. PostgreSQL creates the commit UUID.
begin isolation level serializable;
do $commit$
declare
  v_space uuid := '11111111-1111-4111-8111-111111111111';
  v_admin uuid := '00000002-0000-4000-8000-000000000000';
  v_revision bigint;
  v_updated bigint;
  v_commit uuid := pg_catalog.gen_random_uuid();
  v_receipt jsonb;
begin
  if private.ordax_food_action_eligible_v1(
    v_admin,v_space,'order.create') is not true then
    raise exception 'food_integrated_authorization_denied_valid_admin';
  end if;

  select revision into strict v_revision
  from private.ordax_food_space_state
  where space_id=v_space
  for update;
  if v_revision <> 0 then
    raise exception 'food_integrated_initial_revision_not_zero';
  end if;

  update private.ordax_food_space_state
  set revision=1,
      document='{"schema":"ordax.food-pizzeria-state/6","revision":1}'::jsonb,
      updated_at=pg_catalog.clock_timestamp()
  where space_id=v_space and revision=v_revision
  returning revision into v_updated;
  if v_updated <> 1 then
    raise exception 'food_integrated_cas_update_failed';
  end if;

  -- Do not mint a receipt in the client. It shares the journal commit token.
  v_receipt := pg_catalog.jsonb_build_object(
    'schema','ordax.food-order-commit-receipt/1',
    'spaceId',v_space::text,
    'commandId','food-integrated-create-1',
    'orderId','food-integrated-order-1',
    'status','received',
    'revision',v_updated,
    'commitId',v_commit::text
  );
  insert into private.ordax_food_command_journal(
    space_id,command_id,digest,actor_user_id,
    order_id,status,revision,commit_id,receipt
  ) values (
    v_space,'food-integrated-create-1',repeat('a',64),v_admin,
    'food-integrated-order-1','received',v_updated,v_commit,v_receipt
  );
end;
$commit$;
commit;

do $integrity$
declare
  v_space uuid := '11111111-1111-4111-8111-111111111111';
  v_other uuid := '22222222-2222-4222-8222-222222222222';
  v_admin uuid := '00000002-0000-4000-8000-000000000000';
  v_viewer uuid := '00000004-0000-4000-8000-000000000000';
  v_receipt jsonb;
  v_digest text;
  v_revision bigint;
  v_commit uuid;
  v_changed integer;
begin
  select j.receipt,j.digest,j.commit_id
    into strict v_receipt,v_digest,v_commit
  from private.ordax_food_command_journal j
  where j.space_id=v_space and j.command_id='food-integrated-create-1';

  if v_digest <> repeat('a',64)
    or v_receipt->>'commitId' <> v_commit::text
    or (v_receipt->>'revision')::integer <> 1
    or v_receipt->>'spaceId' <> v_space::text
  then raise exception 'food_integrated_receipt_corruption'; end if;

  -- Simulate reconciliation following a lost COMMIT acknowledgment: this
  -- (space_id,command_id) lookup must return exactly the previous receipt.
  if (select count(*) from private.ordax_food_command_journal
      where space_id=v_space and command_id='food-integrated-create-1'
        and digest=repeat('a',64) and receipt=v_receipt) <> 1
  then raise exception 'food_integrated_replay_not_durable'; end if;

  -- A stale revision cannot mutate state and cannot create a receipt.
  update private.ordax_food_space_state
  set revision=2,
      document='{"schema":"ordax.food-pizzeria-state/6","revision":2}'::jsonb
  where space_id=v_space and revision=0;
  get diagnostics v_changed = row_count;
  if v_changed <> 0 then raise exception 'food_integrated_stale_cas_accepted'; end if;

  -- Missing JSON revision used to pass a plain CHECK because PostgreSQL
  -- accepts UNKNOWN. The canonical proposal must reject incomplete documents.
  begin
    update private.ordax_food_space_state
    set revision=1,
        document='{"schema":"ordax.food-pizzeria-state/6"}'::jsonb
    where space_id=v_other and revision=0;
    raise exception 'food_integrated_incomplete_document_accepted';
  exception when check_violation then null;
  end;
  if (select revision from private.ordax_food_space_state
      where space_id=v_other) <> 0
  then raise exception 'food_integrated_invalid_document_changed_other_space'; end if;

  -- A receipt with matching visible identifiers but NO commitId must fail,
  -- not silently pass via SQL three-valued CHECK logic.
  begin
    insert into private.ordax_food_command_journal(
      space_id,command_id,digest,actor_user_id,
      order_id,status,revision,receipt
    ) values (
      v_space,'food-missing-commit',repeat('d',64),v_admin,
      'food-integrated-order-1','received',1,
      pg_catalog.jsonb_build_object(
        'schema','ordax.food-order-commit-receipt/1',
        'spaceId',v_space::text,
        'commandId','food-missing-commit',
        'orderId','food-integrated-order-1',
        'status','received',
        'revision',1
      )
    );
    raise exception 'food_integrated_incomplete_receipt_accepted';
  exception when check_violation then null;
  end;

  -- Same command ID with a different digest must never create a second row.
  begin
    insert into private.ordax_food_command_journal(
      space_id,command_id,digest,actor_user_id,
      order_id,status,revision,commit_id,receipt
    ) values (
      v_space,'food-integrated-create-1',repeat('b',64),v_admin,
      'food-integrated-order-1','received',1,v_commit,v_receipt
    );
    raise exception 'food_integrated_duplicate_command_accepted';
  exception when unique_violation then null;
  end;

  -- PostgreSQL subtransaction rolls back the state update if the following
  -- receipt is invalid: no committed partial state and no new command row.
  begin
    update private.ordax_food_space_state
      set revision=2,
          document='{"schema":"ordax.food-pizzeria-state/6","revision":2}'::jsonb
    where space_id=v_space and revision=1;
    insert into private.ordax_food_command_journal(
      space_id,command_id,digest,actor_user_id,
      order_id,status,revision,receipt
    ) values (
      v_space,'food-invalid-receipt',repeat('c',64),v_admin,
      'food-integrated-order-1','received',2,'{}'::jsonb
    );
    raise exception 'food_integrated_invalid_receipt_accepted';
  exception when check_violation then null;
  end;

  select revision into strict v_revision
  from private.ordax_food_space_state where space_id=v_space;
  if v_revision <> 1 or exists (
    select 1 from private.ordax_food_command_journal
    where space_id=v_space and command_id='food-invalid-receipt'
  ) then raise exception 'food_integrated_failed_commit_left_partial_state'; end if;

  -- Same DB contains two independent Spaces. Neither state nor command can
  -- migrate to a different Space when the caller has only Space A rights.
  if private.ordax_food_action_eligible_v1(
    v_admin,v_other,'order.create') is not false
  then raise exception 'food_integrated_cross_space_allowed'; end if;
  if private.ordax_food_action_eligible_v1(
    v_viewer,v_space,'order.create') is not false
  then raise exception 'food_integrated_viewer_can_write'; end if;
  if private.ordax_food_action_eligible_v1(
    v_viewer,v_space,'order.read') is not true
  then raise exception 'food_integrated_viewer_cannot_read'; end if;
  if exists (
    select 1 from private.ordax_food_command_journal where space_id=v_other
  ) or (select revision from private.ordax_food_space_state
        where space_id=v_other) <> 0
  then raise exception 'food_integrated_other_space_modified'; end if;
end;
$integrity$;

-- Revocation changes the permission result without changing committed order
-- history. Same-transaction row locks are handled by the SQL policy.
update public.ordax_space_members
set state='suspended'
where space_id='11111111-1111-4111-8111-111111111111'
  and user_id='00000002-0000-4000-8000-000000000000';

do $revoked$
begin
  if private.ordax_food_action_eligible_v1(
    '00000002-0000-4000-8000-000000000000',
    '11111111-1111-4111-8111-111111111111',
    'order.create') is not false
  then raise exception 'food_integrated_revoked_admin_still_authorized'; end if;
  if (select count(*) from private.ordax_food_command_journal) <> 1
    or (select revision from private.ordax_food_space_state
        where space_id='11111111-1111-4111-8111-111111111111') <> 1
  then raise exception 'food_integrated_revocation_damaged_durable_history'; end if;
end;
$revoked$;

-- Defense in depth: no direct client, service_role or MCP executor DML, and
-- no public SQL execution privilege for the private policy resolver.
do $acl$
declare
  v_role text;
  v_table regclass;
  v_policy regprocedure :=
    'private.ordax_food_action_eligible_v1(uuid,uuid,text)'::regprocedure;
begin
  foreach v_role in array array[
    'anon','authenticated','service_role',
    'ordax_edge_executor','ordax_edge_runtime'
  ] loop
    foreach v_table in array array[
      'private.ordax_food_space_state'::regclass,
      'private.ordax_food_command_journal'::regclass
    ] loop
      if pg_catalog.has_table_privilege(v_role,v_table,'SELECT')
        or pg_catalog.has_table_privilege(v_role,v_table,'INSERT')
        or pg_catalog.has_table_privilege(v_role,v_table,'UPDATE')
        or pg_catalog.has_table_privilege(v_role,v_table,'DELETE')
      then raise exception 'food_integrated_table_access_leak: % %',
        v_role,v_table; end if;
    end loop;
    if pg_catalog.has_function_privilege(v_role,v_policy,'EXECUTE')
    then raise exception 'food_integrated_policy_execution_leak: %',v_role; end if;
  end loop;
end;
$acl$;
