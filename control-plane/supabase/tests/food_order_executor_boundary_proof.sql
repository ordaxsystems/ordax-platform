-- In a disposable PostgreSQL 17 fixture, after Identity fixture, Food policy,
-- Food storage and Food executor SQL proposal. Never use in production.
\set ON_ERROR_STOP on

insert into private.ordax_food_space_state(space_id,revision,document)
values
('11111111-1111-4111-8111-111111111111',0,'{"schema":"ordax.food-pizzeria-state/6","revision":0}'),
('22222222-2222-4222-8222-222222222222',0,'{"schema":"ordax.food-pizzeria-state/6","revision":0}');

do $guard$
declare
  v_role text;
  v_priv boolean;
  v_name text;
begin
  if exists (select 1 from pg_catalog.pg_roles
             where rolname='ordax_food_executor'
             and (rolcanlogin or rolsuper or rolbypassrls or rolinherit)) then
    raise exception 'food_executor_must_be_nologin_noninheriting_without_bypass';
  end if;
  foreach v_name in array array[
    'private.ordax_food_space_state',
    'private.ordax_food_command_journal'
  ] loop
    foreach v_priv in array array[true,false] loop
      if pg_catalog.has_table_privilege('ordax_food_executor',v_name,
          case when v_priv then 'SELECT' else 'UPDATE' end) then
        raise exception 'food_executor_direct_privilege_leaked_%',v_name;
      end if;
    end loop;
  end loop;
  if pg_catalog.has_function_privilege('ordax_food_executor',
       'private.ordax_food_action_eligible_v1(uuid,uuid,text)','EXECUTE')
    or pg_catalog.has_table_privilege('ordax_food_executor',
       'auth.users','SELECT')
    or pg_catalog.has_table_privilege('ordax_food_executor',
       'public.ordax_space_members','SELECT')
    or pg_catalog.has_table_privilege('ordax_food_executor',
       'public.ordax_spaces','SELECT')
  then raise exception 'food_executor_inherited_identity_or_policy_access'; end if;

  foreach v_role in array array[
    'anon','authenticated','service_role','ordax_edge_executor','ordax_edge_runtime'
  ] loop
    if pg_catalog.has_function_privilege(v_role,
        'private.ordax_food_verify_action_v1(uuid,uuid,text)','EXECUTE')
       or pg_catalog.has_function_privilege(v_role,
        'private.ordax_food_read_state_v1(uuid,uuid,text)','EXECUTE')
       or pg_catalog.has_function_privilege(v_role,
        'private.ordax_food_find_command_v1(uuid,uuid,text,text)','EXECUTE')
       or pg_catalog.has_function_privilege(v_role,
        'private.ordax_food_commit_order_v1(uuid,uuid,text,text,text,bigint,jsonb,text,text)','EXECUTE')
    then raise exception 'food_executor_rpc_leaked_to_%',v_role; end if;
  end loop;
end;
$guard$;

set role ordax_food_executor;

do $functional$
declare
  v_space uuid := '11111111-1111-4111-8111-111111111111';
  v_other uuid := '22222222-2222-4222-8222-222222222222';
  v_admin uuid := '00000002-0000-4000-8000-000000000000';
  v_viewer uuid := '00000004-0000-4000-8000-000000000000';
  v_rev bigint;
  v_doc jsonb;
  v_receipt jsonb;
  v_found integer;
begin
  if not private.ordax_food_verify_action_v1(v_admin,v_space,'order.create')
    or private.ordax_food_verify_action_v1(v_viewer,v_space,'order.create')
    or not private.ordax_food_verify_action_v1(v_viewer,v_space,'order.read')
    or private.ordax_food_verify_action_v1(v_admin,v_other,'order.read')
    or private.ordax_food_verify_action_v1(v_admin,v_space,'other.action')
  then raise exception 'food_executor_policy_matrix_failure'; end if;

  -- Role can call only the narrow SECURITY DEFINER operations. No direct
  -- access to the tables or canonical Identity.
  begin
    perform 1 from private.ordax_food_space_state where space_id=v_space;
    raise exception 'food_executor_direct_select_worked';
  exception when insufficient_privilege then null; end;
  begin
    perform 1 from public.ordax_space_members;
    raise exception 'food_executor_direct_membership_select_worked';
  exception when insufficient_privilege then null; end;

  select r.revision,r.document into v_rev,v_doc
    from private.ordax_food_read_state_v1(
      v_admin,v_space,'order.create') r;
  if v_rev <> 0 then raise exception 'food_executor_state_read_wrong'; end if;

  v_doc := '{"schema":"ordax.food-pizzeria-state/6","revision":1}'::jsonb;
  v_receipt := private.ordax_food_commit_order_v1(
    v_admin,v_space,'order.create','food-ci-command-1',
    repeat('a',64),0,v_doc,'food-ci-order-1','received'
  );
  if v_receipt->>'schema'<>'ordax.food-order-commit-receipt/1'
    or v_receipt->>'spaceId'<>v_space::text
    or v_receipt->>'commandId'<>'food-ci-command-1'
    or v_receipt->>'status'<>'received'
    or (v_receipt->>'revision')::bigint<>1
  then raise exception 'food_executor_receipt_invalid'; end if;

  select count(*) into v_found
    from private.ordax_food_find_command_v1(
      v_admin,v_space,'order.create','food-ci-command-1') c
    where c.receipt=v_receipt and c.digest=repeat('a',64);
  if v_found<>1 then raise exception 'food_executor_replay_missing_receipt'; end if;

  -- Duplicate command rolls back its CAS in an inner subtransaction.
  begin
    perform private.ordax_food_commit_order_v1(
      v_admin,v_space,'order.create','food-ci-command-1',
      repeat('b',64),1,
      '{"schema":"ordax.food-pizzeria-state/6","revision":2}'::jsonb,
      'food-ci-order-2','received'
    );
    raise exception 'food_executor_duplicate_command_committed';
  exception when unique_violation then null; end;

  select r.revision into v_rev
    from private.ordax_food_read_state_v1(
      v_admin,v_space,'order.read') r;
  if v_rev<>1 then raise exception 'food_executor_duplicate_modified_state'; end if;

  -- Only read is allowed for viewer; no mutation under an alternate action.
  begin
    perform private.ordax_food_commit_order_v1(
      v_viewer,v_space,'order.create','viewer-write',repeat('b',64),1,
      '{"schema":"ordax.food-pizzeria-state/6","revision":2}'::jsonb,
      'viewer-order','received'
    );
    raise exception 'food_executor_viewer_mutated';
  exception when insufficient_privilege then null; end;

  begin
    perform 1 from private.ordax_food_read_state_v1(
      v_admin,v_other,'order.read');
    raise exception 'food_executor_cross_space_read_allowed';
  exception when insufficient_privilege then null; end;

  if exists (select 1 from private.ordax_food_find_command_v1(
      v_viewer,v_space,'order.read','unwritten'))
  then raise exception 'food_executor_missing_command_not_null'; end if;
end;
$functional$;

reset role;
update public.ordax_space_members
  set state='suspended'
  where space_id='11111111-1111-4111-8111-111111111111'
    and user_id='00000002-0000-4000-8000-000000000000';
set role ordax_food_executor;

do $revocation$
begin
  if private.ordax_food_verify_action_v1(
      '00000002-0000-4000-8000-000000000000',
      '11111111-1111-4111-8111-111111111111','order.create')
  then raise exception 'food_executor_revoked_admin_allowed'; end if;
  begin
    perform private.ordax_food_commit_order_v1(
      '00000002-0000-4000-8000-000000000000',
      '11111111-1111-4111-8111-111111111111',
      'order.transition','post-revoke',repeat('a',64),1,
      '{"schema":"ordax.food-pizzeria-state/6","revision":2}'::jsonb,
      'food-ci-order-1','preparing'
    );
    raise exception 'food_executor_revoked_admin_mutated';
  exception when insufficient_privilege then null; end;
end;
$revocation$;
reset role;

do $post$
begin
  if (select revision from private.ordax_food_space_state
      where space_id='11111111-1111-4111-8111-111111111111')<>1
    or (select revision from private.ordax_food_space_state
      where space_id='22222222-2222-4222-8222-222222222222')<>0
    or (select count(*) from private.ordax_food_command_journal)<>1
  then raise exception 'food_executor_state_or_journal_violation'; end if;
end;
$post$;
