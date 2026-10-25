-- Runs ONLY against an isolated PostgreSQL fixture. Never on a live project.
\set ON_ERROR_STOP on
begin;

do $verify$
declare
  v_name text;
  v_role text;
  v_relation regclass;
begin
  foreach v_name in array array[
    'private.ordax_food_space_state', 'private.ordax_food_command_journal'
  ] loop
    v_relation := to_regclass(v_name);
    if v_relation is null
       or not exists (
          select 1 from pg_catalog.pg_class
          where oid = v_relation::oid
            and relrowsecurity and relforcerowsecurity
       ) then
      raise exception 'food_rls_missing_or_not_forced: %', v_name;
    end if;
    foreach v_role in array array[
      'anon','authenticated','service_role',
      'ordax_edge_executor','ordax_edge_runtime'
    ] loop
      if pg_catalog.has_table_privilege(v_role,v_relation,'SELECT')
        or pg_catalog.has_table_privilege(v_role,v_relation,'INSERT')
        or pg_catalog.has_table_privilege(v_role,v_relation,'UPDATE')
        or pg_catalog.has_table_privilege(v_role,v_relation,'DELETE') then
        raise exception 'food_table_exposed_to_%: %',v_role,v_name;
      end if;
    end loop;
  end loop;

  if to_regprocedure('public.ordax_food_commit_order_v1(uuid,text,jsonb)') is not null
     or to_regprocedure('private.ordax_food_commit_order_v1(uuid,text,jsonb)') is not null then
    raise exception 'food_public_rpc_must_not_exist_before_authorized_owner';
  end if;
end;
$verify$;

insert into public.ordax_spaces(space_id)
values ('11111111-1111-4111-8111-111111111111'::uuid),
       ('22222222-2222-4222-8222-222222222222'::uuid);
insert into public.ordax_accounts(user_id)
values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid);

insert into private.ordax_food_space_state(space_id,revision,document)
values
('11111111-1111-4111-8111-111111111111',0,
 '{"schema":"ordax.food-pizzeria-state/6","revision":0}'::jsonb),
('22222222-2222-4222-8222-222222222222',0,
 '{"schema":"ordax.food-pizzeria-state/6","revision":0}'::jsonb);

do $checks$
declare
  v_space uuid := '11111111-1111-4111-8111-111111111111'::uuid;
  v_commit uuid := '33333333-3333-4333-8333-333333333333'::uuid;
  v_actor uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid;
  v_receipt jsonb;
begin
  v_receipt := pg_catalog.jsonb_build_object(
    'schema','ordax.food-order-commit-receipt/1',
    'spaceId',v_space::text,
    'commandId','order-command-ci',
    'orderId','food-order-ci',
    'status','received',
    'revision',1,
    'commitId',v_commit::text
  );
  insert into private.ordax_food_command_journal(
    space_id,command_id,digest,actor_user_id,
    order_id,status,revision,commit_id,receipt
  ) values(
    v_space,'order-command-ci',repeat('a',64),v_actor,
    'food-order-ci','received',1,v_commit,v_receipt
  );
  if not exists (
    select 1 from private.ordax_food_command_journal j
    where j.space_id=v_space and j.command_id='order-command-ci'
      and j.receipt=v_receipt
  ) then raise exception 'food_receipt_not_persisted'; end if;

  begin
    insert into private.ordax_food_command_journal(
      space_id,command_id,digest,actor_user_id,
      order_id,status,revision,commit_id,receipt
    ) values(v_space,'order-command-ci',repeat('b',64),v_actor,
      'food-order-ci','received',1,v_commit,v_receipt);
    raise exception 'food_duplicate_key_was_accepted';
  exception when unique_violation then null;
  end;

  begin
    insert into private.ordax_food_command_journal(
      space_id,command_id,digest,actor_user_id,
      order_id,status,revision,commit_id,receipt
    ) values('22222222-2222-4222-8222-222222222222','wrong-space',
      repeat('a',64),v_actor,'food-order-ci','received',1,v_commit,v_receipt);
    raise exception 'food_cross_space_receipt_was_accepted';
  exception when check_violation then null;
  end;

  begin
    update private.ordax_food_space_state
      set revision=1,
          document='{"schema":"ordax.food-pizzeria-state/6","revision":0}'
    where space_id=v_space;
    raise exception 'food_revision_mismatch_was_accepted';
  exception when check_violation then null;
  end;
end;
$checks$;

rollback;
