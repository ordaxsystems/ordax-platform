-- Run exclusively in the isolated CI database after fixture and proposal.
\set ON_ERROR_STOP on
begin;
do $proof$
declare
  v_space uuid := '11111111-1111-4111-8111-111111111111';
  v_other uuid := '22222222-2222-4222-8222-222222222222';
  v_archived uuid := '33333333-3333-4333-8333-333333333333';
  v_retail uuid := '44444444-4444-4444-8444-444444444444';
  v_failures integer;
  v_actor uuid;
  v_oid regprocedure := 'private.ordax_food_action_eligible_v1(uuid,uuid,text)'::regprocedure;
  v_role text;
begin
  if not exists (
    select 1 from pg_catalog.pg_proc p
    where p.oid=v_oid
      and not p.prosecdef
      and p.proconfig @> array['search_path=""']
  ) then
    raise exception 'food_action_policy_must_be_security_invoker';
  end if;

  foreach v_role in array array[
    'anon','authenticated','service_role',
    'ordax_edge_executor','ordax_edge_runtime'
  ] loop
    if pg_catalog.has_function_privilege(v_role,v_oid,'EXECUTE') then
      raise exception 'food_action_policy_public_execute: %',v_role;
    end if;
  end loop;

  -- Cases are independent: role and Space are checked by the canonical
  -- private helper on every invocation, not by app-supplied claims.
  with cases(actor,space,action,expected) as (
    values
      (1,v_space,'order.read',true),
      (1,v_space,'order.create',true),
      (1,v_space,'order.transition',true),
      (2,v_space,'order.read',true),
      (2,v_space,'order.create',true),
      (2,v_space,'order.transition',true),
      (3,v_space,'order.read',true),
      (3,v_space,'order.create',false),
      (3,v_space,'order.transition',false),
      (4,v_space,'order.read',true),
      (4,v_space,'order.create',false),
      (4,v_space,'order.transition',false),
      (5,v_space,'order.create',false),
      (5,v_space,'order.read',false),
      (6,v_space,'order.create',false),
      (6,v_space,'order.read',false),
      (7,v_space,'order.create',false),
      (8,v_space,'order.read',false),
      (2,v_other,'order.create',false),
      (1,v_other,'order.read',false),
      (1,v_archived,'order.create',false),
      (1,v_retail,'order.create',false),
      (1,v_space,'order.delete',false),
      (1,v_space,'orders.read',false),
      (1,v_space,'',false),
      (1,v_space,null::text,false)
  )
  select count(*) into v_failures from cases c
  where private.ordax_food_action_eligible_v1(
    (lpad(to_hex(c.actor),8,'0') ||
      '-0000-4000-8000-000000000000')::uuid,
    c.space,c.action
  ) is distinct from c.expected;
  if v_failures <> 0 then
    raise exception 'food_role_matrix_failed_cases: %',v_failures;
  end if;

  if private.ordax_food_action_eligible_v1(null,v_space,'order.read')
     or private.ordax_food_action_eligible_v1(
       '00000001-0000-4000-8000-000000000000',null,'order.read')
  then raise exception 'food_null_identity_was_allowed'; end if;

  -- Membership revocation is visible immediately on the next check.
  update public.ordax_space_members
    set state='suspended' where space_id=v_space
      and user_id='00000002-0000-4000-8000-000000000000';
  if private.ordax_food_action_eligible_v1(
    '00000002-0000-4000-8000-000000000000',v_space,'order.create')
  then raise exception 'food_suspended_admin_allowed'; end if;

  -- A deleted/suspended Auth subject is never saved by an old Space role.
  update auth.users set deleted_at=pg_catalog.clock_timestamp()
    where id='00000003-0000-4000-8000-000000000000';
  if private.ordax_food_action_eligible_v1(
    '00000003-0000-4000-8000-000000000000',v_space,'order.read')
  then raise exception 'food_deleted_member_allowed'; end if;

  -- Only the canonical active, typed Space can accept orders.
  update public.ordax_spaces set state='archived' where space_id=v_space;
  if private.ordax_food_action_eligible_v1(
    '00000001-0000-4000-8000-000000000000',v_space,'order.create')
  then raise exception 'food_archived_owner_allowed'; end if;
end;
$proof$;
rollback;
