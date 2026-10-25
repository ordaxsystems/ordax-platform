-- DEVELOPMENT PROPOSAL ONLY. Never apply to canonical Supabase until
-- FOOD-001, authenticated host session, grants and deploy gates are approved.
-- A dedicated NOLOGIN executor may call only reviewed private Food operations.
-- The verified actor/selected Space MUST come from trusted server transport.
-- Any credential holder can impersonate the supplied actor: therefore DO NOT
-- grant LOGIN/membership, publish endpoints or wire this into an app.
begin;

do $preflight$
begin
  if to_regclass('private.ordax_food_space_state') is null
    or to_regclass('private.ordax_food_command_journal') is null
    or to_regprocedure('private.ordax_food_action_eligible_v1(uuid,uuid,text)') is null
    or exists (select 1 from pg_catalog.pg_roles where rolname='ordax_food_executor')
    or to_regprocedure('private.ordax_food_verify_action_v1(uuid,uuid,text)') is not null
    or to_regprocedure('private.ordax_food_read_state_v1(uuid,uuid,text)') is not null
    or to_regprocedure('private.ordax_food_find_command_v1(uuid,uuid,text,text)') is not null
    or to_regprocedure('private.ordax_food_commit_order_v1(uuid,uuid,text,text,text,bigint,jsonb,text,text)') is not null
  then raise exception 'food_executor_proposal_preflight_failed'; end if;
end;
$preflight$;

create role ordax_food_executor nologin noinherit nobypassrls
  nosuperuser nocreatedb nocreaterole noreplication;

revoke all on schema public from ordax_food_executor;
revoke all on schema private from ordax_food_executor;

-- A reviewer may only grant membership to a separately authenticated
-- server-side LOGIN role after an approved host binding. No LOGIN here.
grant usage on schema private to ordax_food_executor;

-- The policy itself stays private. The narrow resolver can only return one
-- boolean for an authenticated actor/Space/action supplied by a trusted host.
-- It is not a replacement for validating the transport/session.
create function private.ordax_food_verify_action_v1(
  p_actor uuid, p_space uuid, p_action text
) returns boolean
language sql volatile security definer set search_path = ''
as $fn$
  select coalesce(
    private.ordax_food_action_eligible_v1(p_actor,p_space,p_action),
    false
  );
$fn$;

-- Caller keeps its own SERIALIZABLE transaction open throughout domain
-- application. The row lock survives until COMMIT/ROLLBACK on that connection.
create function private.ordax_food_read_state_v1(
  p_actor uuid, p_space uuid, p_action text
) returns table(revision bigint, document jsonb)
language plpgsql volatile security definer set search_path = ''
as $fn$
begin
  if private.ordax_food_action_eligible_v1(p_actor,p_space,p_action) is not true
  then raise exception 'food_action_denied' using errcode='42501'; end if;
  return query
    select s.revision, s.document
    from private.ordax_food_space_state s
    where s.space_id=p_space
    for update;
end;
$fn$;

-- Always reauthorizes, even on an exact receipt replay. It returns no rows
-- when there is no command, not a cross-Space negative lookup oracle.
create function private.ordax_food_find_command_v1(
  p_actor uuid, p_space uuid, p_action text, p_command text
) returns table(space_id uuid, command_id text, digest text, receipt jsonb)
language plpgsql volatile security definer set search_path = ''
as $fn$
begin
  if p_command is null
     or pg_catalog.char_length(p_command) not between 1 and 160
     or p_command !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
  then raise exception 'food_command_invalid' using errcode='22023'; end if;
  if private.ordax_food_action_eligible_v1(p_actor,p_space,p_action) is not true
  then raise exception 'food_action_denied' using errcode='42501'; end if;
  -- Serialize receipt lookup with state mutations in this Space.
  perform 1 from private.ordax_food_space_state
    where private.ordax_food_space_state.space_id=p_space for update;
  return query
    select j.space_id,j.command_id,j.digest,j.receipt
    from private.ordax_food_command_journal j
    where j.space_id=p_space and j.command_id=p_command;
end;
$fn$;

-- Neither the web role nor this executor can directly update private tables.
-- This reviewed write must execute inside the *same* transaction as the
-- current authorised read, domain callback and replay check.
create function private.ordax_food_commit_order_v1(
  p_actor uuid, p_space uuid, p_action text, p_command text,
  p_digest text, p_expected_revision bigint, p_document jsonb,
  p_order text, p_status text
) returns jsonb
language plpgsql volatile security definer set search_path = ''
as $fn$
declare
  v_revision bigint;
  v_commit uuid;
  v_receipt jsonb;
begin
  if p_action not in ('order.create','order.transition')
    or private.ordax_food_action_eligible_v1(p_actor,p_space,p_action) is not true
  then raise exception 'food_action_denied' using errcode='42501'; end if;
  if p_expected_revision is null or p_expected_revision < 0
    or p_expected_revision = 9223372036854775807
    or p_command is null
    or pg_catalog.char_length(p_command) not between 1 and 160
    or p_command !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    or p_digest is null or p_digest !~ '^[0-9a-f]{64}$'
    or p_order is null
    or pg_catalog.char_length(p_order) not between 1 and 160
    or p_order !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    or p_status is null or p_status !~ '^[a-z][a-z_-]{0,31}$'
    or p_document is null or pg_catalog.jsonb_typeof(p_document) <> 'object'
    or (p_document->>'revision')::bigint
          is distinct from p_expected_revision + 1
  then raise exception 'food_command_invalid' using errcode='22023'; end if;

  update private.ordax_food_space_state s
    set revision=p_expected_revision + 1, document=p_document,
        updated_at=pg_catalog.clock_timestamp()
    where s.space_id=p_space and s.revision=p_expected_revision
    returning s.revision into v_revision;
  if v_revision is null then
    raise exception 'food_revision_conflict' using errcode='40001';
  end if;

  v_commit := pg_catalog.gen_random_uuid();
  v_receipt := pg_catalog.jsonb_build_object(
    'schema','ordax.food-order-commit-receipt/1',
    'spaceId',p_space::text,
    'commandId',p_command,
    'orderId',p_order,
    'status',p_status,
    'revision',v_revision,
    'commitId',v_commit::text
  );
  insert into private.ordax_food_command_journal(
    space_id,command_id,digest,actor_user_id,order_id,status,
    revision,commit_id,receipt
  ) values(
    p_space,p_command,p_digest,p_actor,p_order,p_status,
    v_revision,v_commit,v_receipt
  );
  return v_receipt;
end;
$fn$;

-- Fail-closed default EXECUTE on all new routines, regardless of cluster
-- default privileges. This role cannot run the private policy directly.
revoke all on function private.ordax_food_verify_action_v1(uuid,uuid,text)
  from public,anon,authenticated,service_role,ordax_edge_executor,ordax_edge_runtime;
revoke all on function private.ordax_food_read_state_v1(uuid,uuid,text)
  from public,anon,authenticated,service_role,ordax_edge_executor,ordax_edge_runtime;
revoke all on function private.ordax_food_find_command_v1(uuid,uuid,text,text)
  from public,anon,authenticated,service_role,ordax_edge_executor,ordax_edge_runtime;
revoke all on function private.ordax_food_commit_order_v1(uuid,uuid,text,text,text,bigint,jsonb,text,text)
  from public,anon,authenticated,service_role,ordax_edge_executor,ordax_edge_runtime;

grant execute on function private.ordax_food_verify_action_v1(uuid,uuid,text)
  to ordax_food_executor;
grant execute on function private.ordax_food_read_state_v1(uuid,uuid,text)
  to ordax_food_executor;
grant execute on function private.ordax_food_find_command_v1(uuid,uuid,text,text)
  to ordax_food_executor;
grant execute on function private.ordax_food_commit_order_v1(uuid,uuid,text,text,text,bigint,jsonb,text,text)
  to ordax_food_executor;

commit;