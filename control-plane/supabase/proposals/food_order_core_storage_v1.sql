-- REVIEW-ONLY PROPOSAL: NOT APPLIED AND NOT A CANONICAL MIGRATION.
-- FOOD-001 is deferred. The migration registry must not be changed or any SQL
-- executed against the live project until the canonical Food data owner and
-- per-action authorization owner approve the rollout.
--
-- This is a private, inaccessible durability primitive for the existing
-- ordax.food-pizzeria-state/6 domain. Not a second Sales book or Inventory.
-- CHECK boolean predicates use IS TRUE because PostgreSQL treats UNKNOWN as
-- successful CHECK; missing JSON keys must never pass the integrity boundary.
-- Atomicity/CAS and idempotency are provided by the owner transaction adapter,
-- and authorization is enforced inside that same backend transaction.
begin;

do $preflight$
begin
  if to_regclass('public.ordax_spaces') is null
    or to_regclass('public.ordax_accounts') is null
    or to_regclass('private.ordax_food_space_state') is not null
    or to_regclass('private.ordax_food_command_journal') is not null
  then
    raise exception 'food_order_storage_owner_preflight_failed';
  end if;
end;
$preflight$;

create table private.ordax_food_space_state (
  space_id uuid primary key
    references public.ordax_spaces(space_id) on delete restrict,
  revision bigint not null check (revision >= 0),
  document jsonb not null
    check ((jsonb_typeof(document) = 'object'
      and document->>'schema' = 'ordax.food-pizzeria-state/6'
      and (document->>'revision')::bigint = revision) is true),
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  updated_at timestamptz not null default pg_catalog.clock_timestamp()
);

-- A single idempotency ledger per Space + command, NOT per device/channel.
-- The future server adapter inserts this entry and updates the state within
-- ONE serializable transaction, both guarded by the authorized Space row.
create table private.ordax_food_command_journal (
  space_id uuid not null references
    private.ordax_food_space_state(space_id) on delete restrict,
  command_id text not null check (
    char_length(command_id) between 1 and 160
    and command_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
  ),
  digest text not null check (digest ~ '^[0-9a-f]{64}$'),
  actor_user_id uuid not null references
    public.ordax_accounts(user_id) on delete restrict,
  order_id text not null check (
    char_length(order_id) between 1 and 160
    and order_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
  ),
  status text not null check (status ~ '^[a-z][a-z_-]{0,31}$'),
  revision bigint not null check (revision >= 1),
  commit_id uuid not null default pg_catalog.gen_random_uuid(),
  receipt jsonb not null check ((
    jsonb_typeof(receipt) = 'object'
    and receipt->>'schema' = 'ordax.food-order-commit-receipt/1'
    and receipt->>'spaceId' = space_id::text
    and receipt->>'commandId' = command_id
    and receipt->>'orderId' = order_id
    and receipt->>'status' = status
    and (receipt->>'revision')::bigint = revision
    and receipt->>'commitId' = commit_id::text
  ) is true),
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  primary key(space_id, command_id),
  unique(space_id, commit_id)
);

-- This proposed base is intentionally NOT a callable Food API. The Data API,
-- browser roles, remote MCP executor and generic service_role cannot access
-- either table. No permissive RLS policy or SECURITY DEFINER RPC is introduced.
alter table private.ordax_food_space_state enable row level security;
alter table private.ordax_food_space_state force row level security;
alter table private.ordax_food_command_journal enable row level security;
alter table private.ordax_food_command_journal force row level security;

revoke all on table private.ordax_food_space_state
  from public, anon, authenticated, service_role,
       ordax_edge_executor, ordax_edge_runtime;
revoke all on table private.ordax_food_command_journal
  from public, anon, authenticated, service_role,
       ordax_edge_executor, ordax_edge_runtime;

commit;
