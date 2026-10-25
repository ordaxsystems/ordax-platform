# Food Order Core — PostgreSQL storage proposal (not deployed)

Status: **REVIEW ONLY** — FOOD-001 execution is deferred. No database
mutation was performed against the canonical project.

## Ownership and why this lives here

The canonical durable PostgreSQL owner is `ordax-platform`; authoritative
Space and account keys already exist in the canonical project.
`ordax-apps/apps/food-pizzeria/src/application/food-order-core.mjs`
owns application order rules and the transaction interface. The database
must not become a second Sales/Inventory/Payments owner.

The proposed tables under `private` are:

- `ordax_food_space_state`: one guarded revision + Food domain v6 document
  per Space. This intentionally mirrors the **current domain's global
  revision/CAS contract**, not a claim of ultimate storage scalability.
  Before operational rollout, owner must decide whether the long-term
  domain should split Menu/Order/Dine-in aggregates, avoiding a full snapshot
  rewrite on every high-volume kitchen event.
- `ordax_food_command_journal`: `(space_id, command_id)` primary key,
  SHA-256 digest, actor, order/status/revision and exact durable receipt.
  Command replay must compare digest, then return the same receipt within
  the same authorized Space; journal entries cannot be evicted or rewritten.

Both tables have **RLS enabled and forced**, *zero policies* and explicit
revocations from `anon`, `authenticated`, `service_role` and existing
remote-action executor roles. There is deliberately no Food RPC,
SQL function that grants access, browser Data API endpoint or write role.

## Space-owned per-action proposal (still no operational grant)

`food_order_action_policy_v1.sql` prepares a **private, SECURITY INVOKER**
resolver over existing canonical Space/role and Auth eligibility authorities,
not a second table of grants. It accepts a server-derived subject and Space,
but has **no EXECUTE grant to any application, Data API or remote MCP role**.

| Active canonical Space role | `order.read` | `order.create` | `order.transition` |
| --- | --- | --- | --- |
| Owner | Allow | Allow | Allow |
| Active `admin` | Allow | Allow | Allow |
| Active `member` | Allow | Deny | Deny |
| Active `viewer` | Allow | Deny | Deny |
| Suspended/absent/ineligible user | Deny | Deny | Deny |

The Space must be `active`, `professional`, `food.pizzeria`. Auth
eligibility comes from the existing
`private.ordax_trusted_actor_auth_eligible_v1` helper, and canonical
Space/member rows are locked `FOR SHARE` against concurrent revocation
within the transaction. This is the strictest temporary policy that does
not invent new permissions; it does **not** yet model cashier/cook/staff
job-specific rights or approvals. Production role grants and entitlement
semantics must be signed off by the Space/Identity owner.

The Food backend must authenticate the actor independently, never accept
caller IDs as authority, and revalidate this policy inside the same
transaction before commit. No SQL grant/role for invoking it, server
transport, adapter `authorizeAction`, session-lifecycle hookup or deployed
policy is part of this proposal. This SQL alone cannot enable orders.

## Least-privilege SQL executor proposal (no deployment)

`food_order_executor_boundary_v1.sql` proposes **one NOLOGIN, NOINHERIT,
NOBYPASSRLS** role `ordax_food_executor` that owns no tables and has no
direct SELECT/INSERT/UPDATE/DELETE on any Food table, Space, member or Auth
session. Its only permissions are `USAGE` on the nonexposed `private` schema
and `EXECUTE` on four reviewed Food-only routines:

- `ordax_food_verify_action_v1`: consult the existing private action policy.
- `ordax_food_read_state_v1`: reauthorize and acquire a Space-scoped row lock.
- `ordax_food_find_command_v1`: reauthorize before reading an idempotency receipt.
- `ordax_food_commit_order_v1`: reauthorize inside the same backend
  transaction, apply CAS and create the command journal and receipt atomically.

These narrow `SECURITY DEFINER` functions are owned by the SQL migration
owner, explicitly schema-qualified and unavailable to client/MCP/service roles.
They are a proposed way to reach the existing **forced RLS + zero policy**
tables *without granting general relation privileges*. The current Apps
`postgres-order-transactions.mjs` **still uses direct table SQL and cannot be
used with the least-privilege role**. Its PostgreSQL integration tests to date
run as an ephemeral superuser; they do not establish least-privilege readiness.
Before commercial use, the Apps owner must repoint that one adapter to the
reviewed SQL operations (not keep both production backends) and prove real
PostgreSQL E2E under a restricted role.

A `SECURITY DEFINER` routine is privileged: each routine validates the exact
action and Space and never accepts untrusted SQL. The *host* is still required
to independently authenticate the caller and bind `p_actor` and `p_space`
to a current, authorized session and selection. Without that verified host,
possession of an executor credential could impersonate users by supplying
their UUIDs. **No LOGIN credential, membership, transport, endpoint or
operational grant is created here.**

CI executes this proposal in a fresh PostgreSQL 17 database with synthetic
Identity and Spaces; it proves direct-table denial, private RPC ACLs,
per-action role checks, revocation, CAS, atomic rollback on a duplicate and
receipt lookup. This is not a deployed migration or live-host E2E.

## Rollout gates (all required before real deployment)

1. Authorize execution of FOOD-001 by the owner of the OS roadmap.
2. Resolve the canonical **per-action Food authorization** from Identity,
   active membership and approved capabilities. Merely passing
   `private.ordax_subject_can_access_space_v1` is not sufficient:
   membership alone does not grant `order.create`/`order.transition`.
3. Implement and test a server-only PostgreSQL transaction adapter that
   authenticates subjects from trusted transport, acquires Space state
   row locks, checks grants at the write boundary, commits CAS state and
   idempotency receipt in ONE transaction, and exposes receipt lookup
   under fresh authorization; do not use a generic `service_role` key.
4. Approve any necessary changes to the global revision storage model and
   initialization from an authorized, non-browser source. Do not copy local
   demo data to production.
5. Run cross-Space, two-user, revoked-grant, concurrent revision, journal
   collision, crash-after-commit and RLS/role tests against an isolated
   database before applying a canonical migration.
6. After the migration is reviewed, create the final migration under
   `control-plane/supabase/migrations` using the canonical workflow;
   apply exactly once to the canonical project and lock actual ledger
   version and Git blob in `migration-registry.json`. A proposal must
   **not** be merged as an applied migration or deployed prematurely.

## Combined isolated PostgreSQL proof and JSON integrity

The PostgreSQL 17 CI also applies the **existing Space/Identity fixture,
private Food action policy and private Food storage proposal to one separate
ephemeral database**. It checks an authorized serializable order mutation,
CAS conflict, durable receipt recovery after an unknown transport outcome,
idempotent command uniqueness, rollbacks of invalid receipts, two-Space
isolation and active-member revocation. This is a SQL boundary integration
proof; it does **not** exercise the Apps JavaScript domain, authenticate a
network transport or provision a commercial executor.

The storage proposal uses `CHECK ((predicate) IS TRUE)` for JSON documents
and receipts. PostgreSQL normally accepts both TRUE **and UNKNOWN** in a
`CHECK` constraint; missing JSON keys therefore must be treated explicitly
as failures. The combined proof rejects absent document revision and receipt
commit token, as well as inconsistent receipts. The proposal remains in
`proposals/` and is not applied to canonical Supabase.

## Test coverage

The `Food Storage Proposal Proof` workflow runs **ephemeral PostgreSQL
17 only**. It creates minimal canonical account/Space fixture tables,
applies the proposal in isolation and proves table privileges,
forced RLS, no exposed Food RPC, journal uniqueness, tenant receipt checks
and revision/document consistency. No credentials from the canonical
project or Supabase service_role are used.

The proposal is a staging artifact, not a commercially functional
Food Order Core and not authorization to switch on Food in Space.
