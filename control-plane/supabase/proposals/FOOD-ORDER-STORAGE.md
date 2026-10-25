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

## Test coverage

The `Food Storage Proposal Proof` workflow runs **ephemeral PostgreSQL
17 only**. It creates minimal canonical account/Space fixture tables,
applies the proposal in isolation and proves table privileges,
forced RLS, no exposed Food RPC, journal uniqueness, tenant receipt checks
and revision/document consistency. No credentials from the canonical
project or Supabase service_role are used.

The proposal is a staging artifact, not a commercially functional
Food Order Core and not authorization to switch on Food in Space.
