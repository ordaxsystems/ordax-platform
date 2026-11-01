# PostgreSQL product remote authority

This directory owns the PostgreSQL migrations for the end-user ORDAX remote
authority.

The canonical persistent database is:

- Supabase project: `ordax-platform` (ref `jhfphsjptrpmtnzkpwud`; production environment unchanged)
- project ref: `jhfphsjptrpmtnzkpwud`
- region: `sa-east-1` (São Paulo)
- PostgreSQL: durable source of truth

The previous Supabase project named `ordax-control-plane` is not the canonical
production database for this authority.

## Architecture

```text
ChatGPT / ORDAX Web / Mobile
            |
            v
     remote edge/API
            |
     +------+------+
     |             |
     v             v
realtime/session  Supabase/PostgreSQL
coordination      durable source of truth
                  grants / actions / receipts / audit
                         |
                         v
                   ORDAX Runtime
```

PostgreSQL is the durable authority. Edge/realtime infrastructure may transport
requests or coordinate live sessions, but it must not become a second persistent
authority.

Large binary artifacts belong in an object store, not in PostgreSQL.

## Product capability grants: client-scoped execution

The canonical grant group and target lookup contract binds both
`client_kind` and `client_id`. Migration
`20261007203000_product_client_grant_isolation_v1.sql` makes action
enqueue use this **same** exact identity, and records `client_id` in
private action requests and audit entries. Replayed idempotency requests
must match the same client. The superseded enqueue/resolver signatures
must not remain executable; the new enqueue requires a non-null client ID.

Cloudflare must derive `client_id` from a verified, bound credential /
OAuth client identity, **never** from request body fields or other
untrusted action payload. This migration **alone does not enable the
Product endpoint cutover**: JWT subject mapping, client verification,
MCP consumer contracts and end-to-end execution tests still gate the
`product_remote_authority` status in
`control-plane/cloudflare/d1-cutover-authority-map.json`.

### Action status: same per-client read isolation

Migration `20261007204500_product_client_scoped_action_status_v1.sql`
extends the verified `client_kind/client_id` boundary from enqueue and
idempotency replay to reading action status/results. The former
`ordax_get_product_action_v1(owner, request)` signature must be removed,
not left as a privileged legacy overload. The replacement accepts
`(owner, client_kind, client_id, request)` and matches all four columns.
Only `ordax_edge_executor` may call it; direct user, service_role and
anonymous execution remains revoked. Read-only postflight checks verify
signatures, predicates and ACLs.

The Worker PostgreSQL adapter requires the exact identity for status reads,
but the existing `/mcp` and Product endpoints remain on their legacy
handlers until the fully coordinated PostgreSQL-only transition.
No D1/PG dual-write, fallbacks or early production deploys are permitted.

## Migration SSOT and provenance

Applied migrations are immutable history. Never edit an applied migration, never
reapply it manually, and never create a second migration with equivalent effects.

The clean product bootstrap migrations `0001_product_foundation` through
`0007_projects_devices_fk_indexes` were originally versioned in
`washingtonmsdj/prototipo-ordax-os/infra/supabase/product/migrations/`. They
remain historical source provenance and are not copied into this directory.

From `20261007150000_product_remote_authority_v1.sql` onward, this directory is
the canonical source owner for Control Plane PostgreSQL authority and hardening.
New PostgreSQL changes in this domain must be introduced here first through a
branch and pull request, then applied once to the canonical project.

The applied ledger is locked in `migration-registry.json`. It records the exact
canonical project, Supabase ledger version, source repository/path and Git blob
for every approved migration. CI verifies that every SQL file in this directory
matches its locked Git blob and that no unregistered canonical migration exists.

Only historical migrations `0001` through `0007` are approved from the old
`prototipo-ordax-os` migration root. The many later sync/network/legal/quota
migrations that still exist in that historical directory are **not** authorized
for replay into the São Paulo database merely because the files exist.

For a new migration, the operational sequence is:

1. create the SQL on a branch and open a PR before touching the live database;
2. apply it exactly once to `jhfphsjptrpmtnzkpwud`;
3. add the returned Supabase ledger version and the migration Git blob to the
   registry in the same PR;
4. merge only after the registry has no pending entry and CI is green.

The registry also records the few historical cases where the checked-in file is
SQL-equivalent to the ledger but differs only in formatting/comments. Those
files are now pinned and must not drift further.

The files
`20261007181500_edge_runtime_role.sql` and
`20261007182000_remove_unprovisioned_edge_login.sql` preserve exact migration
history already executed on the canonical project. The later
`20261007200000_edge_runtime_login_v1.sql` introduces the stable environment
LOGIN identity `ordax_edge_runtime` only after the Cloudflare boundary is ready.
The role shape is versioned in Git, but the password is provisioned and rotated
out-of-band and must never be committed.

## No dual-primary fallback

D1 and PostgreSQL must never both accept authoritative Product mutations.
PostgreSQL is the target durable SSOT. Dual writes and automatic persistent
fallback are forbidden because they can create split brain in grants, leases,
receipts and audit.

## Product vs engineering authority

Product remote execution is intentionally separate from engineering authority.
Product Web/Mobile/MCP credentials never inherit developer/operator authority.

Canonical Product rows use:

- `public.ordax_product_devices`;
- `public.ordax_space_devices`;
- `public.ordax_device_project_bindings`;
- `public.ordax_remote_capability_grants`;
- private Product action/event/audit tables introduced by the migrations in this
  directory.

Device-scoped grants use `scope_kind = 'device'` with no synthetic project.
Project-scoped grants require a real `project_id` and an active device/project
binding.

## Server-only database access

The database exposes reviewed server-side RPCs through the NOLOGIN group role
`ordax_edge_executor`. That role has no direct table/sequence authority and no
access to the `private` schema. It receives only explicit EXECUTE grants on the
required RPCs.

`service_role` is not the executor for these remote-action RPCs and has no direct
DML authority over the Product remote device/presence/binding/grant tables. The environment LOGIN identity `ordax_edge_runtime` inherits only
`ordax_edge_executor`. It receives no direct table/routine authority. Its
credential is deployment state, not migration source, and must be provisioned
out-of-band before Hyperdrive can become ready.

Private Product action tables grant no direct access to browser roles or to the
edge executor. Server authority enters only through narrowly reviewed
`SECURITY DEFINER` RPCs with pinned `search_path`.

## Generic service role is fail-closed

The Supabase `service_role` is not an ORDAX application executor. It has no
direct privileges on canonical ORDAX Product tables and no EXECUTE privilege on
the Product RPC surface.

This is deliberate even though `service_role` can bypass RLS: server-side
product mutation must not depend on a generic bypass credential. Each mutation
domain must expose a reviewed RPC to a dedicated NOLOGIN executor, with any
environment LOGIN credential provisioned separately through secret management.

The Auth bootstrap trigger remains owned by `postgres`; revoking
`service_role` from `ordax_accounts` does not affect account-row bootstrap.

## Custom roles and PUBLIC inheritance

Custom PostgreSQL roles receive privileges granted to `PUBLIC` even when they
have no explicit grant. The canonical database therefore removes `PUBLIC`
USAGE/CREATE from the `public` schema. Data API roles and reviewed executors
keep only their explicit schema grants.

This prevents a future NOLOGIN executor from acquiring the exposed schema merely
because the role was created. Schema USAGE, function EXECUTE and relation
privileges must all be granted intentionally.

Database-level `TEMPORARY` remains a separate platform-wide concern because it
is also inherited from `PUBLIC`; it must not be changed casually without
proving Supabase-managed service compatibility.

## Default privileges

Future objects created by `postgres` in `public` and `private` are
fail-closed. Default table/sequence access for API roles is revoked, and new
functions do not inherit EXECUTE through `PUBLIC` or server/runtime roles.

Any intentional Data API or server exposure must therefore be granted explicitly
in the same versioned migration that creates or changes the object. RLS and SQL
privileges are separate controls; both must remain correct.

## Server-authoritative mutation policies

Authenticated users retain only the table privileges intentionally exposed for
reads and the narrow account display-name update. Dead INSERT/UPDATE/DELETE RLS
policies from the original direct-client foundation are removed once matching
table DML is revoked, so a future accidental GRANT cannot resurrect a hidden
client mutation API.

## Subject-aware authorization SSOT

Server executors must authorize an explicit subject without impersonating
`auth.uid()`. The canonical private helpers therefore centralize Space access,
Space administration, Project access and Product Device access around
`(subject_user_id, resource_id)`.

Existing RLS functions remain thin `auth.uid()` wrappers over those helpers.
The subject-aware helpers are not executable by `anon`, `authenticated`,
`service_role` or `ordax_edge_executor`; they are internal authorization
building blocks for reviewed SECURITY DEFINER boundaries.

## Space authority

Space mutations use a dedicated NOLOGIN/NOINHERIT `ordax_space_executor`.
The role has schema USAGE and explicit EXECUTE only on the reviewed Space RPCs;
it has no direct table/sequence authority and no private-schema access.

`ordax_spaces.owner_user_id` is the only ownership SSOT. Member rows represent
only `admin`, `member` or `viewer`; they cannot create a second owner
concept. Space `kind` is fixed at creation, while the update RPC may change
only name, state and metadata.

No environment LOGIN member is provisioned by the database baseline. Wiring a
runtime credential to this executor is a separate deployment gate.

## Project authority

Project identity mutations use a dedicated NOLOGIN/NOINHERIT
`ordax_project_executor`. The role has no direct relation authority and may
execute only the reviewed create/update Project RPCs.

Projects are provider-neutral Space-scoped identities. Creation requires an
active Space plus Space-admin authority. `created_by_user_id` is immutable
provenance, not a second owner. Project `kind` is fixed at creation; update may
change name, state and metadata. Archiving is the lifecycle boundary instead of
a generic delete RPC.

Repository connections remain a separate read-only metadata surface. The
database enforces explicit GitHub repository selection (positive installation
and repository IDs plus bounded `owner/repository` full name) and one selected
GitHub repository per Project. No connection mutation RPC is created until the
separate approval/audit gateway exists.

## Entitlements and Profile Pack assignment

Entitlement grants are authorization/billing evidence, not a general CRUD
surface. The canonical database retains them as server-owned read-only rows.
No ad-hoc entitlement issuer or billing operator is created here; issuing or
revoking financial/product entitlements requires a separately reviewed source,
idempotency contract and audit boundary.

Profile Pack definitions (`public.ordax_profile_packs`) stay migration-owned
and versioned. Draft/retired manifests are not exposed through the client
SELECT policy, which admits only active catalog versions. The two bootstrap
packs remain draft until a reviewed activation migration.

An active Space administrator may select an existing **active** pack version or
clear the selection through `ordax_profile_pack_executor` (NOLOGIN, NOINHERIT,
NOBYPASSRLS). This executor has no direct table, sequence, or private-schema
authority: only `ordax_select_space_profile_pack_v1` and
`ordax_clear_space_profile_pack_v1` are executable. Both require the trusted
server to authenticate the actor before passing its UUID to the RPC.

The current selection SSOT remains `public.ordax_space_profile_packs`.
Changes are serialized per Space, repeated commands are idempotent, and every
effective selection/clear is recorded in the private append-only
`ordax_space_profile_pack_events` table. This record is not another current
state, and has no direct client/operator access.

Arbitrary per-Space configuration is intentionally unavailable at this stage:
selection stores an empty JSON object rather than accepting an unreviewed
configuration containing credentials or executable instructions.

## Default entitlement ledger (verified account origin)

The canonical `public.ordax_entitlement_grants` table remains the single
persistent state SSOT. `private.ordax_default_entitlement_policies` owns
versioned policy definitions and starts empty; no entitlement is activated by
creating this schema. Definitions may only be published by a reviewed migration.

The current account-default API is
`ordax_issue_account_default_entitlement_v2(subject_user_id, entitlement_key,
policy_version)`. Its source event is **not** supplied by a caller: PostgreSQL
derives the one-time `account_created:<user_id>:<entitlement_key>` identifier
from a real, non-deleted, non-anonymous and confirmed `auth.users` row
and its matching bootstrapped `ordax_accounts` record. Those two rows are locked `FOR SHARE` while the transaction issues the grant. Event receipts remain private, deduplicated,
auditable, and fail closed on replay with a different policy version.

Issuance is account-scoped and takes the value and duration only from an
active, versioned database policy, not arbitrary JSON or dates from a caller.
Each account/entitlement key has exactly one account-created event. Retries
replay a successful receipt **only while its grant is active and unrevoked**.
Expired or revoked receipts return `account_default_grant_inactive`, never
`ok: true`, and cannot mint another entitlement.
Policy/version updates do not silently regenerate one-time account defaults.

The old v1 issuer accepted a caller-supplied event ID and the v1 revoker
accepted an unverified revocation reason. Both SQL RPC endpoints were removed
after confirming that the canonical database contains no grants, policies or
receipts to migrate. General-purpose revocation stays **fail-closed**; only verified
Auth eligibility-loss transitions can revoke account-default grants; no compatibility wrapper remains.

`ordax_entitlement_default_executor` remains a NOLOGIN/NOINHERIT/NOBYPASSRLS
role with no direct table/sequence/private-schema privileges and only EXECUTE
on the v2 issuer. No runtime LOGIN membership or credential is provisioned for
it. A trusted service must still authenticate *who may request* the account
default issuance; the database proves the account-created origin, not the
identity of the network caller. This is not a payment signature, not a billing receipt and not a claim
of a user's real-world identity verification.

Billing, promotion and administrative grants and revocations remain blocked
pending independent proof, idempotency, audit, and operator authorization.
Never expose this database executor through an unauthenticated endpoint.

## Auth-owned entitlement revocation

The canonical Supabase Auth row is also the authority for loss of eligibility
after an account-default benefit has been issued. A single private PostgreSQL
trigger runs in the Auth transaction for three transitions:

- `deleted_at` changes from NULL to a timestamp (soft-delete);
- `is_anonymous` changes from false to true;
- generated `confirmed_at` changes from non-NULL to NULL, reflecting loss
  of all currently confirmed contact channels.

The new trigger supersedes the deletion-only v1 trigger and function; they
are **dropped**, not retained as a second implementation. The trigger must
watch the full `UPDATE` event because `confirmed_at` is a *stored generated
column* derived from the email/phone confirmation columns. Its `WHEN`
predicate prevents work for unrelated Auth updates.

It atomically expires active `product-default` grants and appends an event
`account_deleted:<grant_id>` for deletion or
`account_ineligible:<grant_id>` for confirmation/anonymous downgrade to
the existing private event journal. A repeated ineligible update does not
duplicate an event because only currently active grants are affected.

The account-default issuer continues to acquire a `FOR SHARE` lock on the
verified `auth.users` / `ordax_accounts` rows before replay checks.
This conflicts with Auth updates that change eligibility, so no default
grant can be issued after an eligibility-losing update commits. A subsequent
upgrade/reconfirmation does not automatically reissue an already consumed
one-time account-created event; this is intentionally fail-closed.

Hard deletion cascades through the existing Auth/entitlement foreign keys.
No independent entitlement SSOT, LOGIN role, generic revocation RPC or
billing/admin authority is introduced. Other grant sources continue to need
their own verified revocation contract.

## Effective entitlement reads and replay contract

`public.ordax_entitlement_grants` is the persistent grant SSOT and keeps
historical validity intervals; it does **not** imply that every row represents
a current permission. The existing authenticated SELECT RLS policy now
requires `valid_from <= clock_timestamp()` and
`valid_until IS NULL OR valid_until > clock_timestamp()`, in addition to
its existing user/Space ownership condition. Thus the Data API never returns
an expired, revoked, or not-yet-active grant as a current entitlement.
The private event journal remains the audit source for past issuance and
revocation; it was not exposed to client roles.
The RLS clock is intentionally the same real clock used by the issuer, so
new grants are visible immediately even if issuance and SELECT run inside
one multi-statement command. The corrective migration is separate and
versioned; neither previously applied SQL file was rewritten.

The existing `ordax_issue_account_default_entitlement_v2` verifies Auth
eligibility before looking up a replay. For a prior issued event it verifies
that the exact referenced grant is still effective and has no revocation
receipt. If not, it returns `ok: false`, `changed: false`,
`replayed: true` and error `account_default_grant_inactive`. This
distinguishes idempotent history from active authorization, without adding
a second issuance path, granting an executor more privileges, or reviving
a revoked account-default benefit.

## Temporary Auth suspension and entitlement visibility

Supabase Auth's `auth.users.banned_until` is a temporary account suspension
signal. While its timestamp is in the future, the canonical
`ordax_issue_account_default_entitlement_v2` refuses both first issuance
and successful idempotent replay. It checks the same Auth row under its
existing `FOR SHARE` lock, avoiding a stale account state.

The existing authenticated SELECT policy on
`public.ordax_entitlement_grants` also checks **live** account eligibility,
including `banned_until`. It retains current-date validity and user/Space
ownership checks. A private, zero-argument SECURITY DEFINER helper reads
`auth.users` and `ordax_accounts` using only the identity supplied by
`auth.uid()`; it cannot be used to probe other users. Only
`authenticated` has EXECUTE permission; no direct Auth SELECT, private
schema USAGE, or additional grant issuer authority is given.

Suspension does **not** expire or delete entitlements, does not append
a revocation event and does not generate a new source of truth.
If an existing grant remains within its validity interval when the ban
expires or is lifted, normal RLS visibility resumes. An expired grant
is still expired; a prior account-created event never reissues one.
The account deletion, anonymity and confirmation-loss transitions retain
the separate Auth-owned permanent revocation behavior.

Auth JWTs can remain cryptographically valid during a suspension, which is
why the entitlement policy rechecks the current PostgreSQL Auth row.
This guard covers entitlement SELECT and the default issuer, not a claim
that every other OrdaX API or JWT session has been globally revoked.

## Live session required for entitlement RLS

Authenticated entitlement SELECT now requires a **current, database-backed
Supabase Auth session**, not merely a JWT that has yet to expire. The existing
`private.ordax_authenticated_entitlement_eligible_v1()` helper is updated
**in place**: it reads `auth.jwt().session_id`, validates UUID syntax, and
checks `auth.sessions(id, user_id)` against `auth.uid()`. Missing, malformed,
deleted, other-user, or expired `not_after` session rows fail closed.
The previous confirmed/not-anonymous/not-deleted/not-banned Auth checks and
the exact authenticated RLS user/Space/date predicates are preserved.

The helper stays zero-argument, volatile, SECURITY DEFINER with an empty
search path and its original EXECUTE privilege restricted to
`authenticated`. Client roles receive no direct SELECT on `auth.sessions`,
no `private` schema USAGE, no extra database role, and no expanded
entitlement-issuance authority. The request JWT must already be verified by
Supabase/PostgREST; Postgres compares its claims against the canonical
session table but does **not** independently verify JWT signatures.
No Auth sessions table is copied or duplicated.

When Supabase Auth deletes a session during sign-out, existing JWTs can
remain cryptographically valid until expiration. They can no longer read
entitlements through this policy because the session row is missing.
This does not assert universal logout enforcement for every OrdaX endpoint:
this database check protects the entitlement read path only. Custom
JWTs without standard Supabase session IDs intentionally fail closed.
Checking `not_after` does not independently implement every provider
inactivity or time-box rule; Auth remains the owner of its session lifecycle.

## Shared authenticated subject session authority (RLS SSOT)

The authenticated Auth eligibility function, previously named
`private.ordax_authenticated_entitlement_eligible_v1()`, is now renamed
**in place** to `private.ordax_authenticated_subject_eligible_v1()`:
the PostgreSQL function's OID, owner, ACL and live-session checks are
preserved. The old private name is removed, rather than retained as a
wrapper or duplicated implementation.

All fourteen other subject-bound `public` RLS policies now require this
same predicate in addition to their original ownership, space, project,
device, membership, memory or remote-capability checks. The existing
entitlement policy automatically follows the function rename through its
OID reference, making **fifteen** sensitive policies dependent on one
source of Auth session eligibility. `ordax_accounts_update_own`
also requires it in both `USING` and `WITH CHECK`, while the
table's direct UPDATE privilege remains revoked for clients.

A missing, expired, deleted, or cross-user Supabase Auth session, an Auth
suspension, account deletion, unconfirmed account, or anonymous account
now fails closed for these private reads. Existing row ownership and RLS
authorization are **not** replaced by session presence. The
`ordax_profile_packs_select_active` policy is intentionally unchanged:
it exposes only the already-active profile pack catalog to authenticated
roles and is not an account/space-private resource.

No Auth sessions are copied, no private schema USAGE or Auth relation
SELECT is granted, and no new helper, role, or exposed RPC is created.
The separate trusted executor APIs still need their own caller verification
and authorization; RLS on client SELECT does not make those operations
automatically session-aware.

## Trusted service actors and canonical Auth eligibility

The ten account-actor write RPCs for Spaces, Space membership, Projects,
Memory and profile-pack selection use dedicated NOLOGIN executors and accept
an explicit `p_actor_user_id` from a trusted service. This input is a
**claimed principal, not proof of who called the service**. The caller's
identity, session and permission to request each RPC must be verified by
the authenticated service **before** it invokes the database executor.

A single, unexposed private `ordax_trusted_actor_auth_eligible_v1(uuid)`
`SECURITY INVOKER` helper now runs *inside* those SECURITY DEFINER RPCs
before any resource change. It checks the canonical `auth.users` row and
the matching `ordax_accounts` identity: confirmed, non-anonymous,
not soft-deleted and not currently banned. It takes `FOR SHARE` locks on
both rows to serialize service mutations against concurrent Auth status
changes. An ineligible actor fails closed as `trusted_actor_auth_ineligible`.
Temporary suspensions do **not** revoke existing resources or memberships;
normal operations resume when Auth becomes eligible again.

This is distinct from the request-session checker
`ordax_authenticated_subject_eligible_v1()` used by RLS: a trusted service
may use a database connection without forwarding the user's JWT. These
two helpers check different boundaries and never substitute for each other.
The SQL helper is deliberately not executable by any app/client role,
service-role or OrdaX executor; the enclosing postgres-owned RPC calls it
with the database owner's privileges. Existing NOLOGIN EXECUTE grants on
the ten public RPCs are unchanged.

The migration pins the exact definitions of all ten existing RPCs before
changing them to avoid silently overwriting another chat's work. It
adds no new table, database executor, RPC endpoint or general-purpose
identity delegation; it does not change Cloudflare, Vercel or upstream
identity validation. After this migration an invalid Auth actor is
rejected even if a trusted service inadvertently queues a stale command,
but **the database still cannot establish that the network caller is the
claimed actor** without the service authorization context.

## Live Auth owner eligibility for Product authority creation

Three existing Product authority-minting RPCs,
`ordax_enroll_product_device_v1`,
`ordax_replace_remote_grant_group_v1`, and
`ordax_enqueue_product_action_v1`, check the verified Auth owner
before issuing device credentials, remote capability grants or new actions.
The existing private `ordax_trusted_actor_auth_eligible_v1(uuid)` is
reused rather than creating a second owner-eligibility implementation.
It requires a matching Product account and a confirmed, non-anonymous,
not-deleted and not-currently-suspended `auth.users` record. Its
`FOR SHARE` locks serialize the mutation with account-status updates.

For an ineligible owner the RPC returns `product_owner_auth_ineligible`;
the action issuer checks it before looking up or acknowledging an
idempotency replay. Validation and the original dedicated
`ordax_edge_executor` EXECUTE boundary are otherwise unchanged. The
migration preflight pins exact function-definition hashes to fail if
another chat has changed any of the three functions concurrently.

Crucially, **revocation** via `ordax_revoke_remote_grant_group_v1`
is intentionally not blocked by this eligibility gate: the system must
be able to remove existing capability grants for a suspended owner.
Device telemetry and cleanup RPCs are also not converted into a new
user-authentication mechanism. A signed OAuth/JWT bearer must still be
verified and bound to the correct owner by the Worker or trusted
upstream service; passing an owner UUID is never caller authentication.

## Scoped Product reads and live Auth owner eligibility

Two existing Product query RPCs, `ordax_list_product_targets_v1` and
`ordax_get_product_action_v1`, now reject reads for an owner whose
canonical Supabase Auth account is suspended, soft-deleted, anonymous
or unconfirmed. Both reuse the lock-bearing
`private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)`
helper already used by Product mutations; there is no duplicate helper,
authorization table or new executor. A denied query returns the
standard `product_owner_auth_ineligible` JSON error.

The two functions remain on their original OIDs with the same
`ordax_edge_executor` privilege; SQL volatility is `VOLATILE`, because
the shared function locks the current Auth and Product account rows.
For eligible owners the original output shape, owner/client scoping,
active grant validity, target listing and action-result semantics remain
unchanged. When a temporary suspension ends, an otherwise available
result can be read again. A soft-deleted account remains ineligible.

The Worker is still responsible for **cryptographically verifying** the
bearer and associating its signed owner/client identity with the
`p_owner_user_id`, `p_client_kind` and `p_client_id` sent to these RPCs.
The database does not authenticate the owner by accepting its UUID.
Removing stale or unauthorized device action leases and cancelling
already-running actions are distinct concerns; this change only
protects Product **query visibility**, not every device callback.

## Memory authority

Durable Memory uses a dedicated NOLOGIN/NOINHERIT `ordax_memory_executor`
with explicit EXECUTE only on reviewed Memory RPCs and no direct relation
authority.

The durable identity model is intentionally limited to `account`, `space`
and `project`. Project-scoped memory uses the canonical `project_id` plus
`space_id` foreign key; the old textual `project_ref` is removed. Device and
session state are not stored as fake durable Memory scopes without canonical
identity.

Creation binds `owner_user_id` to the explicit actor. Space and Project
scopes require subject-aware access through the canonical authorization helpers.
Scope, kind and ownership remain immutable after creation; normal removal is a
soft state transition to `deleted`, not physical deletion.

## Grant groups and target projection

Remote capabilities are replaced and revoked as explicit grant groups. The
database derives Product targets only from active, non-expired grants. A
device-scoped grant is owner-bound and has no synthetic Space/Project. A
project-scoped grant requires a real active Space/Project, execute access to the
device, an active project/device binding and capabilities present in that
binding.

The canonical grant-group migration deliberately has no `legacy` backfill. It
requires the empty foundation state that exists before public rollout and fails
closed if data is unexpectedly present.

### OAuth MCP discovery does not rotate an unchanged grant

The signed `ordax_targets` read still calls PostgreSQL
`ordax_ensure_product_mcp_target_discovery_v1` on every request. Applied
migration `20261101204500_product_mcp_target_discovery_idempotent_v1.sql`
(ledger `20261101203933`) preserves that live consent and Owner-eligibility
check while eliminating the former revoke-and-reinsert on every read.
PostgreSQL serializes an Owner/OAuth-client auto-ensure and reuses only a
**single exact** active, unbounded, Owner-approved, device-scoped
`mcp-discovery/product.target.read/read` grant. Missing, stale or extra
active grants are reconciled exclusively by the existing authorized grant
replacement RPC. No Worker cache, parallel grant ledger, broader capability
or second authority may bypass these checks.

The migration was applied once to the canonical `ordax-platform` Supabase
project; its exact Git blob and real ledger version are pinned in
`migration-registry.json`. New changes must use a separate migration,
never edit or replay this applied source.

## Presence and scale

Realtime coordination owns hot connection state. Ordinary heartbeats must not
write PostgreSQL every few seconds.

The persistence RPC coalesces unchanged presence and writes at most periodically
(currently five minutes) unless connection state, runtime version or capability
digest changes. Connect/disconnect transitions may force an immediate write.

## Cutover gates

A persistent predecessor can stop being authoritative only after all of these are
proven:

1. PostgreSQL migrations are applied exactly once and security/performance
   advisors are reviewed.
2. Runtime/edge access uses the dedicated least-privilege PostgreSQL boundary.
3. Existing required device identity is migrated without synthetic IDs.
4. Delivery uses PostgreSQL leases/fencing and terminal replay.
5. Shadow verification, when used, is read-only and never becomes dual-write.
6. Product MCP -> remote boundary -> Runtime -> receipt/audit passes end to end.
7. Legacy Product writes are disabled before PostgreSQL Product writes become
   authoritative.
