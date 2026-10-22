# Project-First / Workspace resource grant — Platform M1 projection

**Status:** reviewed-design candidate; **not a live grant issuer**, Product endpoint, database migration, or authorization to use a local folder. See [Platform issue #266](https://github.com/ordaxsystems/ordax-platform/issues/266), [Runtime PR #185](https://github.com/ordaxsystems/ordax-runtime/pull/185) and [Apps PR #268](https://github.com/ordaxsystems/ordax-apps/pull/268).

## One trust boundary per owner

- **Platform/PostgreSQL** is the authority for authenticated owner, canonical Space/Project UUID, app Client, device, consent, expiry and grant revocation. Only a SECURITY DEFINER RPC using server-owned inputs can return a trusted grant row.
- **Runtime** owns the trusted human folder picker, opaque resource reference, local filesystem identity and policy, symlink/junction handling, Git/filesystem snapshot and action receipt. It must revalidate authorization on **every** operation, including after a long snapshot.
- **Apps Orchestrator** owns Lab project/workspace UI and persists only logical IDs in its existing Store. A local Lab ID, a ChatGPT message, device Full Access or a Product capability profile must never mint a file grant.

## Current source contract

`control-plane/cloudflare/src/project_workspace_grant_contract.ts` contains `projectWorkspaceGrantProjection(raw, trusted, nowMs)`. Its inputs are explicitly **server-owned**: a canonical Product subject/Space/Project scope and an already-authenticated PostgreSQL row. Shape-only checks require exact owner, canonical Space/project, Lab project mapping, actor, client, workspace session, device, and opaque `resource_...` identifier. It refuses revoked, inactive, non-human-picker, non-read-only, expired and greater-than-24-hour grants. The output includes only the values needed by the Runtime Apps consumer and expiry; it never returns paths, secrets, SQL rows or filesystem data.

**This function is not sufficient to authorize an operation**. A caller could forge both inputs if they were exposed as JSON. Accordingly it is not imported by `index.ts`, `mcp_http.ts`, remote grant profiles or any Product handler. The owner must eventually supply a PostgreSQL RPC and a Runtime chooser with authenticated transports; no temporary API is permitted.

## Requirements before a live resource grant

1. Canonical SQL transaction: resolve authenticated owner and client, membership in Space/Project, attested device binding, revocation and consent. Link Lab project ID only through durable server-owned mapping; do not trust it directly.
2. Trusted Runtime picker: owner selects an actual directory, confirms read-only scope/expiry, and Runtime records a local root identity. The Platform resource ID must refer to exactly one Runtime-owned resource; no JSON filepath/path traversal grants.
3. Issue/renew/revoke through dedicated scoped RPCs; no arbitrary `profile_key` can authorize a resource and no implicit conversion from device-level computer-filesystem/full-computer-control grants.
4. Runtime verifies a **fresh**, authenticated Platform decision for every `verifyBinding`/`snapshot`, plus its local policy. No use of a stale cached proof after offline/revoke.
5. Apps requires both the Runtime proof and its own actor/project policy; stores no raw path, file body, user secret or bearer token.
6. Tests: two owners/clients/projects/devices isolated; expires/revokes mid-operation; offline/picker rejected; symlink/reparse path and root replacement; real Windows E2E with a disposable VESTE fixture, no Git write and no GPT send.

## Evidence

- Dynamic Node tests: `node --test control-plane/tests/project-workspace-grant-contract.test.mts` cover field-by-field scope, forged IDs, read-only policy, time limits and redaction.
- The already-required Python scope test `tests.test_product_action_scope_contract` asserts projection only and absence of a new live writer/MCP route.
- No Worker deploy, SQL migration, new grant profile, production permission or Windows installation is performed by this change.

**Next gate:** design and review the PostgreSQL SECURITY DEFINER resource grant schema/RPC **together with the trusted Runtime picker**. Until both are present, the Apps alpha.11 status must truthfully remain `capability_unavailable`.