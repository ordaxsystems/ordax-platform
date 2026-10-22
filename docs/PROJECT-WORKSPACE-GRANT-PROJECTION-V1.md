# Project-First / Workspace resource grant — Platform M1 projection

**Status:** candidate resource registration/revocation are being reviewed in a Platform PR; **not an applied database migration, deployment, or authorization to use a local folder**. The existing read-only Device verifier remains default-off. The Runtime proof decoder is on main; Platform issue [#266](https://github.com/ordaxsystems/ordax-platform/issues/266) continues to block database promotion and production activation.

## One trust boundary per owner

- **Platform/PostgreSQL** is the authority for authenticated owner, canonical Space/Project UUID, app Client, device, consent, expiry and grant revocation. Only a SECURITY DEFINER RPC using server-owned inputs can return a trusted grant row.
- **Runtime** owns the trusted human folder picker, opaque resource reference, local filesystem identity and policy, symlink/junction handling, Git/filesystem snapshot and action receipt. It must revalidate authorization on **every** operation, including after a long snapshot.
- **Apps Orchestrator** owns Lab project/workspace UI and persists only logical IDs in its existing Store. A local Lab ID, a ChatGPT message, device Full Access or a Product capability profile must never mint a file grant.

## Current source contract

`control-plane/cloudflare/src/project_workspace_grant_contract.ts` contains the shared `projectWorkspaceGrantProjection(raw, trusted, nowMs)`. The existing `projectWorkspaceVerifierResponse` in the authenticated Device transport uses it to validate exact owner/Space/Project/Lab/actor/client/session/device/resource scope, active read-only authority, trusted Runtime picker marker and the original lifetime. Registration reuses that verifier response projection instead of implementing a second proof validator.

**Projection is not sufficient to authorize an operation**. Candidate registration requires a signed Owner session whose OAuth client matches the request and the enrolled Product Device credential. Runtime verification reuses the existing authenticated Device transport and its read-only proof route; PostgreSQL rechecks the grant and revocation on every call, so no Owner JWT renewal is needed for each workspace read. The owner grant remains in `ordax_remote_capability_grants`; resource rows are subordinate references only. The routes add no MCP tools and accept no filesystem paths.

## Requirements before a live resource grant

1. Canonical SQL transaction: resolve signed Owner and client, membership in Space/Project, active device binding, revocation and consent. Link Lab project ID only through the durable server-owned mapping.
2. Runtime calls registration only after the existing native picker and affirmative Owner confirmation; its opaque resource ID must match an in-memory Runtime selection and its captured root identity.
3. Reuse `ordax_remote_capability_grants`; no arbitrary `profile_key` can authorize a resource and no implicit conversion from device-level filesystem/full-computer-control grants.
4. Runtime verifies a **fresh**, authenticated Platform decision for every `verifyBinding`/`snapshot`, plus its local policy. No use of a stale cached proof after offline/revoke.
5. Apps requires both the Runtime proof and its own actor/project policy; stores no raw path, file body, user secret or bearer token.
6. Tests: two owners/clients/projects/devices isolated; expires/revokes mid-operation; offline/picker rejected; symlink/reparse path and root replacement; real Windows E2E with a disposable VESTE fixture, no Git write and no GPT send.

## Evidence

- Dynamic Node tests: `node --test control-plane/tests/project-workspace-grant-contract.test.mts` cover field-by-field scope, forged IDs, read-only policy, time limits and redaction.
- SQL PGlite tests cover the proposed lifecycle RPCs; route tests cover dual authentication, exact scope, path rejection and proof projection.
- No Worker deploy, SQL migration, new grant profile, production permission or Windows installation is performed by this change.

**Next gate:** integrate the candidate Platform API with the trusted Runtime picker and existing ProjectWorkspacePort, then complete Windows E2E. Until then, the Apps status must truthfully remain `capability_unavailable`.
