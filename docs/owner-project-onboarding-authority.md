# Owner project onboarding — authority contract (#220)

Status: **design gate**, not a deployed onboarding or authorization grant.

## Source of truth

1. Space: `ordax_spaces`, via existing `ordax_create_space_v1` under the dedicated `ordax_space_executor` authority.
2. Project: `ordax_projects`, via `ordax_create_project_v1` under `ordax_project_executor`.
3. GitHub selection: `ordax_project_connections`, only after server-side verification of the requesting Owner's GitHub App installation and selected repository. `repository_id`, `installation_id` and `repository_full_name` must be obtained from the GitHub provider, not trusted from browser form fields.
4. Device execution: `ordax_space_devices` must be active with `access_mode='execute'` and `ordax_device_project_bindings` must be active for that device and project, authorized through dedicated transactional Owner RPCs.
5. Permissions: independently created via the existing `/v3/owner/remote-grant-groups` authority, scoped to the same OAuth client, Space, project, device, capabilities and expiration. **Onboarding must never issue grants automatically.**

## New write boundary required

Only the authenticated Owner service, with a dedicated constrained DB execution role, may invoke reviewed onboarding RPCs. Existing `ordax_project_executor`, `ordax_edge_executor`, `authenticated`, `service_role` and Studio must not acquire direct table writes or a generic create-connection RPC.

The implementation must use an Owner-authenticated and CSRF-resistant request entrypoint, idempotency key, audit/receipt, and a transaction guarded against concurrent duplicate registrations. Authenticated product identity and GitHub installation authority must both be checked; never derive Owner from submitted `owner_user_id`. Repository rename and installation revocation must invalidate stale connections; a repository name alone must not imply ownership.

For every mutation: recheck Owner/Space/project/device relations inside the transaction, fail closed on ambiguity, race, missing verification or ineligible identity. A suspended or archived Space/project or revoked device is not eligible. Revocation must block future enqueue even if an older OAuth client token exists.

## User-facing states

`needs_space` → `needs_project` → `needs_github_installation` → `needs_repository_selection` → `needs_device_binding` → `needs_execute_confirmation` → `ready_without_grants` → `grants_pending` → `ready`.

States must be derived from canonical reads, not local flags. Only show accessible resources. Device binding with `execute` and each native grant need separate affirmative Owner action; previews are read-only.

## Release gates

- Verify no direct table permissions for browser, Studio, general edge and project executor roles.
- Reject spoofed installation/repository identifiers, inaccessible repositories, cross-Owner target, revoked device, archived project, mismatched Space and duplicate repository assignment.
- Simultaneous identical requests are idempotent; conflicting simultaneous requests fail without partial commits.
- Revoke any association and prove subsequent native operations are denied without enqueue; reconnecting a Runtime must not resurrect authority.
- `process_list` requires project scope and its own read capability; `terminal_exec` requires a distinct `terminal.exec` capability.
- Prove positive E2E with a real installation and Owner consent after all negative tests, with auditable request and receipt.

## Existing implementations to reuse

- `control-plane/supabase/migrations/20261007193000_space_authority_v1.sql`
- `control-plane/supabase/migrations/20261007193500_project_authority_v1.sql`
- `control-plane/supabase/migrations/20261007194000_project_connection_contract_hardening_v1.sql`
- `control-plane/supabase/migrations/20261016141000_owner_project_scope_resolver_v1.sql`
- `control-plane/cloudflare/src/product_owner_grant_admin.ts`

This contract does not authorize direct database inserts, grant escalation, auto-enrollment or publishing before end-to-end proof.
