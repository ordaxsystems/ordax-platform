# Owner project onboarding — authority contract (#220)

Status: **backend onboarding foundation implemented for Owner state + Project creation; GitHub connection and device binding remain gated**.

## Implemented boundary

The canonical Worker now owns one Owner-only onboarding surface:

- `GET /v3/owner/project-onboarding?device_id=UUID`: derives Space/Project/device readiness from PostgreSQL and returns only bounded product state.
- `POST /v3/owner/project-onboarding/projects`: creates a Project inside an existing admin-authorized Space through the canonical `ordax_create_project_v1` RPC. It requires `confirm=create_project` and accepts no repository IDs, provider metadata, grants or arbitrary metadata.

Database execution is isolated by `ordax_owner_project_onboarding_executor`, a NOLOGIN role inherited only by `ordax_edge_runtime`. It has no table DML and only receives EXECUTE on the reviewed onboarding-state RPC plus the existing canonical Project-creation RPC.

The onboarding-state RPC exposes no `installation_id`, external account identity, token, path or credential. It reports per-project gates such as `needs_github_installation`, `needs_repository_selection`, `needs_device_binding` and `ready_without_grants`.

This implementation does **not** create a GitHub connection, bind a device for execution or issue Product grants.

## Source of truth

1. Space: `ordax_spaces`. Existing browser-auth Space creation still uses `ordax_create_space_v1`; the Worker must not fabricate `auth.uid()` or bypass that boundary.
2. Project: `ordax_projects`, via `ordax_create_project_v1`.
3. GitHub selection: `ordax_project_connections`, only after server-side verification of the requesting Owner's GitHub installation and selected repository. `repository_id`, `installation_id` and `repository_full_name` must be obtained from the provider, never from browser/model fields.
4. Device execution: `ordax_space_devices` must be active with `access_mode='execute'` and `ordax_device_project_bindings` active for that device/project, through a dedicated Owner transaction.
5. Permissions: independently created through `/v3/owner/remote-grant-groups`, scoped to the same OAuth client, Space, Project, device, capabilities and expiration. **Onboarding never auto-grants.**

## Remaining GitHub/device boundary

The canonical Platform currently has no GitHub App installation authority that can independently verify the Owner and selected repository. Therefore the server must stop at `needs_github_installation`; it must not accept provider IDs from a browser/model to populate `ordax_project_connections`.

Before repository selection can be enabled:

- establish one server-side GitHub installation authority for the Owner;
- obtain installation/repository identity from GitHub itself;
- handle repository rename and installation revocation;
- insert/update the connection only through a reviewed transactional RPC;
- then add a separate explicit execute-confirmation transaction for `ordax_space_devices` + `ordax_device_project_bindings`;
- keep grant issuance as a later, separate affirmative action.

Existing `ordax_project_executor`, `ordax_edge_executor`, `authenticated`, `service_role`, Studio and Surface must not acquire direct table writes or a generic create-connection RPC.

## User-facing progression

`needs_space` → `needs_project` → `needs_github_installation` → `needs_repository_selection` → `needs_device_binding` → `needs_execute_confirmation` → `ready_without_grants` → `grants_pending` → `ready`.

States are derived from canonical reads, never local flags. Device execute binding and each project-native grant remain separate Owner actions.

## Release gates

- No direct table permissions for browser, Studio, general edge or project executor roles.
- Reject spoofed repository/installation IDs, cross-Owner device, revoked device, archived Project, mismatched Space and ambiguous connection.
- Repository connection/device binding transactions must be idempotent and fail atomically on conflict.
- Revocation must prevent later enqueue; Runtime reconnect must not resurrect authority.
- `process_list` requires project scope plus project-native process grant.
- `terminal_exec` requires the distinct `terminal.exec` grant.
- Positive E2E requires a real verified GitHub installation, explicit device binding, explicit grants and signed action receipts.

## Existing implementations reused

- `control-plane/supabase/migrations/20261007193000_space_authority_v1.sql`
- `control-plane/supabase/migrations/20261007193500_project_authority_v1.sql`
- `control-plane/supabase/migrations/20261007194000_project_connection_contract_hardening_v1.sql`
- `control-plane/supabase/migrations/20261016141000_owner_project_scope_resolver_v1.sql`
- `control-plane/cloudflare/src/product_owner_project_scope.ts`
- `control-plane/cloudflare/src/product_owner_grant_admin.ts`

This contract does not authorize direct database inserts, grant escalation, auto-enrollment or release before real end-to-end proof.
