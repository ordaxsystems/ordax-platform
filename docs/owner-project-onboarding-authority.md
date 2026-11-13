# Owner project onboarding — authority contract (#220)

Status: **Project onboarding and server-authoritative GitHub repository selection are implemented in the backend; GitHub App configuration, Account callback transport, device execute binding and grants remain gated.**

## Implemented Project boundary

The canonical Worker owns one Owner-only Project onboarding surface:

- `GET /v3/owner/project-onboarding?device_id=UUID`: derives Space/Project/device readiness from PostgreSQL and returns only bounded product state.
- `POST /v3/owner/project-onboarding/projects`: creates a Project inside an existing admin-authorized Space through the canonical `ordax_create_project_v1` RPC. It requires `confirm=create_project` and accepts no repository IDs, provider metadata, grants or arbitrary metadata.

Database execution is isolated by `ordax_owner_project_onboarding_executor`, a NOLOGIN role inherited only by `ordax_edge_runtime`. It has no direct relation DML and no USAGE on the private schema; it receives only EXECUTE on reviewed RPCs.

The onboarding-state RPC exposes no `installation_id`, external account identity, token, path or credential. It reports per-project gates such as `needs_github_installation`, `needs_repository_selection`, `needs_device_binding` and `ready_without_grants`.

Project creation does **not** create a GitHub connection, bind a device for execution or issue Product grants.

## Implemented GitHub authority

The Platform GitHub boundary is server-authoritative and uses GitHub App user authorization, not browser-supplied installation metadata.

Owner routes:

- `POST /v3/owner/github/authorization-challenges`
- `POST /v3/owner/github/authorization-completions`
- `GET /v3/owner/github/repository-candidates?challenge_id=UUID`
- `POST /v3/owner/github/repository-selections`

The challenge stores only `state_sha256`, never raw OAuth state. PKCE S256 is derived from a server-side secret. Completion moves the challenge from `pending` to `verifying` before the OAuth code exchange, so an uncertain provider response is never replayed automatically.

The user access token returned by GitHub exists only in Worker memory. It is used to verify:

1. the authenticated GitHub user through `GET /user`;
2. installations visible to that user through `GET /user/installations`;
3. repositories visible through `GET /user/installations/{installation_id}/repositories`.

The token, refresh token, client secret and PKCE verifier are never persisted in PostgreSQL.

Provider-derived repository candidates are stored only in private short-lived tables:

- `private.ordax_owner_github_authorization_challenges`
- `private.ordax_owner_github_repository_candidates`

Candidate reads expose only repository choice metadata; they do not expose `installation_id`, GitHub user id or credentials.

Final repository selection accepts only:

- `challenge_id`;
- `repository_id`;
- `confirm=select_repository`.

The browser/model cannot supply `installation_id`, repository full name, GitHub account id, provider metadata, device binding or grant. The transactional selection RPC resolves the exact previously verified candidate and only then writes `ordax_project_connections`. Successful selection advances to `needs_device_binding`.

## Source of truth

1. Space: `ordax_spaces`. Existing browser-auth Space creation still uses `ordax_create_space_v1`; the Worker must not fabricate `auth.uid()` or bypass that boundary.
2. Project: `ordax_projects`, via `ordax_create_project_v1`.
3. GitHub authorization challenge/candidates: private short-lived Platform tables. They are not Product state and are deleted/expired after selection.
4. GitHub selection: `ordax_project_connections`. Installation/repository identity comes only from GitHub API responses verified by the server.
5. Device execution: `ordax_space_devices` must be active with `access_mode='execute'` and `ordax_device_project_bindings` active for that device/project, through a dedicated Owner transaction.
6. Permissions: independently created through `/v3/owner/remote-grant-groups`, scoped to the same OAuth client, Space, Project, device, capabilities and expiration. **Onboarding never auto-grants.**

## GitHub configuration and release gate

The code is deliberately fail-closed until a canonical GitHub App is configured. The Worker requires:

- `PRODUCT_GITHUB_APP_CLIENT_ID`
- `PRODUCT_GITHUB_APP_CLIENT_SECRET`
- `PRODUCT_GITHUB_APP_PKCE_SECRET`
- `PRODUCT_GITHUB_APP_INSTALL_URL`

The callback authority is fixed to `https://ordax.com.br/account/mcp/github/callback`.

Until the GitHub App exists and the Account gateway owns that authenticated callback path, the public Account/Site must continue presenting GitHub as unavailable. Integrating this code or applying its migration does not create/register the GitHub App, configure secrets, publish the callback or enable any production flag.

A setup redirect `installation_id` is never accepted as proof. Repository candidates must be recovered through the authenticated GitHub user API flow before selection.

## Remaining boundary after GitHub selection

After a verified repository is selected:

- implement the explicit Owner execute-confirmation transaction for `ordax_space_devices` + `ordax_device_project_bindings`;
- keep grant issuance as a later, separate affirmative action;
- handle GitHub installation/repository revocation and rename so stale `ordax_project_connections` cannot authorize new work;
- connect the Account callback/start/candidate/selection transport without exposing Product or GitHub tokens to browser JavaScript;
- prove the complete path with a real GitHub installation and signed Runtime receipts.

Existing `ordax_project_executor`, `ordax_edge_executor`, `authenticated`, `service_role`, Studio and Surface must not acquire direct table writes or a generic create-connection RPC.

## User-facing progression

`needs_space` → `needs_project` → `needs_github_installation` → `needs_repository_selection` → `needs_device_binding` → `needs_execute_confirmation` → `ready_without_grants` → `grants_pending` → `ready`.

States are derived from canonical reads, never local flags. GitHub repository selection, device execute binding and each project-native grant remain separate Owner actions.

## Release gates

- No direct table permissions for browser, Studio, general edge or project executor roles.
- Reject spoofed repository/installation IDs, reused OAuth state, duplicate provider candidates, cross-Owner Project, archived Project, mismatched Space and ambiguous connection.
- Never persist GitHub access/refresh tokens or PKCE verifier.
- Never retry an uncertain OAuth completion or repository-selection mutation as a fresh action.
- Repository connection/device binding transactions must fail atomically on conflict.
- Revocation must prevent later enqueue; Runtime reconnect must not resurrect authority.
- `process_list` requires project scope plus project-native process grant.
- `terminal_exec` requires the distinct `terminal.exec` grant.
- Positive E2E requires a real verified GitHub App installation, explicit device binding, explicit grants and signed action receipts.

## Existing implementations reused

- `control-plane/supabase/migrations/20261007193000_space_authority_v1.sql`
- `control-plane/supabase/migrations/20261007193500_project_authority_v1.sql`
- `control-plane/supabase/migrations/20261007194000_project_connection_contract_hardening_v1.sql`
- `control-plane/supabase/migrations/20261016141000_owner_project_scope_resolver_v1.sql`
- `control-plane/supabase/migrations/20261113214943_owner_project_onboarding_authority_v1.sql`
- `control-plane/supabase/migrations/20261113223950_owner_github_installation_authority_v1.sql`
- `control-plane/cloudflare/src/product_owner_project_scope.ts`
- `control-plane/cloudflare/src/product_owner_project_onboarding.ts`
- `control-plane/cloudflare/src/product_owner_github_authorization.ts`
- `control-plane/cloudflare/src/product_owner_grant_admin.ts`

This contract does not authorize direct database inserts from browser-facing roles, grant escalation, auto-enrollment or release before real end-to-end proof.
