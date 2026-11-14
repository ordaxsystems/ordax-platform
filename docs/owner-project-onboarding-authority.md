# Owner project onboarding — authority contract (#220)

Status: **Project onboarding, server-authoritative GitHub repository selection and two-party Project↔Device binding are implemented in the Platform backend. Runtime confirmation, Account release, GitHub App configuration and Product grants remain independently gated.**

## Implemented Project boundary

The canonical Worker owns the Owner-only Project onboarding surface:

- `GET /v3/owner/project-onboarding?device_id=UUID`: derives Space/Project/device readiness from PostgreSQL and returns only bounded Product state.
- `POST /v3/owner/project-onboarding/projects`: creates a Project inside an existing admin-authorized Space through the canonical `ordax_create_project_v1` RPC. It requires `confirm=create_project` and accepts no repository IDs, provider metadata, grants or arbitrary metadata.
- `POST /v3/owner/project-onboarding/device-binding-intents`: requests a short-lived binding intent for one exact `project_id + device_id`. It requires `confirm=bind_project_device` and never accepts local Project identity, path, capability ceiling or grant data from the browser.

Database execution is isolated by `ordax_owner_project_onboarding_executor`, a NOLOGIN capability role inherited by the canonical Edge Runtime login. It has no direct relation DML and no USAGE on the private schema; it receives only EXECUTE on reviewed RPCs.

The onboarding-state RPC exposes no `installation_id`, external account identity, token, local path or credential. It reports canonical project gates such as `needs_github_installation`, `needs_repository_selection`, `needs_device_binding` and `ready_without_grants`.

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

Final repository selection accepts only `challenge_id + repository_id + confirm=select_repository`. The browser/model cannot supply `installation_id`, repository full name, GitHub account id, provider metadata, device binding or grant. The transactional selection RPC resolves the exact previously verified candidate and only then writes `ordax_project_connections`. Successful selection advances to `needs_device_binding`.

## Implemented two-party Project↔Device binding

The binding authority is intentionally split between Owner and enrolled Device Agent.

Owner step:

- `POST /v3/owner/project-onboarding/device-binding-intents`
- accepts only `project_id + device_id + confirm=bind_project_device`;
- creates a five-minute private intent after revalidating Owner auth, owned active device, active Project/admin Space and exactly one active GitHub repository connection;
- snapshots the verified connection/repository identity so later repository drift invalidates confirmation.

Device step on the existing authenticated transport:

- `POST /v3/device/transport/project-binding-intents` reads pending intents for the device identity derived from its enrolled credential;
- `POST /v3/device/transport/project-binding-confirm` accepts only `intent_id + local_project_ref + confirm=bind_local_project`;
- `local_project_ref` must be the opaque local Project Catalog identity `project-N`; it is not a filesystem path, repository name or browser-controlled identifier.

Create-intent and confirmation serialize on the canonical Project row. A superseded intent cannot confirm later, and a Project/device pair already actively bound returns a conflict instead of silently relinking.

Successful Device confirmation atomically activates:

- `ordax_space_devices(state='active', access_mode='execute')`;
- exactly one active `ordax_device_project_bindings` row for the Project/device.

The partial unique index `ordax_device_project_bindings_one_active_uq` prevents ambiguous active bindings for one Project/device pair.

The binding's `allowed_capabilities` is a compatibility ceiling equal to the union of canonical **Project-scoped** Owner grant profiles already defined by the Platform. It is not a grant. The binding transaction never inserts into `ordax_remote_capability_grants`.

The binding authority is release-gated by `OWNER_PROJECT_DEVICE_BINDING_ENABLED=enabled`. That flag is deliberately absent from `wrangler.mcp.toml`; source integration does not activate production.

### Applied migration

Canonical source:

`control-plane/supabase/migrations/20261113235000_owner_project_device_binding_authority_v1.sql`

Applied Supabase ledger:

- version: `20261114000316`;
- ledger name: `owner_project_device_binding_authority_v1`;
- source blob: `de556507828ba53c2a69e234c353e01d07335e16`;
- registry relation: `exact`.

The applied migration is immutable. Any future schema correction must use a new migration.

Post-apply audit observed zero pending intents, zero active Project/device bindings and zero active Space/device execute rows, so the migration changed authority structure without fabricating user state.

## Source of truth

1. Space: `ordax_spaces`. Existing browser-auth Space creation still uses `ordax_create_space_v1`; the Worker must not fabricate `auth.uid()` or bypass that boundary.
2. Project: `ordax_projects`, via `ordax_create_project_v1`.
3. GitHub authorization challenge/candidates: private short-lived Platform tables. They are not Product state and are deleted/expired after selection.
4. GitHub selection: `ordax_project_connections`. Installation/repository identity comes only from GitHub API responses verified by the server.
5. Device binding intent: `private.ordax_owner_project_device_binding_intents`; it is short-lived coordination state, not durable permission.
6. Device execution: `ordax_space_devices` active with `access_mode='execute'` plus one active `ordax_device_project_bindings` row confirmed by the enrolled Device Agent.
7. Permissions: independently created through `/v3/owner/remote-grant-groups`, scoped to the same OAuth client, Space, Project, device, capabilities and expiration. **Onboarding and binding never auto-grant.**

## GitHub configuration and release gate

The code remains fail-closed until a canonical GitHub App is configured. The Worker requires:

- `PRODUCT_GITHUB_APP_CLIENT_ID`
- `PRODUCT_GITHUB_APP_CLIENT_SECRET`
- `PRODUCT_GITHUB_APP_PKCE_SECRET`
- `PRODUCT_GITHUB_APP_INSTALL_URL`

The callback authority is fixed to `https://ordax.com.br/account/mcp/github/callback`.

A setup redirect `installation_id` is never accepted as proof. Repository candidates must be recovered through the authenticated GitHub user API flow before selection.

## Account and Runtime release state

The Account GitHub bridge is implemented in `ordax-os` #2558. The Owner binding-intent bridge is implemented in `ordax-os` #2560 (`9e8a060cd89814858c828c0aaa3452e332305a01`) and is guarded by its own `ORDAX_MCP_OWNER_PROJECT_DEVICE_BINDING_ENABLED` flag.

The Account browser must never submit `local_project_ref`, local path, capability ceiling or grant information. Its only binding action is the Owner request for `project_id + device_id`.

The Runtime/Device Agent remains the sole owner of local Project registration and confirmation. It must read the pending Device transport intent, resolve an already-registered local Project Catalog id (`project-N`) and only then confirm through the canonical Device transport. No browser, model or Account gateway may fabricate that confirmation.

Until the Device Agent path is proven end-to-end, both the Platform binding flag and the Account binding flag must remain disabled.

## Remaining boundary after backend binding

- compose the Device Agent/Runtime polling + local Project registration confirmation against the new Device transport;
- keep the Account #2560 binding-intent flag off until that Runtime proof exists;
- configure and verify the real GitHub App/callback release without exposing provider credentials;
- handle GitHub installation/repository revocation and rename so stale `ordax_project_connections` cannot authorize new work;
- expose grants only as later explicit Owner decisions after `ready_without_grants`;
- prove the complete path with a real GitHub installation, local Project registration, explicit binding, explicit grants and signed Runtime receipts.

Existing `ordax_project_executor`, `ordax_edge_executor`, `authenticated`, `service_role`, Studio and Surface must not acquire direct table writes or a generic create-connection/binding RPC.

## User-facing progression

Canonical durable onboarding state:

`needs_space` → `needs_project` → `needs_github_installation` →
`needs_repository_selection` → `needs_device_binding` →
`ready_without_grants` → explicit grants → executable scoped actions.

`awaiting_device_confirmation` is short-lived intent coordination state, not a durable Project readiness state.

States are derived from canonical reads, never local UI flags. GitHub repository selection, Device Agent binding and each Product grant remain separate affirmative actions.

## Release gates

- No direct table permissions for browser, Studio, general edge or project executor roles.
- Reject spoofed repository/installation IDs, reused OAuth state, duplicate provider candidates, cross-Owner Project, wrong device, archived Project, mismatched Space and ambiguous connection.
- Never persist GitHub access/refresh tokens or PKCE verifier.
- Never retry an uncertain OAuth completion, repository selection or binding-intent mutation as a fresh action.
- Repository selection and Device binding transactions fail atomically on conflict.
- A Device confirmation must come through enrolled Device authentication and an already registered opaque `project-N`, never a path.
- Revocation must prevent later enqueue; Runtime reconnect must not resurrect authority.
- `process.list` requires project scope plus project-native process grant.
- `terminal.exec` requires the distinct `terminal.exec` grant.
- Positive E2E requires a real verified GitHub App installation, explicit Device Agent binding, explicit grants and signed action receipts.

## Existing implementations reused

- `control-plane/supabase/migrations/20261007193000_space_authority_v1.sql`
- `control-plane/supabase/migrations/20261007193500_project_authority_v1.sql`
- `control-plane/supabase/migrations/20261007194000_project_connection_contract_hardening_v1.sql`
- `control-plane/supabase/migrations/20261016141000_owner_project_scope_resolver_v1.sql`
- `control-plane/supabase/migrations/20261113214943_owner_project_onboarding_authority_v1.sql`
- `control-plane/supabase/migrations/20261113223950_owner_github_installation_authority_v1.sql`
- `control-plane/supabase/migrations/20261113235000_owner_project_device_binding_authority_v1.sql`
- `control-plane/cloudflare/src/product_owner_project_scope.ts`
- `control-plane/cloudflare/src/product_owner_project_onboarding.ts`
- `control-plane/cloudflare/src/product_owner_github_authorization.ts`
- `control-plane/cloudflare/src/product_owner_grant_admin.ts`
- `control-plane/cloudflare/src/product_device_transport.ts`

This contract does not authorize direct database inserts from browser-facing roles, grant escalation, auto-enrollment or release before real end-to-end proof.
