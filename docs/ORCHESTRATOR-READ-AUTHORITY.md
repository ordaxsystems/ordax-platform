# Orchestrator Lab: Product read authority

Platform owns this authority; Runtime owns the managed launcher and App bridge.
The existing App service and read-only catalog remain owned by Apps #268.

## Contract

`POST /v3/device/transport/orchestrator-read-authorization` uses the existing
device token authentication and accepts only the seven execution-fence fields:
job, effect, attempt, lease, epoch, agent instance and boot. Device identity is
taken from authenticated transport, never from the body. Owner, OAuth client,
grant, app, capability, project and installation cannot be supplied by a model.

The edge-only PostgreSQL RPC derives subject/client/grant from the running
action. It requires exact fences, live lease/request, eligible Auth account,
active OAuth consent/client and the current canonical grant resolver result.
Only device-scoped `orchestrator.app_read` / `read` under
`orchestrator-app-read` is accepted. Computer Control cannot authorize it.

The result `ordax.orchestrator-read-authorization/1` identifies only
`br.com.ordax.orchestrator.lab`. Expiry is bounded by grant, action, execution
lease and five minutes. Runtime resolves this afresh before bootstrap, reads,
result disclosure and renewal; it rejects foreign/stale/malformed replies and
completed/replaced jobs. No cached grant or model-authored receipt is accepted.

No grant, task, table, install or public MCP tool is created by this migration.
The owner profile is available in source only; the public catalog and release
SSOT are unchanged. Runtime's port is not registered as an executable action.

## Validation and rollout

Tests execute the new migration plus the existing canonical grant resolver and
Auth eligibility function in PostgreSQL/PGlite with isolated fixture tables.
They exercise happy path, all eight fences, expiry, consent/client/account/
device/grant revocation, foreign capabilities, write mode and executor ACLs.
The checked-in postflight verifies the installed function and privileges
without creating data. HTTP tests check device authentication and rejection of
model identity fields. Runtime tests cover fresh checks and late disclosure.

Local: 282 Node tests passed. Broad Python discovery has six failures and one
setup error already reproduced on unchanged main (retired route/source tests).
The canonical migration was applied once as ledger version `20261021184429`
after source PR #264 was opened. The read-only postflight passed against the
installed function: anon/authenticated/service_role cannot execute; the
canonical edge executor and its inheriting runtime login can execute. Invalid
execution context returns denial. No test grant or task was created live.
Security advisors showed no new findings relative to the preflight baseline.
Do not conceal those results or change unrelated product contracts.

Rollout follows `control-plane/supabase/README.md`: branch/PR first, migration
exactly once, ledger version/blob pinned, postflight, then integration checks.
The Worker is not deployed by creating this source PR. Verified installation
registration/provenance, actual job executor, public MCP projection and live
account/device E2E remain prerequisites. Full 24h supervision is not enabled.

## First public read

`orchestrator_lab_status` is a read-only public MCP action that enqueues the
device-scoped `orchestrator.app_read` capability. It accepts device selection and
completion wait only; the action payload is empty. The attested boundary requires
the `orchestrator-app-read` profile and rejects generic computer profiles even if
they contain the capability. Runtime owns verified installation lookup and status
execution. Source registration does not deploy the Worker or install the App.
