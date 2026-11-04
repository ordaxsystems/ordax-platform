# OrdaX MCP — Owner device console contract v1

## Canonical owners
- Platform (ordax-platform): identity, consent, devices, grants, revocation, and session choice.
- Runtime (ordax-runtime): local agent, execution, policy and Windows lifecycle.
- Site (ordax-site): the existing signed-in My Account user interface.
- OS (ordax-os): existing same-origin Account gateway between browser and Platform.
- Studio: optional consumer only; not an identity, grant or install authority.

## Existing and new Platform operations

- GET /v3/owner/devices — NEW. Owner-only read. No device/client/owner query parameters. PostgreSQL source of truth is the existing device and presence tables; maximum 200 devices. Returns schema ordax.owner-mcp-devices/1 with count and devices. Each device has device_id, name, kind, channel, state, online, last_seen_at and runtime_ready. Online/ready is an observation, not execution authorization.
- GET /v3/owner/remote-authority?device_id=UUID — EXISTING. Canonical Owner list of consented OAuth clients and exact grant groups for one selected device.
- DELETE /v3/owner/remote-grant-groups/GROUP_UUID?client_id=CLIENT_UUID — EXISTING. Revokes only that Owner/client/grant group; no local policy change.

The new owner inventory RPC ordax_owner_mcp_devices_v1(uuid) is accessible to ordax_edge_executor only. Public, anon, authenticated, and service_role have no execute permission. Owner eligibility and ownership filtering happen in SQL after the same signed Owner authentication as the existing grant endpoints. No second database, credentials, OAuth system or grants registry.

Example inventory response (fictional data, not a live device):
{
  "ok": true,
  "schema": "ordax.owner-mcp-devices/1",
  "count": 1,
  "devices": [{
    "device_id": "11111111-1111-4111-8111-111111111111",
    "name": "Desktop",
    "kind": "desktop",
    "channel": "development",
    "state": "active",
    "online": true,
    "last_seen_at": "2026-11-03T18:00:00Z",
    "runtime_ready": true
  }]
}

## Public Account gateway handoff

The Account browser never receives the Owner bearer or calls mcp.ordax.com.br cross-origin. Reuse the existing signed same-origin Account gateway owned by ordax-os; its currently implemented usage bridge is /account/usage/mcp. Proposed explicit, separately authorized routes:

1. GET /account/mcp/devices: validates signed Account session, calls the fixed Platform owner inventory endpoint and validates schema, count, distinct IDs and bounded JSON size.
2. GET /account/mcp/authority?device_id=UUID: lazy-loads existing exact-device grants only after user selects a device. Do not issue up to 200 SQL requests on the initial device listing.
3. POST /account/mcp/revoke: requires signed Account session, CSRF/origin checks and confirmation of exact client UUID, device UUID and grant-group UUID. The server calls the existing DELETE. It re-reads the same device after a confirmed result. Never replay an ambiguous mutation automatically.

Presentation uses the already established Minha Conta sections Meus dispositivos and Integracoes. The name ChatGPT may refer to multiple distinct consented OAuth client UUIDs; show the distinct client IDs. Revoking one grant must not affect another device or client. Do not claim a missing/unknown device was revoked. Device credential removal is a separate operation and is NOT implemented here.

## Rollout and persistence constraints

Implemented in local source with unit and PGlite tests: owner inventory API, SQL isolation and existing revocation re-use. NOT deployed: PostgreSQL migration or Cloudflare Worker. NOT finished: public Account gateway, browser panel, end-to-end revocation proof. No local Runtime files, credentials or grants changed.

The Central session binding currently expires after 30 minutes even though grants remain valid. Durable target choice needs a separate explicit Owner preference with revocation and eligibility checks. Do NOT silently choose the sole online computer from several consented devices; presence is not authorization. This console work does not weaken that invariant.
