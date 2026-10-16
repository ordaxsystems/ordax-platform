# OrdaX Platform

Canonical remote platform repository for OrdaX: provider-neutral Control Plane, OrdaX MCP, PostgreSQL/Supabase integration, Cloudflare edge foundation and provider connectors.

## ChatGPT integration

The user-facing integration with ChatGPT is the **OrdaX custom MCP server** (**OrdaX MCP**), not a separate OrdaX “plugin” product.

Current ChatGPT setup:

- type: **Custom MCP server**;
- canonical URL: `https://mcp.ordax.com.br/mcp`;
- transport: Streamable HTTP;
- authentication: OAuth;
- persistent authority: PostgreSQL;
- device execution: OrdaX Runtime on the authorized target.

The ChatGPT navigation may expose custom MCP servers inside the **Plugins** area. Internal repository paths such as `plugins/ordax-chatgpt/`, `plugin.json`, packaging workflows and historical test names remain compatibility/packaging details; they are not the product name.

See:

- [ChatGPT custom MCP server contract and update model](docs/CHATGPT-CUSTOM-MCP-SERVER.md)
- [Canonical MCP endpoint and current surface](docs/ORDAX-MCP-CANONICAL-ENDPOINT.md)
- [Connection architecture](docs/PRODUCT_MCP_CONNECT.md)
- [Computer Control policy](docs/COMPUTER_CONTROL_POLICY.md)
- [Provider and OS Intelligence boundaries](docs/ORDAX_PROVIDER_CONNECTORS.md#relationship-to-ordax-os)

## Current MCP boundary

The canonical MCP endpoint belongs to the direct-user ChatGPT path:

```text
User's ChatGPT
  -> OAuth
  -> https://mcp.ordax.com.br/mcp
  -> OrdaX Control Plane / grants / audit
  -> authorized OrdaX Runtime
  -> device capabilities
```

Platform owns remote protocol, OAuth verification, grant resolution, queueing/status, audit and the MCP projection. Runtime owns execution on the device. Apps/Studio own their product UI and local project experience. The OS owns native OS/Web composition.

The MCP tool catalog and the target's authorization are deliberately separate. A tool can be discoverable by ChatGPT while a specific device still lacks the grant needed to execute it. OAuth identity, target discovery, capability grant, local Runtime policy, reachability and action result must each be validated independently.

As of 2026-10-16 the authenticated ChatGPT MCP surface reports 18 tools: session/profile/targets/action status plus typed Windows observation and Computer Control. The release SSOT has `supports_remote_actions=true`, while final promotion remains fail-closed behind explicit grant and attested E2E gates.

## Updating the ChatGPT MCP server

The endpoint remains stable across releases. Backend, Worker and Runtime implementation updates do not require a new URL.

When the MCP tool catalog or a relevant tool schema changes, the ChatGPT registration should use **Update tools** / **Atualizar ferramentas** to rediscover the published surface. This refresh does not grant new device permissions and does not replace OAuth or Runtime updates.

Do not create `/mcp-v2`, `/mcp-v3` or duplicate ChatGPT registrations merely to version tool changes. Version contracts internally and use explicit compatibility gates for breaking changes.

## Architecture rules

- PostgreSQL is the persistent authority for the canonical MCP path.
- D1 is not a parallel authority for the new MCP.
- No legacy Worker fallback is allowed for authorization or execution.
- `workers.dev` is not the identity of the official MCP endpoint.
- OAuth, grants and local Runtime policy remain fail-closed.
- Generic shell execution must not replace typed file, Git, browser, desktop, Blender or Unity APIs.
- Source tests do not by themselves prove a live-device E2E release.

The release source of truth is `control-plane/cloudflare/production-foundation.json#mcp_release`.

## Repository identity

Canonical repository: `ordaxsystems/ordax-platform`.

`ordaxsystems/ordax-control-plane` is the immediately previous repository name after the organization transfer. GitHub redirects are compatibility only and must not be used as a source of truth.

Migrated from `washingtonmsdj/mcp-blender` at commit `ce31808f950e04207f028c5925cca2da17d18553` on 2026-10-05.
