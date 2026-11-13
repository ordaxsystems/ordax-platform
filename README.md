# OrdaX Platform

Canonical remote platform repository for OrdaX: provider-neutral Control Plane, OrdaX MCP, PostgreSQL/Supabase integration, Cloudflare edge foundation and provider connectors.

## Estado de continuidade MCP / Aura — 04/11/2026

**DEV Windows concluído:** a
[issue #291](https://github.com/ordaxsystems/ordax-platform/issues/291)
foi fechada em 04/11 com ações e recibos reais via ChatGPT MCP
no Windows físico; cinco credenciais/devices DEV obsoletos foram
revogados, e dois dispositivos atuais foram preservados.
[PR #336](https://github.com/ordaxsystems/ordax-platform/pull/336)
está integrada. **Não refazer** cleanup/inscrição/grants
como um projeto ainda aberto. Não confundir esse E2E Windows
com homologação da Aura, do OrdaX Desktop Native ou de toda
a superfície de ferramentas.

**Lacuna transversal ativa, outro owner:** a Aura lê a
Store `CURRENT` do OS; `ordax-runtime/intelligence.app_catalog`
pode consultar um registro empacotado **não sincronizado**
com instalações atuais. A reconciliação autenticada Native
pertence a [OS #2400](https://github.com/ordaxsystems/ordax-os/pull/2400)
e aos owners OS/Runtime. A Platform só expõe grants e
Device/Owner reais; não manter inventário de apps duplicado
nem traduzir `authority=none` em concessão OAuth.
[OS #2405](https://github.com/ordaxsystems/ordax-os/pull/2405)
é uma release separada de Conta/Owner, gated em
Supabase/Vercel/Worker. Não publicar Worker ou habilitar
flags por esse handoff.

**Leitura atual para agentes:**
[`ordax-os/INTELLIGENCE-HANDOFF.md`](https://github.com/ordaxsystems/ordax-os/blob/main/INTELLIGENCE-HANDOFF.md).
Os números de tools descritos abaixo são **catálogos de
um corte** e nunca correspondem automaticamente ao conjunto
habilitado em cada Device ou visível na conexão existente.

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

The current direct Product MCP catalog advertises **51 tools**: account/session/discovery/status, device-scoped Computer Control, project-scoped terminal/process, and six explicitly scoped repository/project continuity tools (`repository_catalog`, `project_briefing`, `continuity_state`, `continuity_update`, `handoff_create`, `handoff_get`). Continuity uses the existing Runtime store, never a second Platform persistence authority. Grant checks and canonical PostgreSQL owner/device/Space/project/repository binding are required independently; no ChatGPT Web conversation scraping or model relay is enabled. This describes the server-side catalog, **not** the tools loaded by a previously connected ChatGPT conversation or the grants of a device. On 2026-10-19 the server advertised 44 while this conversation exposed 37; the missing seven were native **device** tools (issue #216). Never infer execution authority from tool availability or total count. The release SSOT has `supports_remote_actions=true`, while execution remains fail-closed behind OAuth identity, grants, device attestation and local Runtime policy. See [Product MCP connection and terminology](docs/PRODUCT_MCP_CONNECT.md).

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
- A confirmed Product-MCP conversation→device binding is persistent routing, not a 30-minute authorization lease; OAuth consent, grants and explicit revocation are revalidated instead of using inactivity as security.
- Generic shell execution must not replace typed file, Git, browser, desktop, Blender or Unity APIs.
- Source tests do not by themselves prove a live-device E2E release.

The release source of truth is `control-plane/cloudflare/production-foundation.json#mcp_release`.

## Repository identity

Canonical repository: `ordaxsystems/ordax-platform`.

`ordaxsystems/ordax-control-plane` is the immediately previous repository name after the organization transfer. GitHub redirects are compatibility only and must not be used as a source of truth.

Migrated from `washingtonmsdj/mcp-blender` at commit `ce31808f950e04207f028c5925cca2da17d18553` on 2026-10-05.
