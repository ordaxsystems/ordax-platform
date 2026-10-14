# OrdaX Intelligence — Relay transport boundary

**Status:** source-only compatibility boundary; not mounted in the public Worker, MCP, Relay submit allowlist, Product action catalog or provider path.

This document records the first Platform-side transport slice that follows the Web boundary merged in `ordaxsystems/ordax-os#1765`. It does **not** make OrdaX Web inference available and does not transfer ownership of Intelligence to Platform.

## Ownership

The canonical owners remain:

- `ordax.intelligence/1` — `ordaxsystems/ordax-os`;
- `ordax.model-router/1` — `ordaxsystems/ordax-os`;
- persistent Memory and authorized context policy — `ordaxsystems/ordax-os`;
- Product identity, exact client/device targeting, grants, durable queue/idempotency, audit and receipts — `ordaxsystems/ordax-platform`;
- device/host execution bridge — `ordaxsystems/ordax-runtime` plus the OS-owned runtime it is allowed to reach.

Platform must never call a model provider, `llama.cpp`, local-AI bridge or Memory directly in order to satisfy a Web Intelligence request. A future production transport must reach the OS-owned Intelligence runtime, which remains responsible for routing and consultative response semantics.

## Current source boundary

`control-plane/cloudflare/src/product_intelligence_relay_contract.ts` performs only two operations:

1. validate the already-canonical `ordax.web-intelligence-remote-request/1` envelope against the bounded request shape currently published by `ordax.intelligence/1`;
2. require an exact match with a separately supplied trusted binding containing Product subject, authenticated client, selected device, authorized presentation context and a host-persisted operation UUID.

The binding is not reconstructed from prompt text, model output, tool JSON, arbitrary headers or a provider response. The module cannot issue grants, discover a target, enqueue a job, return a receipt, choose a provider or execute inference.

### Context is not grant scope

Intelligence presentation context is hierarchical:

```text
account/device:  spaceId = null, projectId = null
Space:           spaceId = UUID, projectId = null
Space+Project:   spaceId = UUID, projectId = UUID
invalid:         spaceId = null, projectId = UUID
```

This shape deliberately differs from current Product grant-group scope. A Space-only Intelligence conversation does not create a Space-only Product grant. The future trusted transport owner must prove membership/continuity and whatever Product authorization is required, then supply the exact trusted binding. The Web envelope itself is never authorization.

## Reused Relay authorities

No second gateway is planned. A later activation slice must reuse the existing canonical owners documented in `RELAY-CANONICAL-AUTH.md`:

- Product OAuth/client authentication;
- canonical target discovery;
- PostgreSQL grant resolution;
- the existing Product queue and durable idempotency/effect ledger;
- Product audit and receipts;
- existing Runtime `ordax.product.invoke` transport where appropriate.

The existing `intelligence.app_catalog` and `intelligence.app_detail` Product actions are Application Intelligence metadata. They are **not** model inference and must not be aliased to `ordax.intelligence/1`.

## Why `intelligence.respond` is not enabled yet

There is no production background executor that exposes the canonical OS-owned `ordax.intelligence/1` runtime to the Product transport today. Native composition creates the Intelligence runtime inside the OS composition; directly targeting a provider or the Native local-AI loopback bridge would bypass the Intelligence/model-router owner.

Therefore this slice intentionally does **not**:

- add `intelligence.respond` to `PRODUCT_READ_ONLY_ACTIONS`, Relay capabilities, MCP tools or Worker routes;
- import this contract from `index.ts` or `mcp_http.ts`;
- add a grant profile, queue, table, Durable Object or D1 fallback;
- add provider credentials, provider selection, egress or Memory access;
- claim deployment, credentialed E2E or physical Stable proof.

Regression tests fail if this source-only boundary becomes advertised through the current Product action/Relay/MCP/Worker surfaces.

## Compatibility rule

The Platform boundary mirrors only the transport-visible bounds required to reject malformed/unbounded input before a future dispatch. `ordax.intelligence/1` remains the semantic authority. If its schema or bounds change, Platform must perform an explicit compatibility review and update tests; permissive fallback parsing or silent version coercion is forbidden.

Current validated request limits:

- intents: `ask`, `explain`, `summarize`, `diagnose`;
- prompt: 32,000 characters;
- context: at most 16 entries;
- each context text: 8,192 characters;
- total context text: 65,536 characters;
- provenance: 512 characters;
- `maxTokens`: integer 1–2,048;
- response authority remains an OS concern and must stay `none` when the future result path is implemented.

## Next gate

Before this boundary may be connected to a public or same-origin transport:

1. expose/reach the OS-owned `ordax.intelligence/1` runtime through a reviewed background execution boundary without bypassing the model router;
2. define how Product/session authority resolves the trusted Intelligence context, including Space-only membership/continuity, independently from Product grant-group shape;
3. reuse canonical Product enqueue/idempotency/audit/receipt owners rather than creating an Intelligence queue;
4. prove revocation, logout, target change, context change, unknown outcome and replay behavior;
5. run deployed credentialed E2E against a real authorized device;
6. only then compose the remote Web adapter from `ordax-os#1765` and change product availability from fail-closed.

Until those gates are met, absence of remote Intelligence remains the correct product behavior.
