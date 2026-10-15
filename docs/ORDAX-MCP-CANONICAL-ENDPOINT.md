# OrdaX MCP — endpoint canônico e papel arquitetural

## Serviço oficial

**Identidade externa:** `OrdaX`  
**Endpoint canônico atual:** `https://mcp.ordax.com.br/mcp`  
**Worker:** `ordax-mcp`  
**Owner de código:** `ordaxsystems/ordax-platform`  
**Entrypoint:** `src/product_mcp_entry.ts`  
**Transporte:** Streamable HTTP  
**Auth:** OAuth 2.1 / Supabase Auth  
**Autoridade persistente:** PostgreSQL via Hyperdrive `POSTGRES`

O endpoint está ativo externamente e o domínio/TLS já foram comprovados por smoke público. O Worker canônico continua em modo **read-only canary** e `supports_remote_actions=false` até concluir OAuth real, vínculo de dispositivo/grants e E2E ChatGPT → Runtime.

A fonte de verdade permanece `control-plane/cloudflare/production-foundation.json#mcp_release`. `workers.dev` fica desabilitado para o MCP oficial, D1 não é autoridade do novo MCP e não existe fallback para o Worker legado.

## Não confundir MCP com OrdaX Central

O MCP canônico pertence ao **Modo 1 — ChatGPT direto do usuário** descrito em `docs/ORDAX-AI-CONNECTION-MODES.md`.

```text
Usuário -> conta ChatGPT do usuário -> MCP OrdaX -> Runtime/Studio autorizado
```

Neste modo, o OrdaX não recebe a mensagem do usuário para chamar um modelo em nome dele. O ChatGPT já é o ambiente de conversa/inferência e chama o MCP somente para acessar capacidades OrdaX.

O Worker pode executar autenticação, descoberta de targets, grants, auditoria e coordenação/atestado de sessão. Isso **não** o transforma no OrdaX Central de inferência.

O **Modo 2 — OrdaX Central** é outro caminho de conversa:

```text
Apps/PCs -> OrdaX Central -> Model Router/provedor -> Central -> origem correta
```

A Central pode reutilizar identidade, Runtime, grants, contratos de tools e auditoria, mas não deve ser inserida obrigatoriamente no caminho do MCP direto.

Os nomes históricos `product_central_*` presentes em partes do código atual representam mecanismos de sessão/coordenação legados em nomenclatura. Não significam automaticamente o produto OrdaX Central de inferência.

## URL versus túnel

No ChatGPT, o MCP é cadastrado como uma **Server URL** HTTPS. O transporte que torna essa URL alcançável pode variar:

- validação atual: `https://mcp.ordax.com.br/mcp`, Worker público Cloudflare;
- futuro direto por dispositivo: URL HTTPS estável por dispositivo terminando no Runtime por conexão/túnel seguro iniciado pelo dispositivo.

Logo, “usar URL” e “usar túnel” não são conceitos opostos: uma URL pública pode ser a ponta externa de um túnel. O produto não deve depender de URLs temporárias de demonstração como identidade estável.

## Segurança atual

A superfície publicada continua restrita a:

- `ordax_session`
- `ordax_profile`
- `ordax_targets`
- `ordax_action_status`

Ações de computador, terminal, arquivos mutáveis, browser, Blender, Unity, mouse e teclado permanecem indisponíveis no MCP público até a promoção explícita com grants e E2E.

Bloqueios atuais de release continuam registrados no SSOT. Nenhum deles deve ser contornado por `No Auth`, credenciais fixas, D1, `workers.dev`, sessão compartilhada ou fallback legado.

## Evidência live

- Worker version: `95c5b0cd-3f65-4cee-8d02-46f6bc1a91bb`
- smoke externo: `https://github.com/ordaxsystems/ordax-platform/actions/runs/38705274585`
- `GET /health`: público e read-only
- `/v3/device/setup` sem autenticação: rejeita com `401 product_auth_required`

Estado em 15/10/2026: **endpoint público ativo, OAuth ChatGPT real ainda em validação, ações remotas bloqueadas**.
