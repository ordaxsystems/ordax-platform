# OrdaX MCP — endpoint canônico e papel arquitetural

## Serviço oficial

**Identidade externa:** `OrdaX`  
**Tipo no ChatGPT:** servidor MCP personalizado  
**Endpoint canônico:** `https://mcp.ordax.com.br/mcp`  
**Worker:** `ordax-mcp`  
**Owner de código:** `ordaxsystems/ordax-platform`  
**Entrypoint:** `control-plane/cloudflare/src/product_mcp_entry.ts`  
**Transporte:** Streamable HTTP  
**Auth:** OAuth 2.1 / Supabase Auth  
**Autoridade persistente:** PostgreSQL via Hyperdrive `POSTGRES`

A nomenclatura de produto é **Servidor MCP personalizado do OrdaX** ou, de forma curta, **OrdaX MCP**. A área da interface do ChatGPT pode aparecer sob “Plugins”, e o repositório ainda contém arquivos internos com `plugin` no nome por compatibilidade de empacotamento/review, mas isso não muda a identidade da integração.

A configuração e o fluxo de atualização estão em [CHATGPT-CUSTOM-MCP-SERVER.md](CHATGPT-CUSTOM-MCP-SERVER.md).

## Estado observado — 18/10/2026

A fonte de verdade `control-plane/cloudflare/production-foundation.json#mcp_release` registra:

- `supports_remote_actions=true`;
- `validation_mode=attested-interactive-candidate`;
- `validation_deployment_ready=true`;
- autoridade PostgreSQL;
- `workers.dev=false` para o serviço oficial;
- domínio canônico `mcp.ordax.com.br`;
- OAuth canônico já com evidência de consentimento do cliente ChatGPT.

O MCP publicado e autenticado, observado no ChatGPT em 18/10/2026, reporta **30 tools**. O candidato da PR #212 propõe **37 tools** após upgrade compatível do Runtime e autorização explícita. A superfície já inclui sessão, perfil, targets, status, observação do desktop e Computer Control tipado. Portanto, os documentos não devem mais afirmar que o MCP atual é “read-only canary”.

Isso ainda **não equivale a release irrestrita de controle remoto**. O SSOT mantém os seguintes blockers de readiness para a promoção final:

- `interactive_computer_grant_not_authorized`;
- `attested_interactive_end_to_end_not_verified`;
- `canonical_remote_actions_release_not_verified`.

Em outras palavras: as tools podem estar publicadas no catálogo enquanto um target específico continua sem grants de interação. Catálogo, autorização e execução são estados diferentes.

## Superfície publicada

As 30 tools atualmente observadas no MCP de produção são:

### Identidade e descoberta

- `ordax_session`
- `ordax_profile`
- `ordax_targets`
- `ordax_action_status`

### Observação e política local

- `computer_windows`
- `computer_active_window`
- `computer_screenshot`
- `computer_screen_info`
- `computer_access_status`
- `computer_processes`

### Sistema de arquivos, leitura e edição tipadas

- `computer_file_stat`
- `computer_directory_list`
- `computer_text_read`
- `computer_search`
- `computer_text_write`
- `computer_text_patch`
- `computer_directory_create`
- `computer_path_move`
- `computer_path_remove`

### Interação tipada

- `computer_focus_window`
- `computer_click`
- `computer_mouse_move`
- `computer_drag`
- `computer_launch_app`
- `computer_scroll`
- `computer_type`
- `computer_hotkey`
- `computer_clipboard_read`
- `computer_clipboard_write`
- `computer_terminate_process`

**Candidato de integração (ainda não promovido):** `terminal_exec`, `process_status`, `process_list`, `process_logs`, `process_start`, `process_write_stdin` e `process_stop` são ações de projeto, não herdam `full-computer-control`; exigem a prova canônica do Git origin, a associação Space/projeto, o perfil Owner `project-native-terminal` ou `project-native-process` e Runtime com suporte à atestação. Essa fronteira reutiliza o executor `terminal.exec`/supervisor `process.*` existente. O candidato não cria outro daemon, MCP ou banco de grants. Um terminal não deve ser simulado por `computer_type`.

**Ordem de liberação:** (1) Runtime com contrato de projeto comprovado; (2) Studio com consentimento e grants PostgreSQL explícitos; (3) canary E2E autenticado executando argv inofensivo; (4) verificação de receipts e revogação; (5) promoção da Platform e atualização de ferramentas no ChatGPT. O merge isolado da Platform não comprova disponibilidade de execução.

A publicação de uma tool só torna seu contrato descobrível pelo cliente. A execução continua condicionada a OAuth, target, grant, sessão atestada, Runtime online, política local e validação dos argumentos.

## Atualização do servidor no ChatGPT

A URL pública é estável e não deve mudar a cada release:

```text
https://mcp.ordax.com.br/mcp
```

Atualizações internas do Worker/Control Plane/Runtime que preservam o catálogo e os schemas das tools são transparentes ao cadastro existente.

Quando o catálogo ou schema MCP mudar, a ação esperada no ChatGPT é **Atualizar ferramentas** nas configurações do servidor MCP. Isso faz o cliente reler a superfície publicada; não reinstala o Runtime, não troca a URL e não concede capabilities adicionais.

Não criar `/mcp-v2`, `/mcp-v3` ou um novo cadastro apenas para versionar ferramentas. Contratos devem ser versionados internamente e mudanças incompatíveis precisam de migração explícita.

## Não confundir MCP com OrdaX Central

O MCP canônico pertence ao **Modo 1 — ChatGPT direto do usuário** descrito em `docs/ORDAX-AI-CONNECTION-MODES.md`.

```text
Usuário -> conta ChatGPT do usuário -> MCP OrdaX -> Runtime autorizado
```

Neste modo, o OrdaX não recebe a mensagem do usuário para chamar um modelo em nome dele. O ChatGPT já é o ambiente de conversa/inferência e chama o MCP somente para acessar capacidades OrdaX.

O Worker pode executar autenticação, descoberta de targets, grants, auditoria e coordenação/atestado de sessão. Isso **não** o transforma no OrdaX Central de inferência.

O **Modo 2 — OrdaX Central** continua sendo outro caminho de conversa:

```text
Apps/PCs -> OrdaX Central -> Model Router/provedor -> Central -> origem correta
```

A Central pode reutilizar identidade, Runtime, grants, contratos de tools e auditoria, mas não deve ser inserida obrigatoriamente no caminho do MCP direto.

## URL versus túnel

No ChatGPT, o MCP é cadastrado como uma **URL de servidor HTTPS**. O transporte que torna essa URL alcançável pode variar internamente.

Hoje a identidade externa permanece `https://mcp.ordax.com.br/mcp`, servida pelo Worker Cloudflare. Um futuro transporte direto/atestado por dispositivo pode usar conexão ou túnel seguro iniciado pelo próprio Runtime sem alterar a identidade pública do produto.

Logo, “usar URL” e “usar túnel” não são conceitos opostos: uma URL pública pode ser a ponta externa de uma topologia de transporte segura.

## Segurança

Regras que permanecem obrigatórias:

- OAuth canônico; nenhum bypass `No Auth`;
- PostgreSQL como autoridade persistente do MCP novo;
- nenhuma autoridade D1 paralela;
- nenhum fallback para Worker legado;
- nenhuma sessão compartilhada entre usuários/clientes;
- grants por capability e, quando aplicável, por Space/projeto;
- política local do Runtime como uma segunda fronteira de autorização;
- ações gráficas de computador limitadas e tipadas; terminal nativo somente com grant de projeto específico, sem transformar `computer.type` em shell;
- auditoria e status/receipt para ações remotas;
- nenhuma promoção final sem E2E atestado.

`workers.dev` permanece desabilitado para o endpoint oficial e a identidade estável do serviço é o domínio canônico.

## Evidência e SSOT

A fonte de verdade de release é `control-plane/cloudflare/production-foundation.json#mcp_release`. No baseline registrado em 16/10/2026 ela registra `supports_remote_actions=true`, candidato interativo atestado e blockers explícitos para a promoção final.

A verificação funcional do cliente deve sempre distinguir:

1. tool presente na superfície MCP;
2. sessão OAuth válida;
3. target descoberto;
4. capability realmente concedida ao target;
5. Runtime alcançável;
6. ação concluída com resultado verificável.

Não inferir o passo seguinte apenas porque o anterior está verde.
