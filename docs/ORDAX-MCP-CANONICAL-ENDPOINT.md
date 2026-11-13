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

## Estado e fontes canônicas — 13/11/2026

O contrato oficial continua em `control-plane/cloudflare/production-foundation.json#mcp_release`, com PostgreSQL/Hyperdrive, OAuth 2.1, domínio `mcp.ordax.com.br` e um único Worker `ordax-mcp`. `supports_remote_actions=true` não significa `deployment_ready=true`: o guard de produção exige provas autenticadas de grants, atestação e ações reais.

### Inventário de ferramentas: não duplicar

O inventário de ferramentas **não é mantido neste documento**. A fonte de verdade é `control-plane/cloudflare/src/mcp_http.ts` (`tools/list`), filtrada pelo roteamento atestado em `product_mcp_entry.ts`. A ferramenta `ordax_session` anuncia revisão, contagem e, na revisão candidata, `mcp_tool_names` derivados do mesmo inventário. O cliente GPT pode receber um subconjunto: somente a comparação por nomes permite distinguir uma revisão antiga de filtragem pelo host.

Na verificação autenticada de 12/11/2026, a versão pública reportou **51 ferramentas** e esta conversa recebeu **44**. Esse dado é uma observação temporal, não uma lista fixa ou garantia de atualização. A versão do Worker ainda não incorporava as PRs #346/#347; publicar código novo exige o gate completo e atualizar a conexão não concede grants.

### Permissões e prova de execução

Em 12/11/2026, `computer.terminal_exec` foi executado no `DESKTOP-4UFL03B` pelo MCP público: comando inofensivo, `status=succeeded`, saída correta e código 0. Isso demonstra somente aquele caminho autenticado até o Runtime; **não comprova** transferência de arquivos, revogação, funcionamento multidispositivo nem os sete recibos independentes exigidos pelo gate de produção.

Os grants Owner são snapshots explícitos, não aliases dinâmicos de perfil. Quando um perfil (`full-computer-control`, por exemplo) recebe novas ações `computer.transfer_*`, os grants anteriores não as herdam. A projeção de `ordax_targets` pode indicar a divergência com `profile_alignment` calculado diretamente do catálogo canônico `OWNER_MCP_GRANT_PROFILES`; esse aviso nunca autoriza, executa ou altera um grant. O proprietário deve revisar e conceder novamente o perfil pelo fluxo Owner existente.

A validação física de 13/11/2026 encerrou três lacunas de candidato que não devem voltar a aparecer como bloqueadores: o grant interativo está autorizado, o caminho atestado foi exercitado E2E no Desktop Windows e ações remotas canônicas foram concluídas com recibos reais. Isso **não** equivale à promoção de produção: `validation_evidence.production_release_authority=false` existe justamente para separar validação funcional de evidência formal de release.

Na mesma data, o Runtime físico foi atualizado pelo lifecycle canônico para `7a1be0cb24b2b32d0ef24ad953e2a3338fab2260` (transação `8804f522f7784713827261ee141d5561`, `committed`). O update preservou uma única instalação: um `ORDAX Runtime.exe` e seu Python embutido no mesmo install root, readiness local/transport/Product pronta. A regressão `action_expired` por wake perdido foi reproduzida antes da correção e validada depois dela: durante um terminal de 76,8 s, ações independentes foram reivindicadas em 8,925 s, 1,885 s e 11,916 s; houve **zero** `action_expired` após o boot verificado. A regra canônica é: trabalho ativo mantém fallback de claim ≤18 s; somente Runtime realmente ocioso com wake já verificado pode usar reconciliação de 60 s, sempre abaixo do TTL de ação de 120 s.

O Worker legado principal `ordax-control-plane-v3` já estava ausente na conta oficial. Em 13/11/2026 o canário público histórico `ordax-control-plane-v3-canary` também foi aposentado; o domínio `mcp.ordax.com.br` permanece ligado somente a `ordax-mcp`. O arquivo de candidato continua existindo apenas para `wrangler --dry-run`, com nome `ordax-mcp-validation-candidate` e `workers_dev=false`, portanto não deve recriar uma superfície pública paralela.

Os bloqueios canônicos restantes são:

- `multi_device_end_to_end_not_verified`: ainda falta prova real com mais de um dispositivo elegível;
- `production_release_evidence_incomplete`: o conjunto independente de sete URLs de execução exigido por `REQUIRED_PROOFS` ainda não está completo. Isso inclui o comprovante formal de retirement em URL de workflow, embora a retirada física já esteja concluída.

O guard de produção continua fail-closed. Remover esses bloqueios sem preencher `release_evidence` com os sete comprovantes válidos e sem `device_dispatch_via_trusted_host_verified=true` continua rejeitado pelos testes. Não reintroduzir os antigos bloqueadores apenas por histórico documental: eles descreviam o estado anterior à validação física de 13/11.

**Candidato de integração (ainda não promovido):** `terminal_exec`, `process_status`, `process_list`, `process_logs`, `process_start`, `process_write_stdin` e `process_stop` são ações de projeto, não herdam `full-computer-control`; exigem a prova canônica do Git origin, a associação Space/projeto, o perfil Owner `project-native-terminal` ou `project-native-process` e Runtime com suporte à atestação. Essa fronteira reutiliza o executor `terminal.exec`/supervisor `process.*` existente. O candidato não cria outro daemon, MCP ou banco de grants. Um terminal não deve ser simulado por `computer_type`.

**Ordem de liberação:** (1) Runtime com contrato de projeto comprovado; (2) autorização Owner explícita via Studio **apenas no Windows** e, no OrdaX OS, via gerenciador de permissões **do próprio sistema**; (3) canary E2E autenticado executando argv inofensivo; (4) verificação de receipts e revogação; (5) promoção da Platform e atualização de ferramentas no ChatGPT. O merge isolado da Platform não comprova disponibilidade de execução.

### Autoridade e superfícies por sistema

- **OrdaX OS:** o sistema operacional é dono da política e dos serviços locais de permissões. O aplicativo Studio consome contratos públicos e não concede privilégios por conta própria, nem é dependência de boot, de uso da IA ou do MCP. A interface de consentimento Owner faz parte do sistema, não do Studio.
- **Windows com OrdaX Runtime:** o Studio fornece uma interface de autorização para o proprietário do PC, utilizando os endpoints Owner e a autoridade PostgreSQL já existentes; não é um segundo serviço de autorização nem um substituto da política Windows/Runtime.
- **Ambos:** grants remotos pertencem à autoridade Product/Platform e são associados a conta, cliente MCP, dispositivo, Space/projeto e capacidade. A política local do host é outra condição necessária. `full_access` local não cria automaticamente um grant de terminal remoto. O MCP nunca autoriza a si próprio.
- A resposta do MCP **não deve exigir Studio no OrdaX OS** nem assumir a presença de um aplicativo first-party para conceder permissão. Dicas de autorização devem apontar o responsável correto pelo ambiente. O texto de hints do catálogo é apenas orientação, não um mecanismo de concessão.


A publicação de uma tool só torna seu contrato descobrível pelo cliente. A execução continua condicionada a OAuth, target, grant, sessão atestada, Runtime online, política local e validação dos argumentos.

## Tarefas longas sem bloquear o MCP

`computer_terminal_exec` e `terminal_exec` são comandos **foreground**, mas o Runtime Product usa execução concorrente limitada — **não existe fila global serial**. Um comando longo ocupa apenas seu slot de job e os recursos que realmente conflitam com ele; leituras, metadados, outros projetos e ações independentes podem ser reivindicados e executados em paralelo. Exclusividade é aplicada somente onde existe conflito real (por exemplo, mesmo recurso de escrita, terminal/recurso incompatível, GUI/foco compartilhado ou lifecycle/update).

O fallback de claim também não pode transformar wake advisory em requisito para concorrência: com qualquer job ativo, novas ações independentes continuam sendo reconciliadas em até **18 segundos**. Somente quando o Runtime está realmente ocioso e já recebeu um wake autenticado na conexão atual a reconciliação pode subir para **60 segundos**, ainda abaixo do TTL Product de **120 segundos**.

Comandos foreground com timeout explícito maior continuam válidos, porém para compilações, servidores e tarefas que precisam de acompanhamento/cancelamento independente prefira o supervisor existente (`computer_process_start` ou `process_start`), acompanhado por `*_process_status` e `*_process_logs`. Isso fornece IDs estáveis e supervisão sem criar segundo daemon, fila ou autoridade.

A capacidade legada `ordax.product.read.invoke` foi retirada do Runtime: o contrato vigente usa operações Product tipadas e, quando aplicável, `ordax.product.invoke` com auditoria e autorização próprias. Comandos já aceitos não devem ser enfileirados novamente só porque a verificação de status demorou. Essa regra não altera nem afrouxa grants Owner.

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
