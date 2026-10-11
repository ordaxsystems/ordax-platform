# OrdaX Relay — verificação real e testes de isolamento (2026-10-10)

**Estado:** execução de leitura real em **um** dispositivo vinculado, mais prova em **três redes de contêineres independentes**. Não é homologação de três PCs físicos, três sessões GPT/Grok ou geração multimodal.

## Inventário verificado

- MCP OrdaX: autenticado; `mcp_tool_surface_revision=2026-10-07.1`; 87 ferramentas; **um dispositivo vinculado**, com grants reais; aqui anonimizado como **PC-A**.
- Remote Desktop Commander: três registros da conta principal, **offline**. Um registro da conta de teste aparecia online, mas a consulta de conectividade/comando não respondeu; não foi comprovado um segundo computador funcional. Não foram instalados agentes nem criadas VMs no PC pessoal.
- Nenhum outro dispositivo físico com sessão OrdaX independente foi confirmado nesta execução.

## Operações simultâneas reais no PC-A

Oito ações tipadas foram enviadas juntas por meio do MCP autenticado: 3 `computer.screen_info`, 3 `computer.access_status` e 2 `projects.list`. Resultado: **8/8 succeeded**, **0 pendentes**, tempo decorrido observado do grupo **18,898 ms**. O tempo reflete o conjunto de chamadas via ferramentas e não é um percentil de produção nem oito conversas com o modelo. As execuções no agente retornaram durações de 0,531 a 3,39 segundos, sem distinguir necessariamente tempo de rede, fila e processamento.

Os resultados reais consultados por `ordax_action_status` concluíram. A projeção pública da ação omitiu `device_id`; por isso, mesmo havendo vínculo do pedido na chamada inicial, o **comprovante público isolado** não é evidência suficiente do destino executado. O contrato canônico de PostgreSQL já projeta esse campo, mas a rota pública antiga ainda precisa do cutover.

## Provas adversariais contra a rota real

| Cenário | Resposta observada | Estado |
| --- | --- | --- |
| Comando com UUID de dispositivo não vinculado | `device_not_found` | **Negado como esperado** |
| Consultar UUID aleatório de ação | `action_status_unavailable`, sem conteúdo de terceiros | **Não expôs resultado**, mas mensagem genérica não prova isolamento multi-conta |
| Consultar recibo próprio aceito | `succeeded` | **Executado** |
| Informar `space_id` UUID alheio/aleatório para ação de dispositivo vinculada à conta | `succeeded` | **Comportamento inadequado de escopo**; não demonstra acesso a outra conta |
| Repetir `space_id` inadequado após workflow de deploy | `succeeded` | **Continuou inadequado**: o código novo não chegou ao backend usado pelo plugin |

A expressão SQL legada do grant no `index.ts` foi ajustada para comparar `space_id` exatamente (commit `7690f46c`); o **CI passou**, mas a verificação **live não passou** e a correção não deve ser anunciada como ativa. O GitHub relatou conclusão **success** do workflow de deploy, porém o job `deploy` estava **skipped**. A conta Cloudflare dedicada confirmou a ausência do Worker `ordax-control-plane-v3`. A configuração oficial tem `deployment_ready=false` e blockers de cutover PostgreSQL, política e provisionamento. Não contornar esse gate por flags ou usar a rota antiga como autoridade em paralelo. O serviço observado pelo plugin atual pode ter outro owner/implantação; identificá-lo é pré-requisito para qualquer nova homologação pública.

## Teste de três contêineres em redes privadas reais

Workflow: [ORDAX Relay Container Isolation #38102487975](https://github.com/ordaxsystems/ordax-platform/actions/runs/38102487975) — **success**. Execução `Docker Compose` real em GitHub-hosted Linux, com hub ligado a três redes Docker internas separadas, spoke A/B/C e sentinelas isoladas.

Cada spoke verificou:
1. Consegue contactar a própria sentinela e **não** contactar sentinelas dos dois outros peers por TCP.
2. Não resolve o nome DNS das sentinelas de outros peers.
3. A tentativa HTTP de se passar por outro dispositivo com seu próprio token recebe **401**.
4. Três mensagens/turnos independentes por spoke preservam request ID e marcador do próprio cliente, sem marcadores alheios.
5. `/v1/devices` não divulga inventário de peers.

As três execuções terminaram com `RELAY_ISOLATED_CONTAINER=spoke-N PASS`. Latências medidas para os nove turnos **apenas dentro da rede Docker/test adapter** (ms):

| Spoke | Turno 1 | Turno 2 | Turno 3 |
| --- | ---: | ---: | ---: |
| A | 5,51 | 8,80 | 9,28 |
| B | 8,51 | 3,96 | 6,55 |
| C | 7,65 | 8,76 | 8,32 |

Média observada **7,48 ms**; mínimo **3,96 ms**, máximo **9,28 ms**. Esses tempos não incluem comunicação pela Internet, inferência de IA ou transferência de uma imagem. Não comparar diretamente com a latência do PC real.

## Matriz de prontidão

| Prova necessária | Estado |
| --- | --- |
| Comandos reais a um PC via MCP | **PASSOU** |
| Oito chamadas reais simultâneas (sem modelo) | **PASSOU** |
| Recusa de destino UUID alheio no MCP | **PASSOU** |
| Três clientes isolados em redes Docker diferentes | **PASSOU** |
| Tentativa TCP/DNS de conexão lateral entre três redes Docker | **PASSOU: NEGADA** |
| HTTP forjado com identidade de outro spoke | **PASSOU: NEGADO** |
| Três sequências de mensagens por spoke com adaptador sintético | **PASSOU** |
| Recibo público carrega identidade imutável do PC de execução | **NÃO COMPROVADO** |
| `space_id` aleatório é negado pela rota pública em uso | **FALHOU** |
| Três PCs físicos conectados ao Relay, cada um com conta e sessão próprias | **NÃO TESTÁVEL: faltam dispositivos conectados** |
| Três conversas GPT/Grok independentes em paralelo | **NÃO TESTÁVEL: não há provedor conversacional autorizado pelo Relay** |
| Geração de imagem real em cada PC e entrega correta de bytes/miniatura | **NÃO TESTÁVEL: provedor e transporte multimodal não ligados** |
| Latência P50/P95/P99 de geração de imagem sob concorrência multiusuário | **NÃO MEDIDA** |
| Revogação efetiva imediata em três PCs reais e vazamento pós-revogação | **PENDENTE DE TESTE LIVE** |
| Worker canônico PostgreSQL pronto e alcançado pelo plugin público | **NÃO** |

## Critérios para homologação E2E

1. Concluir a migração Product PostgreSQL #42 e implantar no Cloudflare Worker realmente vinculado ao MCP, de forma coordenada, mantendo **um SSOT** de owner/client/device/grant.
2. Expor no recibo público a identidade canônica do dispositivo, cliente exato e ação sem vazar dados de outros usuários; conferir em produção que `space_id` diferente falha.
3. Provisionar **três máquinas reais distintas**, com três identidades/test clients, um marcador não sensível por computador e autenticações independentes. Não mascarar três contêineres como três PCs físicos.
4. Configurar provedor oficial de texto e imagem no `ordax.intelligence/1`/`ordax.model-router/1` com autorização apropriada; não automatizar conta Web do ChatGPT ou Grok como substituto de API.
5. Testar solicitações simultâneas, respostas e artefatos com `request_id`, `owner`, `client_id`, `device_id`, hashes binários, timestamps e logs sem conteúdo privado. Verificar revogação e recusas cruzadas em cada etapa.
6. Medir fila, geração do provedor, persistência R2, transporte, renderização e duração total separadamente; publicar distribuição de latência e taxas de erro, não um único tempo isolado.
7. Testes adversariais de rede apenas contra peers de teste e redes explicitamente autorizadas; não varrer a LAN de máquinas que não participaram.

**Conclusão:** o MCP do PC-A executa comandos, e o hub experimental resistiu a ataques de isolamento entre três redes Docker, mas a homologação de conversas reais multi-PC e imagens permanece **incompleta**. O deploy da autoridade canônica é o bloqueio decisivo detectado nesta execução.
