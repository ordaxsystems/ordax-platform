# OrdaX Platform — gateway MCP canônico na Cloudflare

Este diretório mantém o **único Worker MCP publicado** da Platform. A fonte canônica de configuração e segurança é o código, não este documento. Mudanças que alterem a autoridade ou o contrato publicado devem preservar a verificação de CI, as provas da implementação real e os controles de autorização existentes.

## Autoridade e composição em produção

| Função | Autoridade canônica |
| --- | --- |
| Worker MCP e HTTP | `ordax-mcp`, `src/product_mcp_entry.ts` |
| Configuração de deploy | `wrangler.mcp.toml` |
| Estado e política de release | `production-foundation.json` → `mcp_release` |
| Validação de release | `scripts/cloudflare/check_mcp_release.py` |
| Banco persistente e grants | PostgreSQL do projeto Supabase `jhfphsjptrpmtnzkpwud` |
| Conexão à autoridade de dados | Binding Hyperdrive `POSTGRES`, sem cache de queries |
| Identidade | Supabase Auth: JWT assinado, issuer/audience/JWKS, OAuth `client_id` autenticado |
| Despacho para dispositivos | Runtime autenticado, sessões atestadas, grants e leases verificados no PostgreSQL |
| Notificação de dispositivo | `DEVICE_WAKE` Durable Object, **somente wake advisory**, sem filas/grants/identidade persistentes |
| Fluxo de IA Central/Forge | Fronteiras separadas de autorização, sem transformar argumentos de modelo em grants |

**Não existe D1 em produção, dual-write, credencial genérica `service_role`, bearer global `ORDAX_OPERATOR_TOKEN` nem segundo Worker publicável.** O antigo `ordax-control-plane-v3` foi aposentado. Seu entrypoint `src/index.ts`, `wrangler.toml`, workflow, scripts de publicação, migrações D1 e gate de release foram removidos do código canônico. Qualquer reintrodução deve falhar nos testes e no gate de publicação.

A configuração `wrangler.product-mcp-canary.toml` existe **somente para validação/dry-run sem rota pública**. Ela não é um Worker de produção, autoridade separada ou fallback. O bundle de produção é verificado por `scripts/cloudflare/assert_canonical_mcp_bundle.py`, que inspeciona o **artefato compilado**; `check_mcp_release.py` valida **fonte e autorização**. Essas verificações são complementares e não duplicam o executor.

## Endpoints e isolamento de ingress

- `https://mcp.ordax.com.br/mcp`: interface MCP pública, com autenticação OAuth e autorização por proprietário, cliente, dispositivo e escopo.
- `https://mcp.ordax.com.br/health`: diagnóstico público de configuração. Um HTTP 200 **não comprova** grants, capacidade de despachar ou E2E.
- `https://mcp.ordax.com.br/ready`: verifica discovery OAuth **e** leitura SQL real via Hyperdrive. Em indisponibilidade ou configuração inválida, retorna indisponibilidade sem declarar falsa prontidão.
- `/.well-known/oauth-protected-resource`: metadados do recurso OAuth vinculados ao issuer canônico.
- Rotas de conta/Owner e transporte de dispositivo: apenas nas formas expressamente aceitas e com verificação server-side. O modelo não pode selecionar outra identidade ou fabricar grant.

O hostname `ordax-mcp.ordaxsystems.workers.dev` é **ingress do mesmo Worker**, restrito por allowlist a requisições Product autenticadas de clientes confiáveis. Não é outro endpoint público MCP: o código bloqueia nesse hostname as rotas MCP, metadata e health não permitidas. O webhook GitHub assinado fica na origem autorizada; ele não faz parte da allowlist de ingress do Runtime.

A identidade do **computador físico** e a da **instalação cliente/Runtime** não devem ser confundidas. Presença/heartbeat ou seleção Owner não constituem, isoladamente, atestado de sessão ou autorização para executar ações.

## Dispositivo, sessão e grants

`src/product_device_setup.ts` implementa `/v3/device/setup` (operações `identify`/`enroll`) usando exclusivamente as RPCs PostgreSQL e credenciais de dispositivo derivadas/hasheadas. Enrollment valida formato de máquina, nome, `device_kind`, `channel` e identidade Owner, com limite de chamadas imposto no banco. `src/product_device_transport.ts` implementa heartbeat, claim, start, renovação de lease, progresso e report sob autenticação real do dispositivo; nenhuma dessas funções cria grants.

Leituras de targets, ações e recibos usam `src/product_mcp_reads.ts` e as RPCs PostgreSQL. Ações tipadas MCP reutilizam os contratos existentes de escopo `product_action_scope.ts`, handlers atestados e grants Owner. O domínio **device** não inventa projeto; operações **project** exigem escopo exato, binding e autorização correspondentes. Nenhum Space `null` deve ser interpretado como permissão implícita para um Space explícito não concedido.

O campo de resposta `protocol: "cloudflare-v3"` em `src/product_device_setup.ts` é um **identificador de contrato de rede já consumido por clientes instalados**, não o nome do Worker ou uma autoridade D1. Não mudá-lo isoladamente: reconciliar primeiro consumidores Desktop/Runtime no repositório proprietário, testar upgrade, compatibilidade e rollback e só então versionar uma alteração do protocolo em conjunto.

## Persistência, armazenamento e limites

O PostgreSQL é o SSOT para identidade, grants, presença, projetos, ações, auditoria e resultados. `src/data_postgres_driver.ts` abre sessões com o binding `POSTGRES` pelo Hyperdrive; credenciais e políticas são restritas ao runtime `ordax_edge_runtime` e ao executor least-privilege `ordax_edge_executor`. O Hyperdrive deve preservar SQL consistente para revogação e leitura após escrita, sem cache de autoridade.

R2 é armazenamento de **bytes** e não uma fonte alternativa de metadados de negócio. A remoção do Worker antigo **não implementou automaticamente** as antigas APIs de artifacts, multipart, queue genérica de engenharia ou retenção. Não reconstruir schemas D1 nem introduzir Durable Objects para persistência de negócio; cada funcionalidade futura exige owner, semântica PostgreSQL/R2 revisada, contrato de falha, idempotência e testes próprios.

O único Durable Object registrado no Worker publicado é `ProductDeviceWake`, usado para notificação advisory. A fila de jobs, os leases e o estado de execução permanecem no PostgreSQL. `scheduled` executa a limpeza de **métricas de uso MCP** via PostgreSQL, não a rotina de retenção de artifacts anteriormente aposentada.

### Reutilizacao segura de metadados no Worker

`src/mcp_http.ts` monta o catalogo publico de ferramentas sob demanda e reutiliza
descritores estaticos e lookup por nome. O allowlist da operacao continua sendo
filtrado em cada chamada. `src/product_auth.ts` reutiliza somente importacoes
WebCrypto de chaves **publicas** JWKS, por identidade de objeto e algoritmo.
A renovacao das chaves substitui os objetos e importa a nova chave; falhas de
importacao nao ficam armazenadas. Token, assinatura, claims, expiracao e
autorizacao continuam verificados individualmente em cada requisicao.
A mesma verificacao OAuth tambem e reutilizada pelas operacoes Central
resolve/open no ambito da requisicao MCP, por meio do autenticador
request-scoped existente; a resolucao SQL, os grants e a revogacao
permanecem atuais e nunca sao compartilhados entre conversas.

**Nao** ativar cache de SQL sensivel no Hyperdrive nem cache de sessoes, grants,
leases, revogacoes ou estado vivo. Sinais wake nao dispensam claim autorizada
no PostgreSQL. Comparar CPU e SQL reais com janelas e carga equivalentes
antes de atribuir reducoes de consumo ao codigo.

## Segurança obrigatória

- JWT assinado, issuer/audience/JWKS corretos, cliente OAuth identificado **após** a verificação da assinatura; sem confiança em headers, query, body ou argumentos do modelo como fonte de identidade.
- Grants, revogação, estado do dispositivo, Space, Project e `client_id` sempre resolvidos na autoridade PostgreSQL. Fail-closed em mismatch, revogação, sessão não atestada ou indisponibilidade.
- Nenhum `env.DB` (inclusive acesso computado/opcional), `D1Database`, `SUPABASE_SERVER_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `ORDAX_OPERATOR_TOKEN` ou dual-write no código ativo.
- 2FA e política Cloudflare verificados no gate canônico; não flexibilizar controles para ultrapassar um deploy bloqueado.
- Erros do MCP projetam somente códigos públicos validados, sem SQL, trace, tokens, dados de outros clientes ou campos extras internos.
- Não publicar novos endpoints, grants, routers paralelos, mecanismos de fallback ou executores para fazer testes legados passarem.

## Validação e publicação

O workflow [`ordax-mcp-validation-deploy.yml`](../../.github/workflows/ordax-mcp-validation-deploy.yml) é a **única esteira de publicação** do Worker MCP. Faz checkout do SHA canônico, testa o candidato, valida release e bundle exatos, exige `main` atualizada e token Cloudflare somente na fase de publicação, realiza deploy via `wrangler.mcp.toml` e verifica o serviço publicamente. Não provisiona Worker alternativo, D1 ou recursos de produção adicionais.

O release mantém dois estados separados:

1. **Primeira homologação E2E completa:** só poderá ser marcada pronta quando houver evidências independentes reais de OAuth/consent, dispositivos, grants, ações, múltiplos dispositivos e isolamento.
2. **Manutenção do Worker MCP já publicado:** pode ser autorizada pelo gate próprio apenas com identidade canônica, candidate validation e comprovação da autoridade existente. Não transforma provas ausentes em E2E aprovado.

Verificações disponíveis:
- `python scripts/cloudflare/check_mcp_release.py --inspect`: lê o estado de primeira homologação (bloqueios continuam explícitos).
- `python scripts/cloudflare/check_mcp_release.py --validation-candidate`: valida candidato **sem autorizar produção**.
- `python scripts/cloudflare/check_mcp_release.py --maintenance-upgrade`: autoriza somente manutenção da instância publicada se todos os requisitos forem atendidos.
- `python scripts/cloudflare/probe_live_product_mcp.py`: smoke HTTPS público sem segredos. **Não prova consent OAuth, grant físico, execução ou multi-device E2E**.
- `scripts/cloudflare/run_mcp_candidate_tests.sh`: suítes de candidato. A CI aplica os checks de origem, autenticação, permissões e bundle.

O GitHub Environment ainda se chama `cloudflare-v3` **apenas como rótulo externo** onde estão configurados segredos e proteções da esteira. Não representa um segundo Worker. Renomeá-lo exige migração verificada de approvals, environment secrets e permission gates no GitHub; não basta uma substituição textual no YAML.

## Trabalho ainda não homologado

O gateway publicado e os testes automáticos **não comprovam por si sós** a autorização interativa física. A [issue #118](https://github.com/ordaxsystems/ordax-platform/issues/118) acompanha o P0 de Space explícito, diferença entre grants genéricos e específicos e resultado/status isolado por cliente. [Issue #42](https://github.com/ordaxsystems/ordax-platform/issues/42) registra o histórico de desmontagem D1 e as decisões de authority que não devem ser substituídas por schema clonado.

Para qualquer alteração em clientes instalados, acordar um contrato versionado com os owners de Desktop e Runtime antes de modificar campos como `protocol`, IDs de dispositivo ou transporte. A prova é o teste negativo e positivo real, não uma CI verde isolada.
