# OrdaX Control Plane — Cloudflare

Este diretório contém a camada Cloudflare do Control Plane remoto do OrdaX.

A autoridade arquitetural de produção está em `production-foundation.json`. Este README explica o contrato; quando houver divergência, o arquivo de foundation e os testes associados prevalecem.

## Arquitetura canônica de produção

- **Cloudflare Worker**: edge/API boundary, autenticação de requests, gateway HTTP, WebSocket handoff e integração com os serviços do Control Plane.
- **PostgreSQL / Supabase**: SSOT persistente. O projeto canônico é `ordax-platform` / `jhfphsjptrpmtnzkpwud` em `sa-east-1`.
- **Hyperdrive**: transporte canônico do Worker para PostgreSQL, com binding futuro `POSTGRES`.
- **R2**: bytes de artifacts/binários. R2 não é SSOT de metadata.
- **Durable Objects**: coordenação realtime/sessão. DO storage não substitui persistência de negócio.
- **D1**: legado temporário do Worker atual, proibido na arquitetura de destino.

Não existe dual-write permitido entre D1 e PostgreSQL.

## Estado da transição

A fundação de produção está deliberadamente **fail-closed**. `deployment_ready=false` permanece enquanto houver blockers em `production-foundation.json`.

O D1 atual está congelado:

- nenhuma tabela D1 nova;
- nenhuma migration D1 nova;
- nenhum novo módulo pode introduzir D1;
- remoções são permitidas e esperadas;
- o binding D1 só pode desaparecer depois que todos os call-sites tiverem authority PostgreSQL canônica.

O guard dessa regra roda em `tests/test_cloudflare_account_resolution.py`.

O mapa canônico da remoção está em `d1-cutover-authority-map.json`. Ele agrupa o legado por domínio de authority, não por cópia de schema, e fixa **tetos por arquivo**, validados contra todos os módulos do Worker: **65 acessos D1 remanescentes** (47 em `index.ts` e 6 em cada módulo de grants de device, intelligence e project; eram 75 antes da aposentadoria do CRUD administrativo de grants Product e auditoria D1). A antiga contagem de 75→71 descrevia somente `index.ts`, não o Worker inteiro. A CI impede crescimento em qualquer módulo e detecta arquivos D1 novos inclusive em subdiretórios e fontes TypeScript/JavaScript (`.ts`, `.tsx`, `.mts`, `.js`, `.jsx`, `.mjs`). O inventário de fontes é o mesmo usado pelo gate de produção; as dez tabelas legadas devem permanecer classificadas exatamente uma vez. Os números por arquivo são mantidos exclusivamente no `d1-cutover-authority-map.json`, sem segunda allowlist.

A operação legada `DELETE /v3/devices/:id` também foi **retirada do Worker de destino**: o handler apagava objetos completos do R2 e abortava uploads multipart **antes** de confirmar a remoção de metadados e jobs no D1. Uma falha posterior no banco poderia provocar perda irrecuperável de bytes e deixar a authority inconsistente. A remoção da rota não faz exclusões automáticas nem migra o contrato por cópia direta; o blocker `engineering_device_deletion_lifecycle_not_ready` exige uma operação canônica com revogação de sessão, ownership verificado, claim/estado/versionamento, coordenação com jobs e ciclo de vida de artifacts, tratamento idempotente das falhas R2 e recuperação auditável. Não reativar o DELETE antes de testes E2E de interrupção e concorrência.

A rotina antiga de retenção (`src/retention.ts`) e o evento `scheduled` foram **retirados do Worker de destino**, e o cron foi removido de ambos os arquivos Wrangler. A rotina usava metadados de negócio D1 para selecionar objetos e apagar bytes R2, o que não é seguro migrar por cópia direta do SQL. O novo blocker `artifact_retention_authority_not_ready` mantém o deploy fechado: só poderá ser removido depois que houver lifecycle e retenção canônicos no PostgreSQL, com ownership, verificação de exclusões, tratamento idempotente de objetos R2 e testes de falha. A PR #68 de authority de artifacts é uma dependência, mas **não autoriza sozinha a retomada de exclusões automáticas**. Não existe um cron alternativo ou mecanismo provisório. O endpoint público `/health` também não anuncia mais `product_retention_v1`, pois a capacidade foi efetivamente aposentada; ela só poderá voltar quando houver uma implementação de retenção canônica comprovada e seus testes.

O contrato legado de leitura de artifacts ainda é D1 e **não está autorizado para produção**. Até o corte definitivo, a emissão de novos tokens de leitura exige que o `UPDATE` de metadata afete exatamente uma linha; a conclusão multipart também exige que o `INSERT` tenha realmente persistido o token (`ON CONFLICT DO NOTHING` não equivale a publicação). Em caso de disputa ou revogação, a resposta é `409`, sem anunciar um link com token inexistente no banco. Isso fecha falsos sucessos, mas não substitui transações e concorrência canônicas PostgreSQL/R2 nem libera o blocker de artifacts.

A auditoria de cutover encontrou 10 tabelas D1 legadas. Product grants/action queue/audit já possuem tabelas e RPCs PostgreSQL; a migration `20261007203000_product_client_grant_isolation_v1` está aplicada e exige correspondência exata de `client_id` no resolver/execução. **O corte de endpoint continua bloqueado** até obter identidade de client por credenciais verificadas e migrar Worker/MCP sem fallback; nunca autorizar pelo `client_id` arbitrário do body. Product pairing/link exige redesenho sobre identity/bindings canônicos; o registry de device é parcialmente coberto e ainda precisa separar Product de engineering/runtime. Artifact metadata/multipart e a queue genérica de engenharia continuam dependentes do contrato acompanhado em **#42**. Não criar tabelas PostgreSQL apenas para reproduzir o schema D1 1:1.

## Product MCP — identidade de client OAuth autenticada (boundary não ativado)

O Supabase OAuth 2.1 emite access tokens com o claim superior `client_id`.
O módulo `src/product_auth.ts` agora disponibiliza
`authenticateProductMcpClientRequest()`: valida assinatura assimétrica por
JWKS, issuer, audience e expiração pelo verificador Product existente, e
**somente depois** lê `client_id` e `role=authenticated`. O `sub` deve ser
UUID canônico. A espécie `product-mcp` é determinada pelo boundary do
servidor, não por um parâmetro do consumidor.

A função recusa fail-closed JWT sem `client_id` OAuth, cliente malformado,
role não autenticada e subject legado textual. Headers como
`X-Ordax-Client-Id`, query strings, body e `user_metadata` não concedem
identidade remota. Sessões de usuário normais continuam com o contrato atual;
um JWT comum não vira um cliente OAuth por inferência.

**Ainda não há cutover de rota.** `/mcp` e as rotas Product públicas
mantêm os consumidores legados até a migração coordenada da identidade,
contracts UUID de Space/Project, grant groups, action/status e E2E. É
proibido misturar a leitura de grants D1 com execução PostgreSQL ou criar
fallback. O mapa `d1-cutover-authority-map.json` continua `partial`.
Testes unitários assinam tokens RSA e verificam isolamento entre
`client_id` de dois clientes do mesmo tipo, spoofing de body/header e
adulteração de assinatura.

## Product PostgreSQL

O destino correto é:

`Worker -> Hyperdrive -> PostgreSQL`

O runtime PostgreSQL usa a credencial LOGIN dedicada `ordax_edge_runtime`, que herda somente o boundary NOLOGIN `ordax_edge_executor`. O Hyperdrive canônico está provisionado com cache desabilitado, TLS `require` e limite de 10 conexões de origem.

`src/product_postgres_store.ts` usa diretamente o binding `POSTGRES` do Hyperdrive com Postgres.js pinado. O endpoint Product de setup (`identify`/`enroll`) utiliza somente as RPCs de identidade PostgreSQL, com token hasheado e limite de re-enrollment aplicado atomicamente no banco; não grava autoridade Product em D1 ou Durable Objects. Na operação `enroll`, o contrato agora exige explicitamente `device_kind` (`desktop`, `laptop`, `mobile`, `server` ou `other`) e `channel` (`stable` ou `development`); não há valor fictício ou default silencioso. Os consumidores devem enviar esses campos antes de liberar o deploy do Worker novo. O runtime não usa backend secret genérico do Supabase, não chama `/rest/v1/rpc/` e continua restrito às RPCs PostgreSQL públicas concedidas ao boundary `ordax_edge_executor`.

São proibidos no runtime Worker de produção:

- `SUPABASE_SERVER_KEY`;
- `SUPABASE_SERVICE_ROLE_KEY`;
- `service_role` genérico como application authority.

O cache do Hyperdrive permanece desabilitado para authority paths como autenticação, grants, jobs e operações com read-after-write.

## Product Auth

A verificação de JWT usa metadata pública do projeto Supabase Brasil:

- issuer: `https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1`;
- audience: `authenticated`;
- JWKS: `https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1/.well-known/jwks.json`.

Esses valores são metadata pública, não secrets. Os testes derivam issuer e JWKS do `postgres.project_ref` do foundation para evitar drift entre Cloudflare e o projeto PostgreSQL canônico.

## workers.dev

O subdomínio account-level canônico foi inicializado como:

`ordaxsystems.workers.dev`

Nenhum Worker foi criado como efeito desse bootstrap. O Worker de produção, quando autorizado pelo gate, ficará no hostname derivado de `worker_name` + esse subdomínio.

O deploy rotineiro resolve o subdomínio ao vivo; não existe fallback para hostname/account legado.

## R2 e artifacts

O bucket canônico é definido pelo foundation como `ordax-device-artifacts`.

Estado atual da conta dedicada: R2 está habilitado e o único bucket canônico `ordax-device-artifacts` foi provisionado em classe Standard, jurisdição default. A API confirmou o bucket ao vivo após a criação.

Regras permanentes:

1. manter bytes no R2;
2. manter metadata persistente no PostgreSQL;
3. não criar segundo bucket como authority paralela;
4. não usar D1 ou Durable Objects como novo SSOT de artifacts.

O fluxo legado de metadata/multipart ainda depende de D1 e será removido no cutover, não duplicado.

## Durable Objects

No destino Cloudflare permanece somente `DeviceSession`, responsável pela coordenação de WebSocket/sessão. O `EnrollmentSession` legado foi retirado da configuração e do source porque persistia identidade Product fora do PostgreSQL; o enrollment canônico já é atômico por RPC. A conta dedicada ainda não possui namespaces Durable Objects provisionados.

No handshake de `/v3/device/ws`, o Worker autentica o dispositivo e valida `X-Ordax-Agent-Instance` e `X-Ordax-Boot-Id` **antes** de acionar o Durable Object. O `DeviceSession` também recusa identidades malformadas e confirma que o registro ainda não foi revogado imediatamente antes de aceitar o WebSocket; uma revogação concorrente não pode resultar em `101 Switching Protocols`. Em conexões já abertas, o heartbeat também exige atualização válida do dispositivo ativo; quando a revogação ou exclusão impede essa atualização, a sessão recebe erro e é encerrada com código WebSocket `1008`. A consulta D1 nessa etapa permanece **legado de engineering runtime** e não autoriza produção até a autoridade canônica de device/jobs substituir todo o caminho.

O destino mantém Durable Objects somente para coordenação de sessão/realtime. Estado de negócio durável deve estar no PostgreSQL; artifacts ficam no R2.

## Deploy

### CI

O workflow `ORDAX Control Plane CI` valida source, contratos e bundle do Worker.

### Produção

O workflow `Deploy ORDAX Control Plane`:

1. faz checkout do SHA exato que passou na CI;
2. valida `production-foundation.json`;
3. valida `production-foundation.json` e `wrangler.toml` pelo guard SSOT `scripts/cloudflare/check_deploy_readiness.py` e só executa o job de deploy quando `deployment_ready=true` e não existem blockers;
4. usa o account id vindo do foundation, sem segunda fonte de verdade;
5. exige `CLOUDFLARE_API_TOKEN` no environment GitHub `cloudflare-v3`;
6. chama `scripts/cloudflare/deploy-production-v3.sh`;
7. executa smoke público depois do deploy.

Para impedir rollback acidental quando vários chats/CI jobs concorrem, o workflow só aceita dispatch manual em `refs/heads/main` ou uma CI bem-sucedida cuja execução tenha origem neste repositório e na branch `main`. O SHA testado continua explícito. Além disso, **bootstrap e deploy rotineiro** verificam que o checkout ainda coincide com `refs/heads/main` do Git remoto imediatamente após o gate de readiness e **antes de ler o token Cloudflare**. Se o HEAD local estiver adiantado, atrasado ou não for possível conferir o remoto, a publicação falha sem fallback. Uma **segunda checagem** ocorre imediatamente antes do comando Wrangler, após consultas à Cloudflare ou instalação de dependências, para reduzir a janela de corrida com commits integrados durante essas etapas; a verificação permanece fail-closed. A validação não se baseia apenas no nome da branch ou no SHA de um workflow anterior.

O deploy rotineiro **não provisiona infraestrutura**.

Como o Worker ainda não existe, o bootstrap e o CI permanente são autoridades distintas:

- criação inicial do Worker: autoridade **Workers Product Admin temporária**, somente depois dos cutovers D1 e bearer operacional, removida após o bootstrap;
- deploys posteriores: **Editor somente no Worker existente**;
- o token rotineiro não recebe Zone/Routes, D1, R2 ou Hyperdrive direct access apenas para publicar bindings.

### Scripts

- `scripts/cloudflare/check_deploy_readiness.py`: guard SSOT do deploy. O workflow pode executar `--allow-blocked` apenas para validar o estado e registrar o output, mas **o script de deploy direto exige readiness verdadeira** antes de consumir credenciais ou chamar a API da Cloudflare. Também verifica os bindings canônicos e a ausência de D1, bearer global e backend secrets no source ao liberar o deploy.
- `scripts/cloudflare/bootstrap-worker-v3.sh`: **bootstrap inicial único**, sem D1, sujeito ao `--bootstrap` do guard; exige que somente `worker_not_provisioned` e `cloudflare_ci_worker_editor_token_not_provisioned` continuem pendentes. Recusa se o Worker já existir, confirma o `workers.dev` canônico e usa credencial **Workers Product Admin temporária** que deverá ser revogada logo após a criação.
- `scripts/cloudflare/deploy-production-v3.sh`: deploy rotineiro do Worker já existente. O script verifica tanto o guard completo quanto a existência real do Worker antes de chamar o Wrangler; um token Editor nunca deve criar infraestrutura.
- `scripts/cloudflare/deploy-v3.sh`: **bootstrap D1 legado aposentado**, recusa qualquer execução; não cria D1, não altera R2 e não publica Worker.

Não adicionar fallback para account antigo, Worker antigo ou D1 antigo.

## Autenticação operacional legada

O bearer global `ORDAX_OPERATOR_TOKEN` é legado e não pode crescer.

A superfície atual está congelada por teste nos handlers:

- `createProductGrant`;
- `createProductGrantFromLink`;
- `listProductGrants`;
- `resolveProductGrantAdmin`;
- `revokeProductGrant`;
- `provisionDevice`;
- `enqueueJob`;
- `getJob`.

Novos handlers não podem chamar `operatorAuthorized()`. A allowlist só deve encolher conforme cada rota migra para authority autenticada e least-privilege. Se a superfície mudar, a CI exige atualização explícita do contrato.

## Segurança

Regras permanentes:

- PostgreSQL é o SSOT persistente;
- sem D1 novo;
- sem dual-write;
- sem backend secret genérico do Supabase no Worker de produção;
- sem bearer global `ORDAX_OPERATOR_TOKEN` no Worker de produção;
- rotas administrativas precisam de authority autenticada e least-privilege compatível com sua semântica;
- credenciais runtime devem ser least-privilege;
- token CI deve ser novo e dedicado à conta OrdaX;
- 2FA é requisito de produção;
- raw device token não deve ser persistido;
- modelo/contexto nunca amplia grants;
- sem shell remoto genérico;
- DNS só muda após gates independentes e rollback comprovado.

A conta Cloudflare dedicada foi padronizada como `ordax-platform`. O único membro administrativo já tem 2FA habilitado e a política da conta agora exige 2FA (`enforce_twofactor=true`), ambos revalidados por leitura da API Cloudflare. A identidade da conta (`account_id`) foi preservada; esse controle não remove os demais blockers de publicação do Worker.

## DNS

A zone `ordax.com.br` ainda não deve ser movida.

O blocker atual é a dependência `catalogo-media`, que pertence a Catálogo/Achegue-se e precisa ser realocada antes do cutover da zone. O workstream Cloudflare do OrdaX não deve alterar recursos Tonecos/Achegue-se durante essa migração.

## Blockers de produção

A lista executável está somente em `production-foundation.json`. No estado atual ela inclui:

- cutover D1 ainda incompleto;
- autenticação operacional legada por `ORDAX_OPERATOR_TOKEN` ainda não removida/substituída;
- Worker de produção ainda não provisionado;
- token CI permanente Worker-scoped ainda não provisionado;

Não remover blocker por expectativa. Cada blocker só sai depois de evidência live + source/CI coerentes.

## Provisionamento local do Device Agent

Este repositório **não contém o instalador do Device Agent Windows**. A referência anterior a um instalador nesse diretório estava desatualizada e foi retirada, para não encaminhar operadores a um arquivo inexistente. O provisionamento e a atualização do consumidor do endpoint `/v3/device/setup` pertencem ao projeto responsável pelo Device Agent, não ao Worker Cloudflare; não criar um instalador duplicado aqui.

Para o cutover canônico, o consumidor precisa enviar `device_kind` e `channel` explícitos no enrollment; a credencial deve ser gerada localmente, enviando ao backend apenas hashes/material derivado e respeitando machine binding, fencing de execução e replay idempotente. O blocker `product_device_setup_client_contract_not_verified` só poderá ser retirado após localizar o consumidor no repositório proprietário, validar o protocolo e executar os testes E2E.

## Product: boundary de grant groups PostgreSQL (ainda não ativado nas rotas)

O adapter `src/product_postgres_store.ts` oferece as RPCs canônicas `ordax_replace_remote_grant_group_v1`, `ordax_revoke_remote_grant_group_v1` e `ordax_list_product_targets_v1`. As assinaturas são derivadas da migration versionada `20261007185000_product_grant_groups_v2.sql`. Os arrays `text[]` são parâmetros tipados, não strings SQL montadas manualmente.

A verificação estrutural em `src/product_remote_grant_contract.ts` aceita somente UUIDs reais de usuário, Space, Project e Device; grupos de capacidades com access mode individual e `client_kind/client_id` explícitos. Autorizar ownership, membership, binding de projeto e grant continua **exclusivamente** nas RPCs PostgreSQL.

**Gate obrigatório de isolamento de cliente:** a migration PostgreSQL de `client_id` foi aplicada (ledger `20261008011240`) e seu postflight validou assinatura, predicado e ACLs. O domínio `product_remote_authority` permanece `partial` porque o Worker ainda precisa derivar `client_id` de credenciais autenticadas, testar segregação inter-client ponta a ponta e migrar os consumidores MCP. O schema estar correto **não autoriza** substituir handlers D1 nem liberar deploy.

**Não houve cutover de endpoint.** Os handlers Product legados e os consumidores MCP ainda usam os contratos D1; estas funções de adapter não são ligadas a eles até a migração vertical coordenada de autenticação, enrollment, grants, targets, action/claim e status. É proibido fazer tradução implícita de `subject_id` arbitrário para UUID, de `project` slug para `project_id`, ou manter fallback/dual-write. Ver issue #42 e `d1-cutover-authority-map.json`.

## Princípio de cutover

A ordem correta é:

1. fechar authorities PostgreSQL faltantes;
2. provisionar LOGIN runtime least-privilege;
3. provisionar Hyperdrive — concluído;
4. substituir o adapter REST pelo caminho Hyperdrive/PostgreSQL — concluído para o Product Postgres RPC boundary; remoção dos call-sites D1 segue por domínio;
5. habilitar R2 e provisionar o bucket canônico;
6. migrar somente artifacts necessários, com integridade;
7. remover D1 do `wrangler.toml` e do runtime;
8. remover/substituir `ORDAX_OPERATOR_TOKEN` por authorities explícitas;
9. criar o primeiro Worker com autoridade temporária de bootstrap;
10. substituir a autoridade de bootstrap por token CI Editor somente naquele Worker e validar deploy/E2E;
11. habilitar 2FA e enforcement de account — 2FA do membro concluído; enforcement account-level permanece separado;
12. resolver a dependência DNS de Catálogo;
13. somente depois executar cutover de `ordax.com.br`.

Sem delete antecipado na origem e sem paliativos para atravessar gates.
