# Project-First M1 — recurso local subordinado ao Product grant

**Estado: código candidato de registro/revogação e verificador read-only estão na source; a proposta SQL não foi aplicada e a capacidade segue desabilitada em produção.** Issue: [#266](https://github.com/ordaxsystems/ordax-platform/issues/266). Uma PR de código não autoriza migração, deploy, troca de grant ou leitura de pastas pessoais.

## SSOT e isolamento

- **Projeto/Space**: `ordax_projects`, `ordax_spaces`, vínculos `ordax_space_devices` / `ordax_device_project_bindings` e `ordax_product_devices`; identidade de repositório mantida pelo resolver Owner existente.
- **Permissão**: `ordax_remote_capability_grants`, com OAuth client e consentimento vivos. Somente `project-workspace-read` + `workspace.project_snapshot`, `read`, escopo `project`, prazo curto e device concreto. Grants amplos de Computer Control não valem.
- **Identidade local**: `private.ordax_lab_project_authorities` associa um ID local não confiável a exatamente um projeto canônico por Owner/client. O vínculo não tem permissão própria.
- **Recursos**: `private.ordax_workspace_resource_bindings` guarda só referência opaca, actor, sessão, device, prazo e FK ao grant existente. Não guarda path, conteúdo, token, credencial ou segredo; várias raízes por projeto não exigem novo cadastro do projeto.
- **Verificação**: `public.ordax_verify_project_workspace_resource_v1` faz join completo sobre relações canônicas, consentimento, revogação e expiração **a cada chamada**, devolvendo só prova limitada. A rota Device/Product existente valida e continua desativada por padrão.
- **Filesystem e Git**: Runtime é owner exclusivo. O SQL não prova que a raiz local existe, é segura contra junction/symlink ou preservou identidade. Runtime precisa revalidar isso antes e depois de cada snapshot.

## Consulta pelo transporte Device/Product existente — código preparado, desabilitado

A Platform contém o ponto de integração read-only `POST /v3/device/transport/workspace-proof` **no handler canônico de transporte Device**, não em um MCP novo. A implementação é `source-only` e exige a configuração literal `WORKSPACE_RESOURCE_VERIFIER_ENABLED=enabled`; ausente ou qualquer outro valor retorna `not_found` após o gate normal de autenticação do dispositivo. **Não configurar essa flag até a migração aprovada, a emissão/revogação e o E2E**. Sem a função SQL aplicada, a operação falha fechada.

O request aceito pelo dispositivo já autenticado contém exclusivamente `owner_user_id`, `actor_id`, `client_id`, `lab_project_id`, `workspace_session_id` e `resource_id`; **não aceita** `device_id`, Space, projeto Product, `path`, token, grant ou permissões do caller. `device_id` é fornecido pelo resultado da autenticação Device existente. Os identificadores da requisição são **chaves de consulta, não autoridade**: `public.ordax_verify_project_workspace_resource_v1` é quem valida todos eles contra ledger, consentimento e vínculo vivos no PostgreSQL.

A função de store `verifyProjectWorkspaceResource` reutiliza o `callRpc` com parâmetros vinculados e RPC allowlisted. A resposta só é liberada se a função SQL retornar `ordax.project-workspace-resource/1` e o resultado passar pelo `projectWorkspaceGrantProjection` existente com todas as identidades coincidentes, `read` e validade original máxima de 24h. Nem caminhos locais nem credenciais são retornados. Falhas de schema, grant ou revogação produzem uma negativa genérica; nenhuma autorização é inferida do JSON do dispositivo.

Os testes do verificador cobrem request allowlist, impossibilidade de escolher outro device pelo corpo, grant de outro Owner/actor/client/session/projeto/recurso, revogação, conteúdo extra, expiração e ausência de autenticação. A credencial Device identifica o transportador, enquanto o PostgreSQL valida o grant e seu ator: não interpretar uma chamada com resourceId como consentimento novo.

## Registro e revogação candidatos — ainda não utilizáveis em produção

O SQL de proposta em `control-plane/supabase/proposals/project_workspace_resource_authority_v1.sql` inclui RPCs estreitos de registro idempotente e revogação do resource ID, ambos subordinados ao grant existente. Eles não criam nem estendem grants. A rota Owner exige JWT assinado com o mesmo OAuth client que será gravado, credencial Device autenticada, resolução server-side do repositório para Space/Project canônicos e um `resource_id` opaco emitido pelo Runtime. Não aceita caminho local, UUID canônico, grant ID ou prazo do chamador.

A rota chama o `projectWorkspaceVerifierResponse` já usado pelo transporte Device, em vez de criar outro validador. O transporte Device continua sendo o único caminho de verificação e permanece default-off. As tabelas privadas continuam sem DML direto ao Edge; somente os RPCs restritos recebem `EXECUTE`. Revogação afeta um recurso, nunca o grant pai. O SQL e as rotas são código candidato: sem migração aplicada e sem o gate existente habilitado, o fluxo real continua indisponível.

## Ordem de promoção

1. Passar CI SQL PGlite para registro idempotente, conflito de projeto/recurso, grant ausente, isolamento e revogação, além de testes de rota/autenticação e privilégios. A proposta vive fora de `migrations/` e não altera o ledger aplicado.
2. Após autorização específica futura, gerar a migração com o CLI canônico, revisar, aplicar pelo owner e registrar no `control-plane/supabase/migration-registry.json` somente a versão realmente aplicada e o hash Git exato. Não adicionar migração não aplicada nem registrar uma aplicação fictícia. Não aplicar em produção neste gate.
3. Integrar o Owner picker já existente no Runtime com o registro Owner autenticado e manter a verificação pelo transporte Device/Product existente. Não adicionar outro picker, verificador ou port.
4. Conectar o consumidor Apps ao mesmo `ProjectWorkspacePort` do Runtime; negar payload que contenha path, token ou identidade de ator derivada de modelo.
5. E2E Windows com fixture VESTE descartável: seleção humana, ler snapshot, revogar, mover pasta, reiniciar, provar nenhuma leitura sem grant e nenhuma escrita. Somente então reclassificar M1 como operacional.

**Não confundir a existência do verificador com uma autorização real.** Esta etapa é exclusivamente definição de persistência e prova read-only offline.
