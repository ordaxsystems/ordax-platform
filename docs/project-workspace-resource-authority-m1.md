# Project-First M1 — recurso local subordinado ao Product grant

**Estado: proposta SQL validável, não migração aplicada nem capacidade habilitada em produção.** Issue: [#266](https://github.com/ordaxsystems/ordax-platform/issues/266). Uma PR de schema não autoriza migração, deploy, troca de grant ou leitura de pastas pessoais.

## SSOT e isolamento

- **Projeto/Space**: `ordax_projects`, `ordax_spaces`, vínculos `ordax_space_devices` / `ordax_device_project_bindings` e `ordax_product_devices`; identidade de repositório mantida pelo resolver Owner existente.
- **Permissão**: `ordax_remote_capability_grants`, com OAuth client e consentimento vivos. Somente `project-workspace-read` + `workspace.project_snapshot`, `read`, escopo `project`, prazo curto e device concreto. Grants amplos de Computer Control não valem.
- **Identidade local**: `private.ordax_lab_project_authorities` associa um ID local não confiável a exatamente um projeto canônico por Owner/client. O vínculo não tem permissão própria.
- **Recursos**: `private.ordax_workspace_resource_bindings` guarda só referência opaca, actor, sessão, device, prazo e FK ao grant existente. Não guarda path, conteúdo, token, credencial ou segredo; várias raízes por projeto não exigem novo cadastro do projeto.
- **Verificação**: `public.ordax_verify_project_workspace_resource_v1` faz join completo sobre relações canônicas, consentimento, revogação e expiração **a cada chamada**, devolvendo só prova limitada. A API não está conectada ao App.
- **Filesystem e Git**: Runtime é owner exclusivo. O SQL não prova que a raiz local existe, é segura contra junction/symlink ou preservou identidade. Runtime precisa revalidar isso antes e depois de cada snapshot.

## Operações ausentes por design

O SQL de proposta em `control-plane/supabase/proposals/project_workspace_resource_authority_v1.sql` **não inclui emissão, inserção, renovação, revogação remota ou rota HTTP**. As relações privadas têm RLS habilitado e nenhuma escrita concedida ao Edge. Sem picker de pasta confiável e consentimento explícito, o port do App continua `capability_unavailable`; não usar SQL direto para fabricar evidência do picker.

## Ordem de promoção

1. Provar CI SQL real PGlite com as próprias funções canônicas de elegibilidade e casos negativos; auditar privilégios e FKs do PostgreSQL canônico somente por leitura. A proposta vive fora de `migrations/` e não altera o ledger aplicado.
2. Após autorização específica futura, gerar a migração com o CLI canônico, revisar, aplicar pelo owner e registrar no `control-plane/supabase/migration-registry.json` somente a versão realmente aplicada e o hash Git exato. Não adicionar migração não aplicada nem registrar uma aplicação fictícia. Não aplicar em produção neste gate.
3. Criar seletor atestado no Runtime e mecanismo de emissão Owner restrito, com recibo/auditoria transacional e revogação. Revisar o escopo do grant e o modo de autenticar actor/session no canal real.
4. Conectar verificação ao transporte Device/Product autenticado e ao `ProjectWorkspacePort` já existente; negar payload que contenha path, token ou identidade de ator derivada de modelo.
5. E2E Windows com fixture VESTE descartável: seleção humana, ler snapshot, revogar, mover pasta, reiniciar, provar nenhuma leitura sem grant e nenhuma escrita. Somente então reclassificar M1 como operacional.

**Não confundir a existência do verificador com uma autorização real.** Esta etapa é exclusivamente definição de persistência e prova read-only offline.