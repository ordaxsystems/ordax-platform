# Project-First M1 — recurso local subordinado ao Product grant

**Estado: proposta SQL validável, não migração aplicada nem capacidade habilitada em produção.** Issue: [#266](https://github.com/ordaxsystems/ordax-platform/issues/266). Uma PR de schema não autoriza migração, deploy, troca de grant ou leitura de pastas pessoais.

## SSOT e isolamento

- **Projeto/Space**: `ordax_projects`, `ordax_spaces`, vínculos `ordax_space_devices` / `ordax_device_project_bindings` e `ordax_product_devices`; identidade de repositório mantida pelo resolver Owner existente.
- **Permissão**: `ordax_remote_capability_grants`, com OAuth client e consentimento vivos. Somente `project-workspace-read` + `workspace.project_snapshot`, `read`, escopo `project`, prazo curto e device concreto. Grants amplos de Computer Control não valem.
- **Identidade local**: `private.ordax_lab_project_authorities` associa um ID local não confiável a exatamente um projeto canônico por Owner/client. O vínculo não tem permissão própria.
- **Recursos**: `private.ordax_workspace_resource_bindings` guarda só referência opaca, actor, sessão, device, prazo e FK ao grant existente. Não guarda path, conteúdo, token, credencial ou segredo; várias raízes por projeto não exigem novo cadastro do projeto.
- **Verificação**: `public.ordax_verify_project_workspace_resource_v1` faz join completo sobre relações canônicas, consentimento, revogação e expiração **a cada chamada**, devolvendo só prova limitada. A API não está conectada ao App.
- **Filesystem e Git**: Runtime é owner exclusivo. O SQL não prova que a raiz local existe, é segura contra junction/symlink ou preservou identidade. Runtime precisa revalidar isso antes e depois de cada snapshot.

## Consulta pelo transporte Device/Product existente — código preparado, desabilitado

A Platform contém o ponto de integração read-only `POST /v3/device/transport/workspace-proof` **no handler canônico de transporte Device**, não em um MCP novo. A implementação é `source-only` e exige a configuração literal `WORKSPACE_RESOURCE_VERIFIER_ENABLED=enabled`; ausente ou qualquer outro valor retorna `not_found` após o gate normal de autenticação do dispositivo. **Não configurar essa flag até a migração aprovada, a emissão/revogação e o E2E**. Sem a função SQL aplicada, a operação falha fechada.

O request aceito pelo dispositivo já autenticado contém exclusivamente `owner_user_id`, `actor_id`, `client_id`, `lab_project_id`, `workspace_session_id` e `resource_id`; **não aceita** `device_id`, Space, projeto Product, `path`, token, grant ou permissões do caller. `device_id` é fornecido pelo resultado da autenticação Device existente. Os identificadores da requisição são **chaves de consulta, não autoridade**: `public.ordax_verify_project_workspace_resource_v1` é quem valida todos eles contra ledger, consentimento e vínculo vivos no PostgreSQL.

A função de store `verifyProjectWorkspaceResource` reutiliza o `callRpc` com parâmetros vinculados e RPC allowlisted. A resposta só é liberada se a função SQL retornar `ordax.project-workspace-resource/1` e o resultado passar pelo `projectWorkspaceGrantProjection` existente com todas as identidades coincidentes, `read` e validade original máxima de 24h. Nem caminhos locais nem credenciais são retornados. Falhas de schema, grant ou revogação produzem uma negativa genérica; nenhuma autorização é inferida do JSON do dispositivo.

Os testes cobrem request allowlist, impossibilidade de escolher outro device pelo corpo, grant de outro Owner/actor/client/session/projeto/recurso, revogação, conteúdo extra, expiração e ausência de autenticação. A nova consulta **não** cria, renova ou revoga grants nem implementa o picker; a migração e a ativação permanecem bloqueadas pela issue #266. A credencial Device identifica o transportador, enquanto o PostgreSQL valida o grant e seu ator: não interpretar uma chamada com resourceId como consentimento novo.

## Emissão em duas fases — proposta SQL, sem endpoints e sem ativação

A proposta canônica agora especifica a autorização inicial **sem criar outro ledger de grants**. A tabela privada `ordax_workspace_owner_intents` registra exclusivamente decisões pendentes por até cinco minutos: Owner/client/Lab/Space/Product project/device/actor/session e um `resourceId` não bearer. Não contém caminho, inode, token ou conteúdo, tem RLS `FORCE` e não oferece escrita direta a nenhuma role externa.

O fluxo exige **duas autenticações independentes** e a existência prévia do grant `project-workspace-read` / `workspace.project_snapshot`, `read`, no **mesmo projeto e dispositivo**, com OAuth consentido:

1. O host Owner autenticado apresenta o projeto e a pasta, exige confirmação explícita pelo diálogo nativo e obtém uma referência opaca do Runtime. **Somente depois** a interface de Owner envia ao futuro endpoint Owner um consentimento assinado com os IDs exatos. O RPC proposto `ordax_approve_project_workspace_resource_v1` verifica Owner/Space/Project, OAuth, dispositivo, associação ao projeto e grant existente. Registra o consentimento pendente (5 min), sem conceder leitura. O `lab_project_id` recebe mapeamento imutável à autoridade Product, não um grant.
2. O Runtime, sob o **dispositivo já autenticado** pelo transporte Device/Product e após a confirmação local real, apresenta ao futuro endpoint Device `intentId` e os mesmos actor/client/session/`resourceId`. O RPC proposto `ordax_commit_project_workspace_resource_v1` bloqueia a intenção, confere todos os campos, reavalia as condições do grant e cria **uma referência** na tabela privada atual apontando ao mesmo `ordax_remote_capability_grants`. Essa transação também consome a intenção. Reuso ou confirmação divergente falha; a validade da referência é no máximo uma hora e nunca excede o grant pai.
3. A revogação Owner existente também invalida intenções pendentes, mesmo sem grant emitido. Cancelar antes da segunda etapa impede uma emissão tardia; revogar depois da segunda impede a próxima leitura. A verificação do Runtime continua a ocorrer antes e depois do snapshot.

A segurança do segundo passo **depende da composição no host Owner/Device confiável**: a Platform não consegue inferir confirmação humana de um campo JSON, nem de um token Device isolado. **Não expor essas RPCs diretamente ao modelo, UI renderer, MCP genérico ou HTTP remoto não atestado**. Ambas usam `SECURITY DEFINER` com role Edge restrita porque precisam acessar tabelas privadas; não há `INSERT` direto nem bypass de `RLS` concedido às demais roles. Os testes PGlite são descartáveis e verificam owner/device/client cruzados, negativa antes da confirmação, duplicação, revogação, expiração e privilégios.

**Gates não cumpridos:** não existem endpoints HTTP Owner/Device que emitam o grant, nem composição real dos diálogos e identidade do host para esta operação. Esta SQL segue em `proposals/`, sem migração nem registro de hash aplicado. Configuração `WORKSPACE_RESOURCE_VERIFIER_ENABLED` continua desligada; nenhuma conta, pasta ou autorização real foi alterada. A proposta especifica o contrato seguro, não habilita a funcionalidade.

## Revogação pelo proprietário — proposta, bloqueada por padrão

A proposta PostgreSQL também inclui `public.ordax_revoke_project_workspace_resource_v1(uuid,uuid,text)`: função restrita à role `ordax_edge_runtime`, sem `INSERT`, sem `GRANT UPDATE` em tabelas privadas e sem modificar `ordax_remote_capability_grants`. A operação altera exclusivamente `revoked_at` da referência opaca já existente, **quando Owner, client UUID e resourceId coincidem** com o vínculo privado. Outro proprietário, outro cliente ou ID desconhecido retornam `false` e não causam efeitos. Repetições também retornam `false`. A revogação continua permitida se o consentimento OAuth tiver sido retirado; negar a revogação nessa situação prenderia o usuário a uma autorização antiga.

O endpoint `DELETE /v3/owner/workspace-resources/{resourceId}?client_id={clientUUID}` reaproveita a autenticação de Owner assinada de `product_owner_grant_admin` e o `callRpc` parametrizado existente. A identidade do Owner **nunca é aceita do request**: somente a sessão validada a fornece. `client_id` é um filtro exato, não uma autorização independente. Outras query strings, seleção arbitrária de device, caminhos e token no request não são aceitos.

O mesmo gate `WORKSPACE_RESOURCE_VERIFIER_ENABLED=enabled` permanece obrigatório. Sem ele, retorna `not_found` e nada é alterado. **Não habilitar o gate** até a migração aprovada, o emissor atestado e os testes Windows E2E. A revogação funcional futura é apenas uma parte do ciclo de vida dos recursos; **a emissão permanece apenas como proposta SQL; ainda não há host atestado nem endpoint de emissão**.

Os testes SQL PGlite verificam Owner/client errados, revogação repetida, persistência, privilégio exclusivo da role Edge e que a revogação funciona após retirada do consentimento. O ledger de grants continua intocado. Os testes HTTP verificam que o endpoint exige autenticação e rejeita formas ambíguas/indevidas.

## Operações ausentes por design

O SQL de proposta em `control-plane/supabase/proposals/project_workspace_resource_authority_v1.sql` inclui apenas funções restritas de consentimento Owner e confirmação Device, verificador de leitura e revogação. **Nenhum endpoint de emissão, migração aplicada ou capacidade instalada existe.** A rota HTTP é implementada no handler Owner existente, mas permanece desabilitada. As relações privadas têm RLS forçado, sem escrita direta concedida ao Edge; as alterações futuras são feitas somente dentro de funções `SECURITY DEFINER` explicitamente allowlisted. Sem picker de pasta confiável e consentimento explícito, o port do App continua `capability_unavailable`; não usar SQL direto para fabricar evidência do picker.

## Ordem de promoção

1. Provar CI SQL real PGlite com as próprias funções canônicas de elegibilidade e casos negativos; auditar privilégios e FKs do PostgreSQL canônico somente por leitura. A proposta vive fora de `migrations/` e não altera o ledger aplicado.
2. Após autorização específica futura, gerar a migração com o CLI canônico, revisar, aplicar pelo owner e registrar no `control-plane/supabase/migration-registry.json` somente a versão realmente aplicada e o hash Git exato. Não adicionar migração não aplicada nem registrar uma aplicação fictícia. Não aplicar em produção neste gate.
3. Integrar seletor atestado no Runtime e mecanismo de emissão Owner restrito com recibo/auditoria transacional; revalidar a revogação Owner proposta após consentimento real. Revisar o escopo do grant e o modo de autenticar actor/session no canal real.
4. Conectar verificação ao transporte Device/Product autenticado e ao `ProjectWorkspacePort` já existente; negar payload que contenha path, token ou identidade de ator derivada de modelo.
5. E2E Windows com fixture VESTE descartável: seleção humana, ler snapshot, revogar, mover pasta, reiniciar, provar nenhuma leitura sem grant e nenhuma escrita. Somente então reclassificar M1 como operacional.

**Não confundir a existência do verificador com uma autorização real.** Esta etapa é exclusivamente definição de persistência e prova read-only offline.