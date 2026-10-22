# Conectar o OrdaX ao ChatGPT

## Terminologia

No ChatGPT, o OrdaX é conectado como um **servidor MCP personalizado**.

Nome canônico de produto: **OrdaX MCP**.  
Endpoint canônico: `https://mcp.ordax.com.br/mcp`.

A interface do ChatGPT pode manter essa configuração dentro da área chamada **Plugins**, e o repositório contém arquivos internos com `plugin` no nome para empacotamento e compatibilidade. Isso é detalhe de implementação; a conexão do usuário é um servidor MCP personalizado.

A referência operacional completa está em [CHATGPT-CUSTOM-MCP-SERVER.md](CHATGPT-CUSTOM-MCP-SERVER.md).

## Arquitetura

O OrdaX Runtime mantém o computador conectado ao plano de controle. O ChatGPT não acessa `localhost` e não precisa manter um terminal aberto.

```text
ChatGPT do usuário
   |
   | OAuth + MCP Streamable HTTP
   v
https://mcp.ordax.com.br/mcp
   |
   v
OrdaX Control Plane
   |-- identidade OAuth
   |-- targets / presença
   |-- grants / Spaces
   |-- admissão / auditoria / status
   v
OrdaX Runtime autorizado
   |
   +-- Computer Control
   +-- projetos / arquivos (família em evolução)
   +-- Git (família em evolução)
   +-- preview / processos
   +-- browser de testes (família em evolução)
   +-- Blender / Unity (adapters especializados em evolução)
```

O dispositivo onde o ChatGPT está aberto é o **cliente**. O dispositivo escolhido a partir de `ordax_targets` é o **target**. Cliente e target podem ser dispositivos diferentes e o target nunca deve ser trocado silenciosamente.

## Cadastro no ChatGPT

Usar:

| Campo | Valor |
| --- | --- |
| Tipo | Servidor MCP personalizado |
| Nome | OrdaX |
| URL do servidor | `https://mcp.ordax.com.br/mcp` |
| Autenticação | OAuth |

Não usar `No Auth`, token fixo, URL `workers.dev`, endpoint temporário ou uma URL versionada criada apenas para atualizar tools.

O arquivo `plugins/ordax-chatgpt/mcp.json` preserva a configuração compatível de empacotamento do mesmo endpoint. Ele não representa um segundo servidor.

## Autenticação e autoridade

A autenticação do caminho canônico usa OAuth. A identidade persistente e os grants do MCP novo pertencem à autoridade PostgreSQL do OrdaX Platform.

Princípios obrigatórios:

- o usuário e o cliente OAuth são derivados de credenciais verificadas, não de campos fornecidos pelo caller;
- um target aparecer no catálogo não concede execução;
- grants são avaliados por capability e podem ser associados a Space/projeto;
- revogação e expiração precisam ser respeitadas em cada nova operação;
- D1 não é autoridade paralela do MCP canônico;
- não existe fallback silencioso para o Worker legado;
- o Runtime aplica uma política local adicional antes da execução.

## Medição de uso e planos

O OrdaX MCP está recebendo um medidor de chamadas para dimensionar os planos e
acompanhar o custo operacional com dados reais. A unidade observada é uma
chamada autenticada e bem-sucedida a uma ferramenta MCP. Inicialização, ping,
listagem de ferramentas, notificações, chamadas com erro e polling interno não
entram na contagem. Retries idênticos do mesmo cliente são deduplicados por uma
impressão digital HMAC-SHA-256 temporária, protegida por um segredo de
implantação; argumentos, prompts e histórico de conversa não são persistidos
pelo medidor.

Esse primeiro corte é somente de observação: a flag `MCP_USAGE_METER_MODE`
fica desligada por padrão e só pode ser habilitada com esse segredo configurado.
Não existe bloqueio por quota nem cobrança, e o
usuário continua pagando o uso do modelo diretamente ao provedor de IA. Os
agregados são por conta, ferramenta e mês-calendário UTC (somente a deduplicação é separada por cliente OAuth); ficam
somente o mês atual e o anterior. O digest de deduplicação é limpo após 24 horas
por uma rotina diária, normalmente em até 48 horas. Antes de habilitar a coleta,
a migration deve estar aplicada e o Worker implantado com a política publicada.

Preços e direitos dos planos continuam definidos no catálogo comercial do
OrdaX OS. Este ledger do Platform mede chamadas do MCP e não é uma segunda
autoridade de assinatura, grant ou entitlement.

### Consulta autenticada de consumo MCP

A Platform expõe `GET /v3/product/usage` no Worker Product MCP já existente,
sem criar outro servidor MCP ou banco paralelo. A rota exige o **JWT assinado
da Conta OrdaX**, com papel autenticado; o sujeito do token escolhe a conta.
Parâmetros de URL e payloads não podem escolher outro usuário. A leitura usa
somente `public.ordax_get_product_mcp_usage_v1`, sob a função privilegiada
existente no PostgreSQL, com seleção do agregado privado da própria conta.
`anon`, `authenticated` e `service_role` não executam diretamente essa RPC.

A resposta contém apenas mês UTC, nome de ferramenta e número de chamadas
observadas nos dois meses retidos. `collection_active_now` representa o
estado de implantação **no momento da consulta**; não comprova coleta completa
desde o começo do mês. `coverage=partial_observational` e
`billable=false` impedem interpretar os números como fatura, saldo,
franquia ou obrigação de pagamento. Um agregado vazio com coleta desativada
**não significa uso zero**.

A Conta pública do OS usa cookies HttpOnly e **ainda não consome essa rota**:
a integração futura precisa reutilizar seu gateway autenticado, sem expor o
JWT ao JavaScript, e apresentar apenas valores reais com esse aviso de cobertura.
Nenhuma assinatura, medição de storage ou limite comercial foi ativado por
este endpoint.

## Descoberta dos dispositivos

`ordax_targets` retorna somente a visão autorizada para a sessão atual, incluindo presença informada e grupos de grants publicados.

Interpretar os campos de forma estrita:

- `online=true` significa presença informada pela plataforma; não é grant;
- `last_seen_at` informa a última presença conhecida; não cria reachability;
- um dispositivo offline pode continuar no catálogo;
- um dispositivo online pode rejeitar uma operação por ausência de capability;
- `grant_groups` descreve autorização publicada para aquele target/contexto.

Não fazer scan de rede para inventar targets e não usar nome do computador como autoridade de segurança. O UUID do target retornado pelo MCP é a identidade usada nas tools.

## Superfície atual

Em 16/10/2026 a conexão autenticada do ChatGPT reporta **18 tools**.

### Sessão, perfil, targets e status

- `ordax_session`
- `ordax_profile`
- `ordax_targets`
- `ordax_action_status`

### Observação e política do computador

- `computer_windows`
- `computer_active_window`
- `computer_screenshot`
- `computer_screen_info`
- `computer_access_status`
- `computer_processes`

### Interação tipada

- `computer_focus_window`
- `computer_click`
- `computer_mouse_move`
- `computer_drag`
- `computer_launch_app`
- `computer_scroll`
- `computer_type`
- `computer_hotkey`

A superfície não é mais descrita como “somente leitura”. Ao mesmo tempo, **tool publicada não significa tool autorizada no target**.

Uma operação interativa precisa passar por todas estas fronteiras:

```text
OAuth válido
  -> target autorizado
  -> capability/grant válido
  -> sessão/transport do Runtime válida
  -> política local permite
  -> argumentos passam validação
  -> ação executa
  -> receipt/status/auditoria
```

Se qualquer etapa falhar, a operação deve falhar fechada.

## Atualização

A URL do servidor MCP permanece estável.

### Quando não é necessária ação no ChatGPT

Deploys que alterem apenas implementação do Worker, Control Plane, banco, Runtime ou comportamento interno de uma tool, preservando o contrato publicado, devem continuar funcionando pelo cadastro existente.

### Quando usar “Atualizar ferramentas”

Quando uma release adicionar/remover uma tool ou mudar de forma relevante o schema publicado, usar **Atualizar ferramentas** nas configurações do OrdaX MCP no ChatGPT.

Esse refresh:

- relê o catálogo/schema do servidor;
- não cria um novo endpoint;
- não reinstala o Runtime;
- não concede grants;
- não substitui OAuth;
- não justifica `/mcp-v2` ou outro cadastro duplicado.

Mudanças incompatíveis precisam de contrato/versionamento interno e migração explícita.

## Computer Control

Computer Control é composto por tools pequenas e tipadas. Não deve existir uma única ação genérica capaz de contornar as políticas das demais.

Exemplos de limites intencionais:

- clique e movimento usam coordenadas validadas;
- hotkeys têm conjunto/tamanho limitado;
- digitação é bounded;
- `computer_launch_app` não faz expansão de shell;
- screenshot é uma capability separada;
- processos são metadados limitados, não controle arbitrário;
- política local e roots permitidos podem ser consultados sem transformar descoberta em autorização.

Ver [COMPUTER_CONTROL_POLICY.md](COMPUTER_CONTROL_POLICY.md).

## Projetos, arquivos e Git

Essas famílias fazem parte do objetivo do produto, mas **não estão entre as 18 tools publicadas na superfície observada atualmente**.

O básico esperado é:

- listar projetos/roots autorizados;
- leitura e busca de texto;
- escrita/criação/movimentação limitada a roots autorizados;
- status/diff/branch/commit Git;
- pull/push e PR de forma tipada e auditável;
- nenhuma leitura fora do escopo por path traversal, symlink ou slug fabricado.

Não usar terminal genérico para simular essa API.

## Processos, preview e browser de testes

O objetivo é permitir um fluxo de desenvolvimento reproduzível:

1. selecionar projeto autorizado;
2. iniciar processo autorizado;
3. acompanhar logs/health/porta;
4. abrir preview;
5. navegar no browser de testes;
6. clicar/preencher/validar UI;
7. retornar evidência estruturada ao ChatGPT.

O browser de testes deve ser uma família própria de capabilities, não uma sequência opaca de automação desktop quando houver API específica disponível.

## Blender e Unity

Blender e Unity devem continuar como adapters especializados, reutilizando identidade, target, grants, auditoria e transporte do OrdaX MCP.

Não duplicar backend, autenticação ou fila para cada aplicação. O adapter define operações semânticas específicas; o Control Plane continua sendo a fronteira comum.

## Estado de release

O SSOT é `control-plane/cloudflare/production-foundation.json#mcp_release`.

No estado de 16/10/2026 ele registra:

- endpoint `mcp.ordax.com.br/mcp`;
- Streamable HTTP;
- autoridade PostgreSQL;
- `supports_remote_actions=true`;
- `validation_mode=attested-interactive-candidate`;
- `validation_deployment_ready=true`;
- `workers.dev=false`.

A promoção final ainda fica bloqueada até fechar os gates explícitos de grant interativo, E2E atestado e verificação da release canônica de ações remotas. Portanto, não confundir “surface publicada” com “controle liberado para qualquer target”.

## Gate de aceitação do básico completo

A primeira versão pode ser chamada de **básico completo** quando um usuário autorizado conseguir pedir ao ChatGPT, ponta a ponta:

> abra meu projeto, leia e altere os arquivos necessários, mostre o diff, rode o preview, teste a interface, confira o resultado e prepare o commit.

A prova deve usar o OrdaX MCP e o Runtime oficiais, com OAuth, grants, política local e auditoria, sem Desktop Commander como dependência normal e sem bypass via shell.

## Relação com OrdaX Central

Este MCP pertence ao caminho de **ChatGPT direto do usuário**. O ChatGPT já é o ambiente de inferência e chama o OrdaX apenas para capabilities.

OrdaX Central é um caminho separado no qual Apps/PCs podem enviar uma conversa ao Model Router do OrdaX. Ele pode reutilizar os mesmos contratos, identidade e Runtime, mas não deve ser inserido obrigatoriamente entre ChatGPT e MCP.

Ver [ORDAX-AI-CONNECTION-MODES.md](ORDAX-AI-CONNECTION-MODES.md).

## SSOT e arquivos relacionados

- release do MCP: `control-plane/cloudflare/production-foundation.json#mcp_release`;
- entrypoint: `control-plane/cloudflare/src/product_mcp_entry.ts`;
- cadastro/atualização no ChatGPT: `docs/CHATGPT-CUSTOM-MCP-SERVER.md`;
- endpoint canônico: `docs/ORDAX-MCP-CANONICAL-ENDPOINT.md`;
- política desktop: `docs/COMPUTER_CONTROL_POLICY.md`;
- provider boundaries: `docs/ORDAX_PROVIDER_CONNECTORS.md`;
- config MCP de empacotamento: `plugins/ordax-chatgpt/mcp.json`.

Documentos datados de canary/review permanecem como evidência histórica. Quando houver conflito entre uma evidência histórica e o SSOT atual, o `mcp_release` atual e estes documentos canônicos prevalecem.

## Nomenclatura e limites de escopo — 2026-10-19

Este documento é o contrato de **integração MCP**, não uma segunda definição de Space/Perfil. A definição funcional de Space e de Profile Pack permanece em `ordaxsystems/ordax-os/docs/SPACES-AND-PROFILES.md` e `docs/contracts/spaces-and-profile-packs.json`; a autoridade persistente de Conta, Space, Projeto e grants é o PostgreSQL canônico da Platform, com RPCs restritas.

| Conceito | Identidade / responsabilidade | Não confundir com |
| --- | --- | --- |
| Conta OrdaX | sujeito autenticado no provedor de identidade do produto; `session.subject_id` | Profile Pack, Space, credencial do dispositivo |
| `ordax_profile` | nome MCP histórico para o **identificador opaco da conta** (metadado de perfil do conector ChatGPT) | Perfil de preferências, Profile Pack ou Space |
| Perfil do usuário | preferências e configuração da conta | Profile Pack versionado |
| Profile Pack | composição versionada de apps/templates/Intelligence para um Space | identidade, Space ou fonte de dados do negócio |
| Space | ambiente de trabalho persistente, com membros, recursos e vários projetos; `ordax_spaces` | área visual chamada “workspace”, diretório local ou repositório GitHub |
| Projeto canônico | recurso do Space com identidade `ordax_projects.project_id` | slug local do Runtime ou nome de repositório |
| Repositório GitHub | origem externa verificada do projeto; `ordax_project_connections` | prova de autorização por si só |
| Dispositivo/Target | equipamento autorizado e atestado, com presença distinta de identidade | Space ou projeto |
| Grant | autorização por capability/cliente/escopo/dispositivo | vínculo de projeto, acesso de membro ou política local do Runtime |
| Capability / MCP Tool | capacidade definida pelo serviço e sua projeção pública no MCP | app instalado, entitlement ou grant |
| App / Module / Service | respectivamente produto instalável, componente funcional e serviço de execução/autoridade | tool MCP ou Profile Pack |

**Regra de não duplicação:** Platform e OS não podem manter dois Spaces persistentes com identidades incompatíveis. A Surface `ordax.spaces/1` é uma projeção de leitura; `ordax_spaces` e a autoridade RPC existente são a referência de identidade. Projetos locais usam identidade/estado próprios e somente uma **associação explícita** pode ligá-los ao projeto canônico; não fazer equivalência por slug, diretório ou nome GitHub. Fluxos específicos de Flow podem possuir um projeto de conversa próprio, mas não podem usá-lo automaticamente como grant de projeto Runtime.

**Operações MCP:** `ordax_session`, `ordax_profile`, `ordax_targets` e `ordax_action_status` são escopadas pela conta/cliente e seus próprios controles, **sem requisito de Space ou Projeto**. `computer_processes` pertence à família de observação do dispositivo, com autorização e confirmação do Runtime; não é `process_list`. `process_list` e `terminal_exec` são ações de **projeto canônico verificado**, cuja autorização atual exige um Space persistente, vínculo de repositório e duas associações dispositivo/Space e dispositivo/projeto, além de grant específico, atestação e política local. `space_id` opcional no schema não cria Space e não remove esses requisitos.

**Gate #220 / PR #222:** nenhum cadastro fictício deve ser produzido para desbloquear uma operação de dispositivo. O contrato de onboarding Owner é design-only até confirmação de equivalência com `ordax_spaces` do OS, verificação real do GitHub e testes de identidade, revogação, concorrência e E2E. Não habilitar cadastro, merge de migrações ou grants automáticos por mera passagem em teste estático. Ferramentas básicas/observação devem continuar independentes de vínculo artificial de projeto. Não alterar o contrato `ordax_profile` nem os nomes das ferramentas sem migração compatível.

**Verificação de metadados do banco ativo (19/10/2026, somente leitura):** chaves reais `public.ordax_spaces.space_id` e `public.ordax_projects.project_id`; as RPCs `ordax_create_space_v1`, `ordax_create_project_v1` e `ordax_resolve_owner_project_scope_v1` estão presentes. A presença de nomes iguais no OS/Platform não prova por si só uma única rota de implantação para todos os consumidores; confirmar migrations, leitura `/account/spaces` e sessão real antes de liberar o onboarding da #220.

## Inventário de nomes e compatibilidade — 2026-10-19

Inventário de **conceitos**, não nova SSOT de produto: as fontes canônicas permanecem nas autoridades e contratos indicados. Identidades verificadas por leitura dos repositórios e **metadados** (sem linhas de usuário) do PostgreSQL Product ativo.

| Conceito | Nome atual / ambiguidade encontrada | Nome canônico / experiência | Fonte de verdade | Ação de compatibilidade |
| --- | --- | --- | --- | --- |
| Identidade | Account, profile, Owner subject, `ordax_profile` | **Conta OrdaX** / account subject | OAuth Platform, `session.subject_id` | preservar nome/output de `ordax_profile` como compatibilidade ChatGPT, corrigir descrição |
| Preferências da conta | Profile, Account Profile | **Perfil** / account preferences | autoridade de conta OS/Platform | distinguir de Profile Pack e Space, sem novo registro |
| Composição de vertical | Profile, Pack, Professional Profile | **Pacote de perfil** / Profile Pack versionado | `ordax.profile-packs/1` OS | nunca usar como espaço persistente nem grant |
| Ambiente de atividade | Space, Workspace, espaço de trabalho | **Espaço** / Space | `ordax_spaces.space_id`, `ordax.spaces/1` como projeção | reconciliar `/account/spaces` e autenticação do OS com o mesmo UUID; não criar outra tabela |
| Tipo de atividade | profile kind, Space type | **Tipo de espaço** / `domain + subtype` | `ordax_spaces.domain/subtype`, catálogo semântico OS | não inferir providers/entitlement por nome |
| Trabalho persistente cloud | Project, repo, workspace | **Projeto** / Project | `ordax_projects.project_id`, RPCs Platform | preservar FK para Space; não equiparar a slug/diretório |
| Trabalho local | Project, `project-N`, slug, Workspace | **Projeto local** / local Runtime project | `ordax.project-catalog/1` (OS), Runtime workspace | associação explícita e verificável ao cloud Project quando necessária |
| Código externo | project/repository, GitHub account | **Repositório** / repository | GitHub ID/install + `ordax_project_connections` | nunca autorizar por nome de repositório fornecido pelo modelo |
| Máquina | Target, Device, PC | **Dispositivo** / Device | `ordax_product_devices` + Runtime credentials | identidade, presença, operação e grant são gates separados |
| Space ⇄ máquina | Space device, target Space | **Associação Espaço–dispositivo** | `ordax_space_devices` | exigir onde operação é escopada pelo Space; não propagar a leitura básica de device |
| Projeto ⇄ máquina | Device project binding, local project ref | **Vínculo Projeto–dispositivo** | `ordax_device_project_bindings` | sem binding implícito por caminho |
| Responsável | Owner (Space), Owner (device), operator | **Proprietário** com tipo de autoridade explícito | `ordax_spaces.owner_user_id`, identidade dispositivo e grants próprios | não conceder acesso por simples rótulo Owner |
| Permissões | Grant, role, capability, entitlement | **Permissão/grant** da ação com escopo | Platform authorization + Runtime policy | não confundir papel de membro, entitlement, capability e grant |
| Produto instalável | App, Module, Tool, Service | **Aplicativo** / App (Loja) | Store verified catalog / OS app SDK | módulo é componente, MCP tool é entrada, serviço é executor/autoridade |
| Ferramenta exposta | MCP tool, capability | **Ferramenta MCP** / Tool | `mcp_http.ts` + projection Product | manter nomes públicos e schemas compatíveis |
| Chat Flow | Flow Project, Task, Run | **Projeto de conversa**, **Tarefa**, **Execução** | OrdaX Flow owner (não Project Runtime) | `/v1/projects` não cria `ordax_projects`; vinculação futura explícita |
| Área do Studio | Workspace, Project view, Central | **Pasta/Área de trabalho** | Studio UI; Runtime local | nunca usar `Workspace` como alias técnico de Space |

### Matriz de consumidores e sequência sem alteração destrutiva

1. **Identidade e schema:** confirmar roteamento autenticado `/account/spaces` do OS, o mesmo `space_id` no banco da Platform, sem migração por nomes. Comparar migrations instaladas contra fontes versionadas: as RPCs recentes `ordax_mutate_space_lifecycle_v1` / `ordax_mutate_space_membership_v1` do OS ainda não foram observadas no banco consultado.
2. **Apps/Studio:** manter `workspace.project_create` e `projects.list` para projeto **local**. Um futuro vínculo cloud reutiliza `ordax_projects`, `ordax_project_connections` e bindings existentes sob autorização do Owner; não transformar cliques de criação local em SQL implicitamente.
3. **MCP:** Core `ordax_session/ordax_profile/ordax_targets/ordax_action_status` permanece independente de Space/Projeto. Computer Control observa/opera o dispositivo com OAuth/atestação/grant/política local conforme ação. Native `terminal_exec` e `process_list` resolvem Projeto + Space canônicos e a permissão exata.
4. **Runtime/Flow:** Runtime mantém executor local e valida policy; Flow mantém Tasks/chat/Hub sem requisito de boot OS, Studio ou MCP básico.
5. **Migrações futuras:** se a auditoria de tráfego e IDs provar incongruência, planejar migration aditiva versionada, tradução limitada de versões dos clientes e provas de revogação, concorrência, multiusuário, consentimento e rollback. Não renomear a quente nem habilitar comandos somente para desbloquear o onboarding.

A PR `ordax-platform#222` continua **bloqueada por design** até conclusão dessas provas. Testes estáticos/CI e FKs reais são evidência de modelo, **não** demonstração de sincronismo E2E ou de migrações implantadas em todos os destinos.

## Catálogo publicado e sessão conectada

A projeção Product MCP canônica de 19/10/2026 publica **44 ferramentas**, mas essa contagem é **somente do servidor**. Existem dois grupos distintos de execução nativa: sete ferramentas de **dispositivo** (`computer_terminal_exec`, `computer_process_*`) e sete ferramentas de **projeto** (`terminal_exec`, `process_*`). As primeiras não recebem projeto sintético; as últimas continuam dependendo do vínculo de Projeto e Space autorizado.

Uma conexão do ChatGPT já aberta pode expor uma versão anterior. Nesta conversa, `ordax_session` anunciou 44 ferramentas e a sessão disponibilizou 37; faltavam exatamente as sete operações nativas de dispositivo. O incidente está registrado na [issue #216](https://github.com/ordaxsystems/ordax-platform/issues/216). Compare os **nomes** realmente retornados em `tools/list` na mesma identidade OAuth e URL canônica com os nomes disponibilizados no cliente. Uma mera contagem não aprova funcionalidade nem autorização.

Atualize a conexão pela ação oficial de reconectar/recarregar o plugin ChatGPT. Não registre outro MCP, não altere endpoint ou OAuth, não modifique `tools.listChanged` sem implementar corretamente as notificações MCP e não crie grants só para forçar a exibição. Após a reconexão, exigem-se separadamente presença do Runtime compatível, política local, consentimento e grants Owner, teste negativo e prova E2E real.
