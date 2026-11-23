# OrdaX no ChatGPT — servidor MCP personalizado

Este documento é a referência canônica para a integração direta do OrdaX com o ChatGPT.

## Nomenclatura oficial

No produto e na documentação voltada ao usuário, a integração deve ser chamada de **Servidor MCP personalizado do OrdaX** (ou, de forma curta, **OrdaX MCP**).

No ChatGPT, a entrada fica atualmente na área **Plugins**, mas a ação exibida pela interface é **Adicionar servidor MCP personalizado**. Portanto:

- **servidor MCP personalizado** é o objeto que o usuário conecta;
- **OrdaX MCP** é o serviço remoto que implementa o protocolo e publica as tools;
- `https://mcp.ordax.com.br/mcp` é o endpoint canônico e permanente;
- **OrdaX Runtime** executa, no dispositivo autorizado, as ações que exigem acesso local;
- **Control Plane** resolve OAuth, identidade, targets, grants, auditoria e coordenação;
- diretórios, manifests, workflows ou testes que ainda usam `plugin` no nome são detalhes internos de empacotamento/compatibilidade e não definem a identidade do produto.

Não criar nomes de produto como “plugin OrdaX”, “plugin MCP” ou “ORDAX Studio plugin” para descrever esta conexão ao usuário. Também não criar um segundo backend ou um endpoint versionado apenas para atualizar tools.

## Cadastro no ChatGPT

Configuração canônica:

| Campo | Valor |
| --- | --- |
| Nome | OrdaX |
| Tipo | Servidor MCP personalizado |
| URL do servidor | `https://mcp.ordax.com.br/mcp` |
| Transporte | Streamable HTTP |
| Autenticação | OAuth |
| Autoridade persistente | PostgreSQL |
| Worker | `ordax-mcp` |

Fluxo conceitual:

```text
ChatGPT do usuário
  -> OAuth OrdaX
  -> https://mcp.ordax.com.br/mcp
  -> Control Plane / grants / auditoria
  -> Runtime autorizado
  -> computador / projeto / adaptadores
```

O ChatGPT não acessa `localhost` diretamente e não recebe uma credencial mestra do dispositivo. Descoberta do target, autorização de capability e permissão local são etapas distintas.

## Forge MCP

O **Forge MCP** é um segundo servidor MCP personalizado para o mesmo usuário OrdaX, mas não é um segundo backend de identidade nem um túnel para uma máquina específica.

Configuração canônica:

| Campo | Valor |
| --- | --- |
| Nome | Forge MCP |
| Tipo | Servidor MCP personalizado |
| URL do servidor | `https://forge-mcp.ordax.com.br/mcp` |
| Transporte | Streamable HTTP |
| Autenticação | OAuth |
| Authorization Server | `https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1` |
| OAuth | descoberta automática / DCR; não preencher Client ID ou Client Secret manualmente |
| Worker | `ordax-mcp` |
| Autoridade persistente | PostgreSQL |

Fluxo conceitual:

```text
ChatGPT do usuário
  -> mesmo OAuth OrdaX/Supabase
  -> https://forge-mcp.ordax.com.br/mcp
  -> gateway Forge no mesmo Worker ordax-mcp
  -> binding persistente user + OAuth client -> Forge instance
  -> fila/lease/receipt PostgreSQL
  -> conexão outbound do Forge instalado
  -> projetos / Tasks / Runs / memória / continuidade
```

Regras de produto:

- o usuário **não** instala `cloudflared`, não autoriza zona Cloudflare e não recebe token de Tunnel;
- `forge-mcp.ordax.com.br` é um custom domain do mesmo Worker `ordax-mcp`; Cloudflare é infraestrutura de edge, não login do usuário;
- OAuth é o mesmo Supabase do OrdaX MCP, portanto a conta é a mesma; o consentimento do Forge continua separado porque é outro cliente/superfície MCP;
- o Forge instalado se conecta **outbound** à Platform; nenhuma porta pública, certificado Cloudflare ou CNAME por máquina faz parte do produto;
- a Platform conserva somente ferramentas de gerenciamento de instâncias e recibos; cada Forge publica seu próprio catálogo MCP e SHA-256. Na versão com seleção explícita, o gateway acrescenta forge_connection_status, forge_action_status, forge_instances_list e forge_instance_select; o catálogo de tarefas continua pertencendo ao Forge.
- sem uma instância Forge online, o servidor continua instalável e mostra apenas as quatro operações próprias da Platform. Listagem e seleção não executam tarefas nem transferem permissões.
- OrdaX MCP continua responsável por computador/Runtime; Forge MCP continua responsável por projetos, Tasks, Runs, memória e continuidade do Forge. Não fundir as autoridades.

O antigo Cloudflare Access app, o CNAME `cfargotunnel.com` e o Tunnel por máquina foram retirados em 14/11/2026. Não recriá-los como fallback.

## Atualização

A URL do servidor é estável. Uma nova versão do Worker, Control Plane, Runtime ou implementação de uma tool **não exige criar `/mcp-v2`, `/mcp-v3`, reinstalar o servidor ou trocar a URL**.

Existem dois tipos de atualização:

1. **Implementação sem mudança de catálogo/schema de tools.** O deploy é transparente para o cadastro existente do ChatGPT. Nenhuma ação do usuário é esperada.
2. **Mudança na superfície MCP** — nova tool, remoção, renomeação ou alteração relevante de schema. Depois do deploy e dos gates, usar **Atualizar ferramentas** nas configurações do servidor MCP no ChatGPT para que o cliente releia a superfície publicada.

OAuth só deve exigir nova autorização quando a própria sessão, consentimento ou política de acesso exigir. Atualizar tools não deve ser usado para contornar grants nem para ampliar permissões silenciosamente.

### Imagens MCP no ChatGPT — prova física e limite de apresentação (21/11/2026)

**Comportamento canônico:** `computer_screenshot(include_preview=true)`, `browser_screenshot(include_preview=true)` e `artifact_preview` mantêm as permissões existentes; previews válidas (JPEG, até 256 KiB) entram em `tools/call.result.content[]` como bloco `type: "image"`. A mesma resposta tem `structuredContent` com recibo, identificadores, tamanho e SHA-256, mas **sem** cópia dos pixels em `base64`. A projeção ocorre apenas em ação autorizada, terminal e bem-sucedida; nenhuma tool não autorizada pode produzir imagem. Implementação: `control-plane/cloudflare/src/mcp_http.ts`; provas: `control-plane/tests/product_mcp_results.test.mts`.

**Verificado no Windows físico:** Runtime `6ddefa02` instalado, Platform `9432b3c`, Worker `ordax-mcp` na versão Cloudflare `c258d5f8-0d21-4beb-a710-983983b6ad60` com 100% do tráfego durante o diagnóstico. Uma chamada real ao `computer_screenshot` em `DESKTOP-4UFL03B` produziu JPEG de 62.116 bytes; o SHA-256 foi reproduzido a partir da captura PNG salva pelo mesmo Runtime. A prévia apareceu na conversa **somente por um encaminhamento diagnóstico reduzido da imagem original**, fora da entrega MCP padrão. O retorno do conector MCP, inclusive `ordax_action_status`, expôs os metadados estruturados, mas não disponibilizou o bloco visual `content[]` para a conversa.

**Limite de integração, não falha de captura:** imagens MCP são válidas pelo protocolo, mas o suporte ao bloco visual **não é garantido** por todos os clientes ChatGPT/SDK. O [suporte no fórum OpenAI](https://community.openai.com/t/chatgpt-connector-returns-empty-for-mcp-tool-results-with-type-image-while-same-tool-works-in-mcp-inspector/1375446/5) distingue o resultado visual MCP da visão efetivamente disponibilizada ao modelo. O [guia oficial de plugins](https://developers.openai.com/plugins/build/mcp-server) diferencia `content` de `structuredContent`.

**Critério de aceitação:** não marcar "imagem visível no ChatGPT" apenas porque o Worker emite `content[1].type="image"` ou porque uma prévia foi renderizada por terminal/diagnóstico. É necessário comprovar no **cliente conectado** que esse bloco chegou ao modelo/à UI. Enquanto não houver essa prova, classificar como `MCP_image_valid__ChatGPT_visual_delivery_unverified`. Não copiar `base64` para `structuredContent`, não implantar proxy de imagem, não expor URL pública temporária e não ampliar OAuth/grants para mascarar o limite do cliente. Manter o resultado textual/estruturado e o bloco MCP original para clientes que o suportem.

### Regra de compatibilidade

- manter sempre o endpoint canônico `/mcp`;
- versionar contratos e revisão de superfície no servidor, não na URL pública;
- preferir mudanças compatíveis e aditivas;
- mudanças incompatíveis precisam de migração explícita e gate de compatibilidade;
- o botão **Atualizar ferramentas** atualiza a descoberta do cliente; ele não concede capabilities ao dispositivo.

## Superfície publicada e snapshot do ChatGPT (19/10/2026 UTC)

O Worker OrdaX MCP publicou **37 ferramentas** na revisão `2026-10-18.3` (30 de sessão/computador + sete de terminal/processos de projeto). **Esse é um retrato datado**, não outro catálogo para manutenção. As fontes executáveis de verdade permanecem `control-plane/cloudflare/src/mcp_http.ts` (contratos `tools/list`) e `control-plane/cloudflare/src/product_mcp_entry.ts` (allowlist do endpoint); os testes canônicos validam a lista exata.

As sete tools adicionais são `terminal_exec`, `process_start`, `process_status`, `process_list`, `process_logs`, `process_write_stdin` e `process_stop`. Não confundir **`computer_processes`**, leitura de processos do Windows com grant `computer-observe`, com as ações nativas **`process_*`**, vinculadas a projeto e autorizadas separadamente. Ferramentas publicadas **não** são prova de grant nem de suporte do Runtime instalado.

### Quando o ChatGPT ainda oferece menos ferramentas que o Worker

Um app conectado ao ChatGPT pode manter um **snapshot anterior de schemas de ferramentas** depois de um deploy do servidor. No incidente #216, o app OrdaX ligado ao Apps SDK (`asdk_app_6ad0f82f1ac081919f27bad656566da2`) ainda oferecia **30 ferramentas** nesta conversa, embora `ordax_session` já informasse 37 no servidor. Contar ferramentas pelo retorno de `ordax_session` não comprova que o cliente as carregou.

Procedimento oficial para **o mesmo app**:

1. Confirmar o Worker no endpoint canônico e os gates de `tools/list` e `/ready`. Não trocar a URL nem registrar um segundo MCP.
2. Abrir **ChatGPT → Configurações → Plugins → OrdaX MCP → Atualizar/Refresh** (a localização/texto exato podem variar conforme a interface). A atualização de ferramentas deve ser feita na **conexão do app**, não no plugin legado de outro ID.
3. Revisar as sete novas ações e o escopo solicitado; não aprovar grants de execução implicitamente. Abrir uma nova conversa e selecionar o **mesmo app**; verificar os nomes das sete ações no catálogo efetivamente disponibilizado ao cliente.
4. Se não existir opção de atualização no app conectado, usar o fluxo oficial de gestão/república do **próprio app Apps SDK**, preservando o registro original e a identidade OAuth. A alteração de metadados de um pacote app-backed não modifica seu registro de ferramentas; não criar cópias ou trocar o endpoint.
5. Validar separadamente o estado do target por `ordax_targets` e os grants canônicos `project-native-terminal` e `project-native-process` associados ao projeto/Space. Na ausência dos grants, as tools **devem negar** execução. Com grants e Runtime compatível, testar autorização, ação e recibo.

Não ligar `capabilities.tools.listChanged=true` como tentativa de forçar refresh sem implementar e testar também as notificações do protocolo. Atualização do catálogo, autoridade de grants e presença do dispositivo são três condições diferentes.

A descrição do app em uma publicação mais antiga pode citar "somente leitura" ou quantidades históricas de ferramentas; isso não define os privilégios atuais. **O registro do app é editado no seu próprio fluxo do Apps SDK**. O pacote de ligação app-backed permite atualização de skills, mas não aceita mudar apresentação/identidade como substituição da publicação do app.

## Camadas de autorização

Para uma ação local acontecer, as seguintes condições são independentes e precisam estar válidas:

1. sessão OAuth autenticada;
2. target pertencente/visível à conta e ao cliente OAuth correto;
3. capability/grant explícito para a ação;
4. Runtime do target conectado e apto;
5. política local permitindo a operação, aplicação, root ou gesto;
6. validação dos argumentos e limites da tool;
7. auditoria/receipt/status da ação.

Por isso, um computador pode aparecer em `ordax_targets` e ainda rejeitar clique, screenshot, digitação, leitura de arquivo ou clipboard. Isso é comportamento esperado e fail-closed.

### Gate adicional para processos e terminal por projeto

Antes de consultar `project-native-process` ou `project-native-terminal`, a Platform **resolve um vínculo exato**, administrado pelo Owner, entre um Space ativo, um Projeto ativo, uma seleção GitHub verdadeira (`repository_id` e `repository_full_name`), o dispositivo habilitado como executor daquele Space e o dispositivo vinculado ao projeto. Zero vínculos válidos gera `product_project_scope_not_found`; múltiplos geram `product_project_scope_ambiguous`. São **erros de cadastro/identidade**, anteriores à autorização. Um grant global de observação ou `full_access` Windows não corrige a ausência de projeto e não deve ser promovido como solução.

Se `process_list` ou `terminal_exec` retornar `product_project_scope_not_found`, concluir o **cadastro/vínculo do projeto e dispositivo pela autoridade Owner do OrdaX** antes de pedir grants. Não preencher tabelas ou inventar UUIDs via MCP, SQL administrativo, Surface ou Studio; o fluxo de cadastro precisa existir e confirmar essas escolhas. Só depois solicitar `project-native-process` ou `project-native-terminal` sob o **mesmo** Space, Projeto, cliente OAuth e dispositivo. A implantação desse fluxo é acompanhada na issue `ordax-platform#220`. O Studio no Windows é consumidor dos controles de permissão, não a autoridade do SO OrdaX.


## O que ainda falta para o básico completo

O próximo marco não é aumentar indiscriminadamente o número de tools, e sim completar as famílias tipadas necessárias para um fluxo de desenvolvimento ponta a ponta:

| Família | Situação | Básico esperado |
| --- | --- | --- |
| OAuth, sessão, targets, presença | disponível | manter isolamento, revogação e E2E |
| Computer Control | superfície publicada | concluir grants reais e E2E por target |
| Arquivos no computador | leitura e mutações já presentes no catálogo do servidor | concluir E2E por target, grant explícito e concorrência segura sem ampliar roots |
| Projetos/workspace | fundação existente, ainda fora da superfície direta | listar roots/projetos e operações project-scoped sem confundir autoridade de device com project |
| Git | ainda não faz parte da superfície atual | status, diff, branch, commit, pull/push e PR tipados |
| Processos de desenvolvimento | sete ferramentas de projeto publicadas no Worker; cliente ainda depende de Refresh | validar grant próprio, Runtime instalado, iniciar/parar processo, logs e recibos E2E |
| Browser de testes | ainda não faz parte da superfície atual | navegar, clicar, preencher, inspecionar e validar UI sem depender de shell genérico |
| OrdaX Studio | integração a consolidar | projeto ativo, workspace, preview e continuidade estruturada |
| Blender | adapter especializado a promover | operações de cena/validação por tools próprias |
| Unity | adapter especializado a promover | projeto, editor/play mode, logs e validação por tools próprias |
| Grants/Owner UI | em evolução | perfis de capability claros, revisão, revogação e expiração |
| Auditoria/E2E | em evolução | ChatGPT -> MCP -> gateway -> Runtime -> resultado, com identidade e provenance verificáveis |

Terminal genérico não deve substituir APIs tipadas. Quando terminal for necessário, ele deve ser uma capability própria, limitada e auditável. Como `terminal.exec` é project-scoped, ele não deve ser promovido pela allowlist de device: precisa de binding e autorização de projeto explícitos.

## Gate para chamar a primeira versão de “básico completo”

Considerar o básico completo quando for possível, com grants explícitos, executar de ponta a ponta uma solicitação equivalente a:

> abrir um projeto autorizado, ler e editar arquivos, verificar Git, iniciar o preview, abrir o navegador de testes, interagir com a interface, consultar o resultado e produzir um commit verificável.

Esse gate precisa passar sem Desktop Commander como dependência normal do produto e sem bypass de OAuth, grants, política local ou auditoria.

## Fonte de verdade

- endpoint e release MCP: `control-plane/cloudflare/production-foundation.json#mcp_release`;
- implementação do endpoint: `control-plane/cloudflare/src/product_mcp_entry.ts`;
- política de Computer Control: `docs/COMPUTER_CONTROL_POLICY.md`;
- conexão e arquitetura: `docs/PRODUCT_MCP_CONNECT.md`;
- configuração de empacotamento compatível com clientes MCP: `plugins/ordax-chatgpt/mcp.json`.

Arquivos históricos que usam a palavra `plugin` podem permanecer enquanto forem necessários para compatibilidade de build/review. Novos documentos e comunicação de produto devem usar **Servidor MCP personalizado do OrdaX / OrdaX MCP** como nomenclatura canônica.

## Seleção explícita de instância Forge

A vinculação entre um cliente ChatGPT e uma instância Forge é persistente e
pertence exatamente à dupla conta + cliente OAuth. Ela nunca muda porque uma
instância ficou offline ou porque outra anunciou presença.

- forge_instances_list lista apenas instâncias registradas na mesma conta e
  informa o ID selecionado. Não entrega tokens, diretórios nem catálogo externo.
- forge_instance_select exige o ID da nova instância e o ID anteriormente
  vinculado (expected_instance_id). O ID anterior só pode ser omitido quando
  não existia vínculo. O banco rejeita instâncias de outra conta, offline,
  revogadas, alterações concorrentes e solicitações ainda em execução.
- O novo vínculo determina somente o destino de futuras chamadas do MCP.
  Tasks, SQLite, grants, ações aceitas e recibos de cada instância continuam
  sob suas autoridades originais. Reconsultar tools/list mostra o catálogo
  atualizado, sem inventar ferramentas ou fazer chamadas automaticamente.

**Gate de implantação:** aplicar e validar
control-plane/supabase/migrations/20261123020000_forge_mcp_explicit_instance_selection_v1.sql
no PostgreSQL de produção **antes** de promover o Worker com as novas
operações. Não atualizar os metadados de implantação confirmada na
production-foundation.json até a prova dos dois lados. Main e testes verdes
isoladamente não confirmam que o cliente ChatGPT já selecionou outra instância.
