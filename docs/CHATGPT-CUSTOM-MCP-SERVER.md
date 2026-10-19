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

## Atualização

A URL do servidor é estável. Uma nova versão do Worker, Control Plane, Runtime ou implementação de uma tool **não exige criar `/mcp-v2`, `/mcp-v3`, reinstalar o servidor ou trocar a URL**.

Existem dois tipos de atualização:

1. **Implementação sem mudança de catálogo/schema de tools.** O deploy é transparente para o cadastro existente do ChatGPT. Nenhuma ação do usuário é esperada.
2. **Mudança na superfície MCP** — nova tool, remoção, renomeação ou alteração relevante de schema. Depois do deploy e dos gates, usar **Atualizar ferramentas** nas configurações do servidor MCP no ChatGPT para que o cliente releia a superfície publicada.

OAuth só deve exigir nova autorização quando a própria sessão, consentimento ou política de acesso exigir. Atualizar tools não deve ser usado para contornar grants nem para ampliar permissões silenciosamente.

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
