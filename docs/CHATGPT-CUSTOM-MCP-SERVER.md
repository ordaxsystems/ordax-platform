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

## Superfície MCP publicada em 16/10/2026

A conexão autenticada atual reporta **18 tools**. A existência de uma tool no catálogo significa que o ChatGPT conhece seu contrato; **não significa que ela esteja autorizada em todos os computadores**.

### Identidade, descoberta e continuidade

- `ordax_session` — verifica a sessão OrdaX autenticada;
- `ordax_profile` — retorna a identidade opaca estável do perfil;
- `ordax_targets` — lista dispositivos autorizados, presença, Spaces e grants;
- `ordax_action_status` — consulta o estado/resultado de uma ação já aceita.

### Observação do computador

- `computer_windows` — janelas visíveis;
- `computer_active_window` — janela em primeiro plano;
- `computer_screenshot` — captura da área de trabalho ou janela ativa;
- `computer_screen_info` — monitores, desktop virtual e cursor;
- `computer_access_status` — política local de acesso e roots permitidos;
- `computer_processes` — metadados limitados de processos.

### Interação tipada com o computador

- `computer_focus_window` — traz uma janela visível para primeiro plano;
- `computer_click` — clique limitado e validado;
- `computer_mouse_move` — movimento validado do ponteiro;
- `computer_drag` — gesto de arrastar limitado;
- `computer_launch_app` — inicia executável validado, sem expansão de shell;
- `computer_scroll` — rolagem limitada;
- `computer_type` — digitação Unicode limitada;
- `computer_hotkey` — atalho de teclado validado e limitado.

Todas as ações de mutação permanecem submetidas ao grant aplicável, à política local do Runtime e aos limites do sistema operacional. A superfície atual não deve ser descrita como “somente leitura”; ao mesmo tempo, **publicada** não é sinônimo de **concedida**.

## Camadas de autorização

Para uma ação local acontecer, as seguintes condições são independentes e precisam estar válidas:

1. sessão OAuth autenticada;
2. target pertencente/visível à conta e ao cliente OAuth correto;
3. capability/grant explícito para a ação;
4. Runtime do target conectado e apto;
5. política local permitindo a operação, aplicação, root ou gesto;
6. validação dos argumentos e limites da tool;
7. auditoria/receipt/status da ação.

Por isso, um computador pode aparecer em `ordax_targets` e ainda rejeitar clique, screenshot, digitação ou abertura de aplicativo. Isso é comportamento esperado e fail-closed.

## O que ainda falta para o básico completo

O próximo marco não é aumentar indiscriminadamente o número de tools, e sim completar as famílias tipadas necessárias para um fluxo de desenvolvimento ponta a ponta:

| Família | Situação | Básico esperado |
| --- | --- | --- |
| OAuth, sessão, targets, presença | disponível | manter isolamento, revogação e E2E |
| Computer Control | superfície publicada | concluir grants reais e E2E por target |
| Arquivos/projetos | fundação existente, não faz parte das 18 tools atuais | listar roots/projetos, ler, buscar, criar e editar de forma grant-scoped |
| Git | ainda não faz parte da superfície atual | status, diff, branch, commit, pull/push e PR tipados |
| Processos de desenvolvimento | parcial | iniciar/parar processo autorizado, logs, portas, health e preview |
| Browser de testes | ainda não faz parte da superfície atual | navegar, clicar, preencher, inspecionar e validar UI sem depender de shell genérico |
| OrdaX Studio | integração a consolidar | projeto ativo, workspace, preview e continuidade estruturada |
| Blender | adapter especializado a promover | operações de cena/validação por tools próprias |
| Unity | adapter especializado a promover | projeto, editor/play mode, logs e validação por tools próprias |
| Grants/Owner UI | em evolução | perfis de capability claros, revisão, revogação e expiração |
| Auditoria/E2E | em evolução | ChatGPT -> MCP -> gateway -> Runtime -> resultado, com identidade e provenance verificáveis |

Terminal genérico não deve substituir APIs tipadas. Quando terminal for necessário, ele deve ser uma capability própria, limitada e auditável.

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
