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
