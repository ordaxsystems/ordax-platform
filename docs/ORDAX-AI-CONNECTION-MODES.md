# OrdaX — modos oficiais de conexão com IA

**Decisão arquitetural — 2026-10-15**

Este documento é a referência canônica para evitar confusão entre o **MCP direto do usuário** e o **OrdaX Central**. Eles compartilham identidade, contratos de ferramentas, Runtime, grants e auditoria quando aplicável, mas **não são o mesmo caminho de conversa**.

## Modo 1 — ChatGPT direto do usuário

Fluxo de conversa:

```text
Usuário -> conta ChatGPT do próprio usuário -> MCP OrdaX -> Runtime/Studio autorizado
```

Regras:

- a conversa e a inferência acontecem no ChatGPT do próprio usuário;
- o OrdaX **não recebe a mensagem para encaminhá-la a um modelo** e não age como relay de inferência;
- o MCP fornece ferramentas/recursos OrdaX ao ChatGPT;
- Windows: o usuário instala OrdaX Studio + OrdaX Runtime;
- OrdaX OS: Studio/Runtime fazem parte nativamente do sistema;
- ambos devem expor o mesmo contrato lógico de ferramentas e permissões;
- autenticação continua obrigatória; não substituir OAuth por `No Auth` para controle de dispositivo;
- um serviço de identidade/control-plane pode autenticar, registrar dispositivo, resolver grants e auditar, sem se tornar um relay da conversa.

### Transporte

O ChatGPT precisa de um endpoint HTTPS alcançável. Há duas implementações válidas sob o mesmo contrato:

1. **MCP público canônico atual:** `https://mcp.ordax.com.br/mcp` — usado na validação OAuth/read-only atual;
2. **MCP direto por dispositivo:** endpoint HTTPS estável que termina no Runtime local por conexão/túnel seguro iniciado pelo próprio dispositivo.

No segundo caso, `Server URL` continua sendo o campo cadastrado no ChatGPT; o túnel é apenas o transporte por baixo dessa URL. Não usar URL descartável de demonstração como identidade permanente de produto.

O endpoint canônico atual não deve ser descrito como "OrdaX Central chamando o GPT": ele não chama um modelo para responder ao usuário. Ele é gateway MCP/control-plane.

## Modo 2 — OrdaX Central

Fluxo de conversa:

```text
PC/App A --\
PC/App B ----> OrdaX Central -> Model Router/provedor -> OrdaX Central -> origem correta
PC/App C --/
```

Regras:

- o usuário conversa em um app OrdaX, Studio, cliente ou integração, não necessariamente no ChatGPT;
- a Central recebe a solicitação, chama o provedor/modelo autorizado e devolve a resposta;
- deve suportar múltiplos usuários, dispositivos e solicitações concorrentes;
- toda solicitação precisa de correlação explícita, no mínimo `user_id`, `device_id`, `session_id`, `conversation_id` e `request_id`; `space_id`/`project_id` entram quando houver contexto correspondente;
- respostas podem chegar fora de ordem; o `request_id` determina a entrega correta;
- não automatizar uma única sessão web de ChatGPT como infraestrutura multiusuário permanente; usar integração/provedor autorizado pelo Model Router;
- a Central pode reutilizar contratos OrdaX de identidade, grants, Runtime, tools e auditoria, mas não transforma o Modo 1 em relay.

### Transporte

- clientes/PCs normalmente iniciam conexão outbound HTTPS/WebSocket para a Central; não precisam de um túnel individual;
- se a Central rodar em uma máquina privada sem endpoint público, **um túnel na Central** pode publicar o serviço;
- se a Central estiver em cloud/VPS com HTTPS público, túnel não é obrigatório.

## Privacidade e anonimato

Não prometer "anonimato" em nenhum modo.

- **Modo 1:** o provedor conhece a conta ChatGPT do próprio usuário. Um túnel pode ocultar o IP residencial direto do endpoint MCP, mas isso é privacidade de rede, não anonimato da conta.
- **Modo 2:** a Central pode pseudonimizar identificadores antes de chamar um provedor e não encaminhar nome/email/IP do usuário final quando não forem necessários. O provedor ainda recebe o conteúdo enviado e metadados da chamada da Central; o OrdaX continua conhecendo o vínculo interno necessário para roteamento, autorização e auditoria.

## Regra para implementação

Antes de alterar MCP, Runtime, Studio, Model Router ou Central, declarar explicitamente qual modo está sendo modificado.

- Mudança no **MCP direto** não pode criar dependência obrigatória da Central de inferência.
- Mudança na **Central** não pode converter a conta ChatGPT do usuário em conta compartilhada nem reutilizar sessão/cookies de outro usuário.
- O mesmo catálogo/contrato lógico pode ser reutilizado, mas transporte, identidade do chamador do modelo e ownership da conversa permanecem separados.

Os nomes históricos `product_central_*` no código de sessão/atestado referem-se a mecanismos de sessão/coordenação existentes e **não devem ser interpretados automaticamente como o OrdaX Central de inferência descrito neste documento**. Renomeações futuras devem preservar compatibilidade e segurança, não ser feitas apenas para estética.
