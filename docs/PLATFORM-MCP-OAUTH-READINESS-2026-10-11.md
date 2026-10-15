# OrdaX Platform MCP — prontidão OAuth 2.1

**Atualizado em 2026-10-15.**

**Autoridade:** OrdaX Platform + Supabase Auth canônico. O Worker não mantém autenticação substituta, não aceita credencial de operador como OAuth Product e não possui fallback D1.

## Endpoint canônico

O único ingresso MCP Product válido é:

- `https://mcp.ordax.com.br/mcp`
- Worker Cloudflare: `ordax-mcp`
- autoridade persistente: PostgreSQL via Hyperdrive
- OAuth issuer: `https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1`
- `workers.dev`: desabilitado no Worker canônico
- remote actions: **desabilitadas** até os gates E2E finais

O pacote oficial em `plugins/ordax-chatgpt/` e o pacote privado de validação OAuth em `integrations/chatgpt/product-canary/` apontam para esse mesmo endpoint. O pacote privado não cria outro Worker; ele limita a superfície às quatro ferramentas read-only para testar DCR/login/consentimento com segurança.

## Endpoints de operação

- `GET /health`: prova vida do Worker e configuração declarada. Não prova OAuth completo, consentimento, dispositivo ou grants.
- `GET /ready`: consulta a descoberta OAuth 2.1 oficial do Supabase com prazo limitado e falha segura. Exige issuer exato, HTTPS, DCR, `authorization_code`, PKCE `S256` e cliente público.
- `GET /.well-known/oauth-protected-resource`: anuncia a autoridade OAuth do recurso MCP.
- `POST /v3/device/setup`: bootstrap canônico de dispositivo; sem credencial válida deve falhar antes de qualquer autoridade de dispositivo.
- `POST /mcp`: transporte Streamable HTTP do plugin.

## Evidência pública já comprovada

A prova externa atual do domínio canônico está versionada no GitHub Actions:

- run `38705274585`
- `GET https://mcp.ordax.com.br/health` → HTTP 200
- Worker em `read-only-canary`
- `supports_remote_actions=false`
- `POST https://mcp.ordax.com.br/v3/device/setup` sem login → HTTP 401 `product_auth_required`
- Worker Version observada: `95c5b0cd-3f65-4cee-8d02-46f6bc1a91bb`

A descoberta pública OAuth 2.1 do Supabase já havia comprovado DCR, `authorization_code`, PKCE `S256` e cliente público. A evidência histórica do antigo Worker canary serviu para validação inicial, mas **não é mais o endpoint operacional**.

## Baseline OAuth antes do primeiro ChatGPT real

Em 2026-10-15, antes de conectar o pacote privado ao ChatGPT, o projeto oficial `jhfphsjptrpmtnzkpwud` apresentava:

- `auth.oauth_clients`: **0**
- `auth.oauth_consents`: **0**
- `auth.oauth_authorizations`: **0**
- `auth.oauth_client_states`: **0**

Esse baseline torna o primeiro E2E inequívoco: o primeiro cliente criado depois da conexão deve ser atribuível ao fluxo real do ChatGPT, não a teste anterior.

## Critério de prova do OAuth ChatGPT

Não remover `chatgpt_oauth_client_consent_not_verified` apenas porque discovery ou `/ready` retornam 200. A prova precisa demonstrar, no fluxo real do ChatGPT:

1. **DCR real:** novo registro em `auth.oauth_clients` criado pelo cliente ChatGPT, com `client_id` próprio, redirect URI válido e cliente público.
2. **PKCE:** autorização real usando challenge com método `S256`; não aceitar fluxo sem PKCE.
3. **Consentimento:** registro em `auth.oauth_consents` para o usuário e `client_id` exato.
4. **Authorization Code:** autorização real vinculada ao mesmo `client_id`, usuário, redirect URI e scopes.
5. **Token/refresh:** a sessão obtida pelo ChatGPT autentica o MCP sem reutilizar cookie, token antigo ou credencial de outro cliente.
6. **Isolamento:** outro `client_id` não pode reutilizar o consentimento/grant do cliente validado.
7. **Revogação:** revogar consentimento ou cliente deve bloquear nova autoridade, sem cache permissivo no Worker.

Nunca registrar manualmente um `oauth_clients` apenas para tornar o gate verde; o cliente deve nascer do fluxo real do consumidor MCP.

## Bootstrap de dispositivo

O contrato de bootstrap já foi integrado ao Worker canônico e ao Runtime:

- Runtime envia `device_kind` e `channel` explicitamente;
- Studio mantém o access token da conta apenas em memória;
- primeiro login detecta `device_id=null`, executa enrollment, cria pairing e reivindica o pairing;
- token bruto de dispositivo permanece local e o backend armazena hashes privados;
- pairing de propriedade **não** cria automaticamente grants remotos.

Baseline do PostgreSQL em 2026-10-15:

- devices Product: **0**
- credentials Product: **0**
- presence: **0**
- remote grants: **0**
- session challenges: **0**

No PC de desenvolvimento atual existe uma limitação externa de rota do provedor até o par anycast do custom domain. GitHub e outros destinos Cloudflare funcionam, e a prova HTTP externa do endpoint canônico está verde. Não habilitar `workers.dev`, fallback legado ou outra origem para mascarar essa rota local.

## Pacotes do ChatGPT

### Produção

`plugins/ordax-chatgpt/`

- versão atual: `0.4.9`
- endpoint: `https://mcp.ordax.com.br/mcp`
- distribuição continua bloqueada enquanto `mcp_release.deployment_ready=false` ou houver blockers.

### Validação privada OAuth

`integrations/chatgpt/product-canary/`

- versão atual: `0.2.0`
- nome interno: `ordax-product-canary`
- endpoint: `https://mcp.ordax.com.br/mcp`
- apenas: `ordax_session`, `ordax_profile`, `ordax_targets`, `ordax_action_status`
- artifact CI: `ordax-product-oauth-validation-plugin`
- finalidade exclusiva: provar DCR/login/consentimento/token do ChatGPT sem habilitar mutações remotas.

## Blockers atuais do MCP

O domínio/TLS e o contrato de device setup já foram comprovados e não devem voltar a aparecer como blockers sem regressão real. Permanecem:

1. `chatgpt_oauth_client_consent_not_verified`
2. `product_device_enrollment_and_grants_missing`
3. `central_trusted_session_attestor_not_provisioned`
4. `canonical_remote_actions_not_ready`
5. `legacy_control_plane_v3_runtime_not_retired`
6. `end_to_end_chatgpt_to_device_not_verified`

`deployment_ready` continua **false** e `supports_remote_actions` continua **false**.

## Ordem de fechamento

1. Instalar/conectar explicitamente o pacote privado de validação no ChatGPT.
2. Provar DCR + PKCE + consentimento + authorization code no Supabase oficial.
3. Registrar o PC Product pelo fluxo automático do Studio e confirmar presença canônica.
4. Criar somente os grants necessários para o `client_id` exato validado.
5. Provar a sessão confiável ChatGPT ↔ cliente OAuth ↔ PC ↔ conversa.
6. Validar leitura ponta a ponta no MCP oficial.
7. Só depois implementar/promover remote actions canônicas e provar execução ponta a ponta.
8. Retirar definitivamente o Runtime/control-plane legado quando não houver consumidor restante.

## Regras de segurança

- não ativar `deployment_ready` por flag;
- não inserir clientes OAuth manualmente para satisfazer readiness;
- não copiar tokens para o Worker;
- não reutilizar credencial do plugin antigo;
- não usar `workers.dev` como fallback produtivo;
- não reduzir RLS/grants para facilitar E2E;
- não deixar o modelo escolher `device_id`, `client_id`, grant ou autoridade fora de binding confiável;
- falhas de rede, OAuth, sessão ou grant permanecem fail-closed.
