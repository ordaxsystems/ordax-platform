# OrdaX Platform MCP — prontidão OAuth 2.1 (2026-10-11)

**Autoridade:** OrdaX Platform + Supabase Auth canônico; não existe autenticação substituta no Worker. Código: `control-plane/cloudflare/src/product_oauth_readiness.ts` e `product_mcp_entry.ts`.

## Endpoints de operação

- `GET /health`: prova **somente** vida do Worker e presença de configurações declaradas. `auth_configured=true` **não** prova que o OAuth Server está habilitado, que um cliente foi cadastrado, nem que um PC está disponível.
- `GET /ready`: consulta, sem credenciais e com limite de 5 segundos, a descoberta OAuth 2.1 oficial do projeto Supabase. Exige issuer exato, HTTPS na mesma origem para endpoints, registro dinâmico de clientes (DCR), grant `authorization_code`, PKCE `S256` e método público `none`. Nunca segue redirecionamentos; aceita no máximo 64 KiB.
- HTTP **200** em `/ready`: **apenas** descoberta OAuth conforme o contrato. `supports_remote_actions=false` permanece inalterado no canary. Não garante consentimento real, login, refresh, dispositivo, grants, inferência ou Runtime.
- HTTP **503** em `/ready`: OAuth ausente, desabilitado, incompleto, com metadados inválidos ou indisponível. Falha segura: nenhuma tentativa de registrar um cliente alternativo ou fallback D1.

## Estado real verificado

Em `2026-10-11`, `python scripts/cloudflare/verify_product_oauth_server.py https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1` executado no Windows conectado retornou **HTTP 404**. Nenhuma configuração do OAuth foi alterada: o plugin Supabase conectado não dispõe de ação para gerenciar OAuth Server e não havia token administrativo já configurado no ambiente Windows. O servidor de validação permanece *read-only*, e o MCP antigo não é redirecionado.

## Habilitação pela autoridade oficial

1. Acessar o projeto Supabase canônico e habilitar **Authentication → OAuth Server**.
2. Definir `/oauth/consent`, apontando a `Site URL` para a página de consentimento própria e já publicada. Não criar outra UI no Worker.
3. Habilitar **Dynamic Client Registration (DCR)** para que o ChatGPT possa cadastrar seu cliente MCP público com `authorization_code` e PKCE `S256`. Validar sessões, revogação e consentimento pelo client_id exato.
4. Confirmar a descoberta oficial pelo verificador read-only e por `GET /ready`, em seguida executar OAuth E2E no **MCP personalizado** do ChatGPT com conta e usuário reais.
5. Só avançar para execução remota depois de parear os PCs na autoridade PostgreSQL, conceder o perfil necessário ao **cliente OAuth exato** e confirmar Full Access local no Studio. O modo local não contorna grants e vice-versa.

**Não** ativar `deployment_ready` por flag, copiar tokens para o Worker, reduzir escopos de RLS ou reutilizar cookies de sessão ChatGPT. O cutover real é tratado em #42 e a falha de Space não autorizado em #118.
