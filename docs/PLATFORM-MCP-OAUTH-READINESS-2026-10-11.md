# OrdaX Platform MCP — prontidão OAuth 2.1 (2026-10-11)

**Autoridade:** OrdaX Platform + Supabase Auth canônico; não existe autenticação substituta no Worker. Código: `control-plane/cloudflare/src/product_oauth_readiness.ts` e `product_mcp_entry.ts`.

## Endpoints de operação

- `GET /health`: prova **somente** vida do Worker e presença de configurações declaradas. `auth_configured=true` **não** prova que o OAuth Server está habilitado, que um cliente foi cadastrado, nem que um PC está disponível.
- `GET /ready`: consulta, sem credenciais e com limite de 5 segundos, a descoberta OAuth 2.1 oficial do projeto Supabase. Exige issuer exato, HTTPS na mesma origem para endpoints, registro dinâmico de clientes (DCR), grant `authorization_code`, PKCE `S256` e método público `none`. Nunca segue redirecionamentos; aceita no máximo 64 KiB.
- HTTP **200** em `/ready`: **apenas** descoberta OAuth conforme o contrato. `supports_remote_actions=false` permanece inalterado no canary. Não garante consentimento real, login, refresh, dispositivo, grants, inferência ou Runtime.
- HTTP **503** em `/ready`: OAuth ausente, desabilitado, incompleto, com metadados inválidos ou indisponível. Falha segura: nenhuma tentativa de registrar um cliente alternativo ou fallback D1.

## Estado real verificado

**Evidência mais recente, 11/10/2026 às 22:14 UTC:** a prova HTTP externa, executada em GitHub Actions [Product MCP Public Network Probe #38179596350](https://github.com/ordaxsystems/ordax-platform/actions/runs/38179596350), consultou **os endpoints publicados** e observou:
- `GET https://jhfphsjptrpmtnzkpwud.supabase.co/.well-known/oauth-authorization-server/auth/v1` → **HTTP 200**, metadados OAuth 2.1 válidos, issuer correto, registro dinâmico anunciado, PKCE S256 e cliente público.
- `GET https://ordax-control-plane-v3-canary.ordaxsystems.workers.dev/ready` → **HTTP 200**, descoberta OAuth reconhecida.
- `GET /health` e `/.well-known/oauth-protected-resource` no canary → **HTTP 200**, `read-only-canary` e `supports_remote_actions=false`; `GET /v3/product/actions` → **HTTP 404**.
- Prova versionada e repetível em `scripts/cloudflare/probe_live_product_mcp.py`, integrada pela [PR #132](https://github.com/ordaxsystems/ordax-platform/pull/132). O relatório imprime só indicadores públicos, sem tokens ou dados de usuário.

**Registro histórico, no início de 11/10/2026:** `verify_product_oauth_server.py` executado anteriormente no Windows havia recebido **HTTP 404**. A evidência HTTP externa posterior supersede aquele diagnóstico de indisponibilidade; não atribuir a mudança a uma configuração realizada por este chat, nem afirmar o instante da ativação.

**Estado operacional distinto de descoberta:** consulta canônica ao PostgreSQL após a prova mostrou **0 clientes OAuth registrados, 0 consentimentos, 0 dispositivos Product e 0 grants remotos**. A página `https://ordax.com.br/oauth/consent` também respondeu **200** e rejeitou IDs ausentes/malformados com **400** em prova HTTP externa do repositório `ordax-os` [workflow #38179767478](https://github.com/ordaxsystems/ordax-os/actions/runs/38179767478). Isso **não** executou OAuth real, não cadastrou cliente ChatGPT e não autorizou execução no PC. O canary ainda é somente leitura e o plugin antigo permanece em outro Worker.

## Próximos passos de integração — sem criar um segundo OAuth

1. **Já comprovado**: descoberta pública OAuth 2.1 válida na autoridade Supabase e no canary. Não recriar projeto/Auth para obter o mesmo endpoint.
2. **Já comprovado**: apresentação first-party `/oauth/consent` publicada no `ordax.com.br`. Ainda é necessário confirmar o fluxo de redirecionamento com um `authorization_id` real criado pelo Supabase.
3. **Pendente E2E**: o DCR está anunciado nos metadados, mas ainda não há nenhum client_id real registrado. Conectar o plugin privado canary ao ChatGPT por ação explícita do usuário para testar registro do cliente MCP com PKCE S256, login, consentimento, refresh e revogação por client_id exato.
4. Conferir pelo PostgreSQL oficial qual client_id realmente foi criado e executar os testes OAuth/E2E no **MCP personalizado** do ChatGPT com a conta real, sem reutilizar credencial do plugin antigo.
5. Só avançar para execução remota depois de parear os PCs na autoridade PostgreSQL, conceder o perfil necessário ao **cliente OAuth exato** e confirmar Full Access local no Studio. O modo local não contorna grants e vice-versa.

**Não** ativar `deployment_ready` por flag, copiar tokens para o Worker, reduzir escopos de RLS ou reutilizar cookies de sessão ChatGPT. O cutover real é tratado em #42 e a falha de Space não autorizado em #118.
