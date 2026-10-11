# OrdaX Product MCP — auditoria da publicação e do plugin privado

**Data:** 11 de outubro de 2026. **Owner do código:** `ordaxsystems/ordax-platform`.
**Estado:** canary público **somente leitura**, sem integração real de IA pelo Relay.
**Não é a produção** e não comprova três PCs/usuários online.

## Fonte, compilação e implantação

- Código e CI: [PR #120](https://github.com/ordaxsystems/ordax-platform/pull/120), integrada em `342871b0fc96a74f0c710918d0e019f2f196794d`.
- `28/28` testes direcionados no Windows, CI `Canonical Product MCP Canary` concluída com sucesso e bundle Wrangler v4.141.0 gerado por `--dry-run` sem D1.
- Conta Cloudflare oficial `ordax-platform` (`42586bf13b61436219d21def299833e4`), workers.dev subdomínio `ordaxsystems`, Worker de teste `ordax-control-plane-v3-canary`.
- Publicação real via Cloudflare API multipart `PUT /accounts/{account_id}/workers/scripts/{script_name}`, concluída com HTTP 200 em 2026-10-11 06:02:01 UTC. Deployment `df6cc303-4102-4d2f-a314-63b8141ba8d7`, versão `eb1a9603-78a2-40a4-b537-380c925c5a88`. workers.dev habilitado, URLs de preview desabilitadas.
- API Cloudflare confirmou os quatro bindings: `POSTGRES` (Hyperdrive `4b601ec5815f43259bd8040053825d2a`) e três variáveis públicas OAuth; **nenhum binding D1**, segredo de operador ou Supabase Service Role.
- Browser Chrome real no `DESKTOP-COHT67R` verificou inicialmente `GET /health`, com `mode=read-only-canary` e `supports_remote_actions=false`. Naquele teste **anterior**, o Python local recebeu HTTP 403 com Error 1010 (cliente bloqueado por segurança Cloudflare).
- **Evidência HTTP externa posterior (11/10/2026 22:14 UTC):** o runner GitHub Actions, independentemente do Windows local, recebeu **200** do `/health`, **200** do `/ready`, **200** dos metadados OAuth protegidos e **404** de `GET /v3/product/actions`. O Supabase oficial retornou descoberta OAuth 2.1 **200**. Fonte auditável: [Product MCP Public Network Probe, run #38179596350](https://github.com/ordaxsystems/ordax-platform/actions/runs/38179596350), script SSOT `scripts/cloudflare/probe_live_product_mcp.py` (PR #132). Portanto, acesso HTTPS por **esse runner** foi homologado; não extrapolar para todos os clientes, nem dizer que OAuth consent/execução remota está pronto.
- Domínio personalizado `mcp-canary.ordax.com.br` foi anexado para teste à zona oficial, sem conflito com registros anteriores, mas não respondeu por HTTPS em testes reais. Foi **revertido** via API; a lista de Worker Domains retornou vazia e o registro DNS não existe mais. O plugin não foi alterado para esse domínio.

## Novo plugin privado do ChatGPT

- Plugin pessoal criado pela ferramenta oficial: **OrdaX Product — Validação**, identidade `ordax-product-canary`, versão `0.1.0`.
- URL: https://chatgpt.com/plugins/plugins_6acb270cf6d081918f8c341bbde7c07e
- Release inicial: `pluginrel_6acb270e2ec88191b9f92ea3d9d5f8d7`.
- Inspeção posterior dos arquivos persistidos confirmou que `mcp.json` e `.mcp.json` apontam para `https://ordax-control-plane-v3-canary.ordaxsystems.workers.dev/mcp`.
- O plugin oferece **somente leitura OAuth** (`ordax_session`, `ordax_profile`, `ordax_targets`, `ordax_action_status`). Não pede permissão para controlar o PC, ler arquivos ou enviar prompts a uma conta pessoal de ChatGPT.
- Sua criação foi confirmada, porém **instalação/conexão OAuth e uso autenticado a partir do ChatGPT não foram comprovados**. Instalar ou conectar depende de ação explícita do usuário; não presumir que possuir um link equivale a estar autenticado.

## SSOT do plugin e processo correto de atualização

- Metadados versionados: `integrations/chatgpt/product-canary/manifest.json`.
- Destino canônico computado a partir de `control-plane/cloudflare/production-foundation.json` + `control-plane/cloudflare/wrangler.product-mcp-canary.toml`.
- Gerador `scripts/cloudflare/package_product_plugin.py` produz um único ZIP válido, com `plugin.json`, `.codex-plugin/plugin.json`, `.mcp.json` e `mcp.json`. O teste `test_product_plugin_ssot.py` verifica URL única, escopo de leitura e builds determinísticos.
- Workflow `Canonical Product Plugin Package` oferece artefato privado, **sem publicar silenciosamente**, com prazo de retenção controlado. Para uma nova versão: alterar o SSOT, validar CI, conferir endpoint vivo, recuperar `current_release_id` do plugin e então efetuar atualização guardada da **mesma identidade** via Plugin Creator. Nunca recriar cópias de produção para pequenas mudanças.

## Barreiras reais restantes

1. A publicação do Worker de produção `ordax-control-plane-v3` continua bloqueada pelo D1 remanescente nas rotas do Control Plane; não forçar `deployment_ready` nem liberar o D1 legado.
2. O PostgreSQL canônico no Supabase `jhfphsjptrpmtnzkpwud` estava ativo, mas `public.ordax_product_devices` e `public.ordax_remote_capability_grants` tinham **zero registros**. O computador operacional visto no plugin anterior pertence a outra origem e não foi migrado.
3. A [issue #118](https://github.com/ordaxsystems/ordax-platform/issues/118) registra um `space_id` UUID arbitrário bem-formado aceito pelo plugin antigo; o canary **não expõe criação de ações**, então não serve como prova de que o bug do plugin anterior foi corrigido.
4. A nova conexão OAuth do ChatGPT, pareamento real de dispositivos, revogação, confiança do `oauth_client_id`, sessões independentes, inferência via Intelligence/Model Router e testes em três PCs distintos ainda requerem E2E com contas e aparelhos conectados. Resultados sintéticos ou apenas um Chrome vendo `/health` não substituem isso.

**Decisão:** manter o plugin de produção antigo intacto até cutover canônico comprovado e manter o canary restrito à verificação privada. Todas as atualizações seguintes devem partir do SSOT, sem edição manual de URLs em manifests diferentes.

## Pré-requisitos após o OAuth discovery funcionar

A fase de **descoberta do issuer** está comprovada por tráfego real, porém o banco canônico ainda tinha 0 `auth.oauth_clients`, 0 `auth.oauth_consents`, 0 `ordax_product_devices` e 0 `ordax_remote_capability_grants` na consulta posterior. O próximo experimento autenticamente multi-PC não é adicionar outra API/identidade: a conexão do **plugin privado existente** `OrdaX Product — Validação` precisa ser instalada e autorizada pelo usuário para provar DCR, PKCE e consentimento no ChatGPT. Só depois se registra/paira cada Runtime no PostgreSQL por canal autorizado e libera grants por cliente. Até lá, **não promover** esse canary a executor, e não redirecionar o plugin de produção antigo silenciosamente.

A página pública first-party de consentimento foi validada via HTTP 200 e rejeição 400 de `authorization_id` inválido, sem emitir tokens ou autorizar clientes ([OrdaX OS workflow #38179767478](https://github.com/ordaxsystems/ordax-os/actions/runs/38179767478)). A conexão OAuth end-to-end ainda precisa de um ID verdadeiro do provedor.
