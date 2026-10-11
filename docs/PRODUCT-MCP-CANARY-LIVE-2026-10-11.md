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
- Browser Chrome real no `DESKTOP-COHT67R` verificou `GET /health` em workers.dev, com `mode=read-only-canary` e `supports_remote_actions=false`. A ferramenta Python `urllib` recebeu HTTP 403 com Error 1010 (assinatura do cliente bloqueada pelo Cloudflare); por isso **não foi homologado acesso de todos os clientes de API**.
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
