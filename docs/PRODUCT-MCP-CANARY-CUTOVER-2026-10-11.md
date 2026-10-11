# Product MCP canônico — validação sem D1

**Estado:** candidato read-only para a migração da issue #42. **Não foi publicado em produção**. Não é substituto para o Relay funcional, não representa instalação de dispositivo nem serviço GPT.

## Entrypoint e autoridade

- Entrada de teste: `control-plane/cloudflare/src/product_mcp_entry.ts`.
- O código chama o mesmo `handleOrdaxMcp` do Control Plane e usa os manipuladores `createCanonicalProductMcpReadHandlers`. Não copia o catálogo de ferramentas, protocolo MCP ou parser OAuth.
- Credenciais OAuth são verificadas em `product_auth.ts`, com assinatura JWKS do issuer Supabase oficial e o exato `client_id` assinado.
- Consultas de catálogo e recibos passam pelos RPCs canônicos do PostgreSQL via Hyperdrive, com owner e OAuth client específicos, não por cabeçalhos ou IDs de destino selecionados pelo modelo.
- O `wrangler.product-mcp-canary.toml` só vincula `POSTGRES`, sem `DB`, D1, Runtime legado, segredo compartilhado de operador, ou qualquer autorização paralela.
- Apenas `ordax_session`, `ordax_profile`, `ordax_targets` e `ordax_action_status` são anunciados. Comandos de PC e arquivos, criação de ações e terminais não podem ser chamados através desse endpoint; `POST /v3/product/actions` e demais rotas legadas são 404.
- `/health` identifica **explicitamente** `read-only-canary` e `supports_remote_actions=false`. A resposta não significa que o usuário autenticou, que um PC está online ou que GPT inferiu.

## Reproduzir

Node 24+ e, na raiz do repo:

```sh
npm install --prefix control-plane/cloudflare --ignore-scripts --no-audit --no-fund --package-lock=false
node --test control-plane/tests/product_mcp_entry.test.mts control-plane/tests/product_mcp_discovery.test.mts control-plane/tests/product_mcp_failure_responses.test.mts
cd control-plane/cloudflare
npx --yes wrangler@4.141.0 deploy --dry-run --config wrangler.product-mcp-canary.toml --outdir .canary-bundle
```

O workflow `Canonical Product MCP Canary` valida a entrada, OAuth e o bundle sem publicar nada. Não executar `wrangler deploy` real desse canary antes de confirmar autoridade de publicação, permissões, restrições de exposição e smoke externo.

## Migração correta do plugin

A conta Cloudflare oficial é `ordax-platform`, com subdomínio `ordaxsystems.workers.dev`, Hyperdrive `ordax-control-plane-postgres` e PostgreSQL Supabase `jhfphsjptrpmtnzkpwud`. O plugin pessoal antigo do usuário `ordax-studio` v0.1.4 contém o host **de outra origem** `ordax-control-plane-v3.ordax-ac1ca1b50d09.workers.dev`. Esta referência legada precisa ser retirada **somente depois** que o Worker canônico oficial tiver entrado em produção e passar o E2E de OAuth, dispositivo, Space, ações e revogação.

Não mudar `.mcp.json` para uma URL indisponível nem duplicar o plugin publicado; preferir atualizar o plugin pessoal existente com o release guardado após teste da implantação oficial. Registrar no repo uma definição canônica da URL, versão, superfície MCP e smoke de autenticação para que futuros releases do plugin a usem sem adivinhar destino.

## Pendências que o canary não resolve

1. O Worker de produção ainda depende de rotas D1 e não cumpre `check_deploy_readiness.py`; mover **todo** o transporte restante para as APIs/RPCs oficiais antes do cutover.
2. A autoridade PostgreSQL Product não possui dispositivos, grants e sessões remotas; cadastrar dispositivos legítimos no fluxo de pareamento e consentimento oficial, com revogação e recibos.
3. A inferência Relay deve consumir o `ordax.intelligence/1` e o `ordax.model-router/1` existentes com quota, identidade, roteamento e recibo durável, não reutilizar sessão Web pessoal do ChatGPT.
4. Testar três contas autenticadas em três PCs/VMs distintos, com o Studio Central efetivamente online, sem descoberta entre pares. As suítes de laboratório isolam clientes lógicos, mas não satisfazem essa homologação.
5. A issue #118 registra uma ação concluída via plugin legado com Space UUID não autorizado. O canary recusa ações; **isso não confirma** que o plugin ativo corrigiu a vulnerabilidade. A correção precisa ser testada diretamente no deployment canônico promovido.

**Regra:** não forçar `deployment_ready=true`, não remover o gate, não publicar D1 legado, não transferir tokens entre contas e não tratar sucesso de `/health` como homologação de IA real.
