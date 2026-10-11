# Product MCP — isolamento de Space P0: evidência real e prova da fonte canônica

**Data:** 11/10/2026. **Issue:** [#118](https://github.com/ordaxsystems/ordax-platform/issues/118).

## Diagnóstico reproduzido com o MCP real

Um pedido **somente leitura** `computer.screen_info` com `space_id` UUID explícito e
sem grant correspondente retornou `status=succeeded` no plugin legado instalado.
Um pedido idêntico **sem Space** também retornou `succeeded`, como esperado.
Os dois recibos foram consultados posteriormente e confirmaram execução, não
apenas criação de trabalho. O catálogo do mesmo cliente OAuth informava apenas
concessões globais `space_id=null`. O experimento não escreveu arquivos nem
inspecionou informações pessoais.

O endpoint do plugin operacional é
`ordax-control-plane-v3.ordax-ac1ca1b50d09.workers.dev/mcp`.
Ele **não pertence** à conta Cloudflare canônica atualmente conectada
`ordax-platform`. A conta oficial `ordaxsystems.workers.dev` possui somente
o Worker `ordax-control-plane-v3-canary`, de **leitura**, não o Control Plane
com executor. Não confundir o código publicado no primeiro com o código da
`main` atual.

## Fonte canônica verificada

O código fonte `control-plane/cloudflare/src/index.ts` resolve grants exigindo
o mesmo `subject_id`, `device_id` e
`((space_id IS NULL AND requested IS NULL) OR space_id = requested)`,
além de revogação e validade. O `mcp_http.ts` preserva um Space explícito
ao criar a solicitação interna. A prova `tests/test_product_grant_sql_runtime.py`
**extrai a consulta SQL da função real** e a executa em SQLite em memória:
grant global apenas para pedido sem Space; UUID explícito alheio recusado; grant
do Space exato aceito; grants revogados/expirados/de outros sujeitos ou PCs
não podem reviver um grant global. A suite de `mcp_http.ts` também verifica
o encaminhamento literal de Space ao handler.

Esses testes executam consulta e código do repositório; **não** são evidência
de atualização do Worker antigo, nem substituem prova de autorização Postgres
na conta canônica ao vivo.

## Estado da autoridade oficial

Consulta direta à instância PostgreSQL canônica
`jhfphsjptrpmtnzkpwud` em 11/10/2026:
`public.ordax_product_devices = 0` e
`public.ordax_remote_capability_grants = 0`.
Logo, nenhum PC nem grant da antiga implantação foi vinculado corretamente
à nova autoridade. Não duplicar/copiar token de dispositivo, forçar grants,
usar cliente OAuth do prompt nem reabrir D1. O OAuth Server Supabase ainda
depende de configuração oficial de consentimento e registro de cliente.

## Gate de corte

1. Publicar o **owner canônico** somente depois de passar
   `scripts/cloudflare/check_deploy_readiness.py`, sem D1 e com OAuth correto.
2. Parear Runtime(s) com `ordax_product_devices` usando o fluxo autenticado,
   associar Space, cliente OAuth e grants canônicos — sem reaproveitar segredos
   legados.
3. Executar via ChatGPT MCP **real**, nessa **nova implantação**:
   sem `space_id` + grant global → permitido; `space_id` arbitrário →
   recusado **antes de enfileirar**; Space exato concedido → permitido;
   cliente/dispositivo cruzado → recusado; revogação → recusado, inclusive
   leitura de status/recibo.
4. Somente então habilitar `Central → ChatGPT → plugin → PC`. Cada chamada
   requer associação confiável da sessão da conversa ao owner/client/PC.
   Um modelo que escrever o UUID correto não cria autorização.

**Situação:** produção antiga falha na prova negativa; produção canônica ainda
não foi ativada. Não descrever o P0 como corrigido em ambiente vivo.
