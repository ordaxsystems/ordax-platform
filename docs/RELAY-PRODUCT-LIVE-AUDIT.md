# Relay — Auditoria de leitura do PostgreSQL canônico

**Data da verificação:** 2026-10-10 (Bahia). **Projeto:** `ordax-platform` / ref `jhfphsjptrpmtnzkpwud`, região `sa-east-1`. **Método:** consultas de catálogo SQL somente de leitura pelo conector Supabase autorizado, sem aplicar migrations, executar RPCs de negócio, usar credenciais dos clientes, abrir sessões ou alterar registros.

## Funções reais confirmadas

As três RPCs de que depende a integração Product do Relay **existem no banco real**, todas marcadas `SECURITY DEFINER`:

| RPC | anon EXECUTE | authenticated EXECUTE | service_role EXECUTE | ordax_edge_executor EXECUTE |
| --- | --- | --- | --- | --- |
| `ordax_list_product_targets_v1` | Não | Não | Não | Sim |
| `ordax_enqueue_product_action_v1` | Não | Não | Não | Sim |
| `ordax_get_product_action_v1` | Não | Não | Não | Sim |

Assinaturas verificadas no catálogo `pg_proc`; os argumentos conferem com `product_postgres_store.ts`, incluindo `owner_user_id`, `client_kind`, `client_id` exato e a chave de idempotência no enqueue. As funções definidoras dependem de grants restritos e das verificações internas de sua implementação; essa auditoria de ACLs **não comprova, isoladamente**, ausência de vulnerabilidades de lógica de autorização no SQL.

## RLS e tabelas

Foi confirmado `relrowsecurity=true` para:

- `private.ordax_product_action_requests`
- `private.ordax_product_action_events`
- `private.ordax_product_action_audit`
- `public.ordax_product_devices`
- `public.ordax_remote_capability_grants`

As três tabelas `private` não permitem `SELECT` direto para `anon`, `authenticated` ou `service_role`. As tabelas públicas de dispositivos e grants permitem leitura a `authenticated`, **sob políticas RLS**: `ordax_product_devices_select_authorized` usa elegibilidade do usuário e `private.ordax_can_access_product_device`; `ordax_remote_capability_grants_select_admin` usa elegibilidade e autorização de proprietário ou administrador do Space. Nenhuma escrita, elevação de função ou ajuste de política foi feito nesta auditoria.

## Correspondência com o SSOT de migrations

O `control-plane/supabase/migration-registry.json` guarda **`applied_version` distinto do prefixo do nome do arquivo**. A consulta ao ledger `supabase_migrations.schema_migrations` confirmou as seguintes cinco versões aplicadas:

| Migration | applied_version confirmada |
| --- | --- |
| `20261007185000_product_grant_groups_v2` | `20261007200115` |
| `20261007203000_product_client_grant_isolation_v1` | `20261008011240` |
| `20261007204500_product_client_scoped_action_status_v1` | `20261008014205` |
| `20261007212500_product_owner_auth_eligibility_v1` | `20261008032616` |
| `20261007213000_product_owner_read_eligibility_v1` | `20261008034118` |

A consulta aos *nomes de arquivo* diretamente na coluna `version` não retorna resultados por desenho: o ledger usa `applied_version`, não o nome da migration. Não iniciar replay de migrations por esse motivo.

## Limites e gates não concluídos

1. A auditoria confirmou existência e ACLs de **RPCs reais** e versões do ledger; não executou submissão ou leitura de recibos reais em contas, não comprovou permissões Runtime por dispositivo e não validou o fluxo de inferência.
2. O candidato `product_relay_submit.ts` usa o RPC de enqueue existente, mas está **fora da rota pública**. Ele valida um único dispositivo/projeto, ações limitadas de leitura e idempotência fornecida por um transporte confiável.
3. O endpoint público MCP ainda utiliza parte do fluxo D1 legado até a migração completa da [issue #42](https://github.com/ordaxsystems/ordax-platform/issues/42). Não ativar ponte para produção por flags, troca de rota isolada ou fallback D1.
4. Para conexão definitiva do Relay, um contrato de transporte deve **gerar e persistir o idempotency_key antes do envio**, selecionar e confirmar o destino pelo Product (e não por texto do modelo), usar `ordax.intelligence/1` / `ordax.model-router/1` para inferência e receber receipts do Runtime real. O Studio é um cliente administrativo, não outra autoridade de ações.
5. O teste e2e de três clientes `product_relay_submit_receipt_e2e.test.mts` simula somente a resposta das funções de banco e execução. A auditoria live de catálogo não transforma esse teste em uma execução real.

**Decisão:** os pré-requisitos de schema/ACL para a futura migração estão presentes e legíveis; o **cutover completo ainda é uma dependência operacional**, e não foi executado nesta etapa.
