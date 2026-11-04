# Instruções para agentes — ordax-platform

Este repositório conserva a autoridade dos seus próprios contratos, código e responsáveis. Não copiar componentes nem criar SSOT paralelo.

## Handoff de Produto MCP para próximos chats — 04/11/2026

**Não retomar missão DEV já concluída:**
[`Platform #291`](https://github.com/ordaxsystems/ordax-platform/issues/291)
foi encerrada com MCP ChatGPT → Windows físico e recibos reais;
cinco devices/credenciais antigos foram revogados e os dois
devices atuais preservados. A [PR #336](https://github.com/ordaxsystems/ordax-platform/pull/336)
integrou a operação Owner canônica; não executar outra limpeza,
migração, matrícula, grant ou teste exaustivo sem regressão atual.
O Worker público e rota Owner ainda têm **gates independentes**
e não devem ser ativados por inferência desse sucesso DEV.

A integração Aura/Fabric com a Store `CURRENT` instalada pertence
ao OS (fonte/vínculo Native) e ao Runtime (cliente Product), **não**
ao PostgreSQL/Worker. Handoff vigente:
[`ordax-os/INTELLIGENCE-HANDOFF.md`](https://github.com/ordaxsystems/ordax-os/blob/main/INTELLIGENCE-HANDOFF.md).
Este repo continua dono somente de OAuth, Device/Owner,
grants/leases, autorização, dispatch e recibos remotos;
`ordax-surface` é owner da UI e `ordax-apps` dos providers.
`OS #2405` permanece release-gated e **não** é pré-requisito
para refazer MCP DEV. Sob pedido de “continue”, verificar `main`,
issue/PR atual e atuar só na lacuna daquele owner.

## Execução DEV — Evolução Rápida

Aplicar a [política transversal canônica do OrdaX](https://github.com/ordaxsystems/ordax-os/blob/main/docs/DEVELOPMENT-WORKFLOW.md#regra-operacional-transversal--evolucao-rapida-dev-2026-11-04): identificar o owner/arquivo afetado, executar diretamente a correção/implementação, integrar e só depois validar proporcionalmente ao impacto. Evitar pesquisas, testes, builds, novos workflows, documentação e PRs paralelas sem necessidade comprovada. `continue` significa avançar a entrega corrente, não reiniciar auditorias.

Gates de segurança, trust, permissões, proteção da `main`, integridade, operações destrutivas e promoção de release continuam obrigatórios quando aplicáveis. Respeitar os documentos e contratos locais; este arquivo é um encaminhamento da política de execução, não uma segunda autoridade técnica.
