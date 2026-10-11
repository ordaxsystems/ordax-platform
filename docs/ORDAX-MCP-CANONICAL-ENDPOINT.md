# OrdaX MCP — endereço e identidade definitivos

## Um único serviço MCP oficial

**Identidade externa planejada:** `OrdaX`.
**Domínio canônico:** `https://mcp.ordax.com.br/mcp`.
**Worker:** `ordax-mcp`.
**Owner de código:** `ordaxsystems/ordax-platform`.
**Ponto de entrada:** `src/product_mcp_entry.ts`.
**Transporte:** HTTP streamable com OAuth 2.1.
**Autoridade:** Supabase Auth + PostgreSQL via Hyperdrive `POSTGRES`.

As referências de domínio/nome/estado constam **uma única vez** em
`production-foundation.json#mcp_release`; `wrangler.mcp.toml` é validado
contra esse SSOT. Não criar ou renomear outro OAuth, banco, executor, broker,
fila, Runtime ou infraestrutura de dispositivos para expor o MCP.

O nome `control-plane-v3` pertence a um Worker com D1 no código histórico
de produção, e não será usado como nome ou destino de deploy do MCP.
O Worker de validação `ordax-control-plane-v3-canary` permanece apenas como
ponto experimental *read-only* existente; NÃO é alias nem proxy do novo
endereço. Os testes compilam o **bundle próprio do Worker `ordax-mcp`**,
sem importar `src/index.ts` ou `env.DB` em nenhum caminho de execução.

## Decisão de segurança

O endereço `mcp.ordax.com.br` **ainda não está ativo**. Não anunciar
ao ChatGPT antes que um Worker com o bundle aprovado seja implantado,
o domínio TLS seja verificado, a sessão OAuth e o client_id real estejam
consentidos e o PC/Runtime tenha vínculo Product canônico.

`scripts/cloudflare/check_mcp_release.py` é o gate fail-closed da
identidade e release pública do MCP. A política exige comprovantes
independentes de:

1. Domínio customizado, DNS e TLS aprovados por HTTPS real;
2. OAuth do cliente ChatGPT e consentimento first-party concluídos;
3. Dispositivo Product real pareado, com grants do client_id correto;
4. Host Central que atesta de modo independente a sessão e o PC;
5. E2E multi-dispositivo com isolamento, revogação e falhas;
6. Serviço legado desativado, sem possibilidade de fallback.

O gate atual registra os seis bloqueios e **recusa** tentativa de liberar
a produção sem as evidências. A workflow
`OrdaX MCP Canonical Candidate` valida a configuração, executa testes
de OAuth e compila o bundle definitivo sem possuir acesso a tokens de
deploy e sem executar nenhuma mutação Cloudflare.

**Nunca** disponibilizar tools de ação remota pelo nome `OrdaX`
enquanto o host confiável e os grants não estiverem comprovados.
O código atual da entrada é conscientemente somente leitura; os
resultados de CI NÃO equivalem a E2E real ChatGPT → PC.

## Remoção do legado

A configuração velha `wrangler.toml` do **Control Plane genérico** não
foi silenciosamente substituída, pois ainda possui D1 e o mapa de
dependências `d1-cutover-authority-map.json` aponta migrações ausentes
(pareamento/links, jobs de engenharia e artifact lifecycle).
Apagá-lo por renomeação seria perder os testes de regressão e deixar
dados/efeitos sem owner. Sua implantação já está `deployment_ready=false`.

A retirada final deste código ocorrerá **depois** de selecionar para
cada contrato legado uma implementação canônica ou aposentadoria
explícita, com as suites e recibos correspondentes. Não usar D1 no novo
MCP, não duplicar uma queue e não redirecionar o plugin privado
anterior para um serviço não homologado.

Estado em 11/10/2026: **bundle candidato configurado, domínio não
publicado, E2E remoto não comprovado**.
