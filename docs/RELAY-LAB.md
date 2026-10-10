# OrdaX Relay — laboratório de conexões isoladas

Status: **laboratório executável, não ativado em produção**. Owner remoto: `ordaxsystems/ordax-platform`. Experiência de administração desejada: OrdaX Studio (owner `ordax-apps`); Model Router/Intelligence, autenticação/contas e grants permanecem em seus owners canônicos. Não criar outro Product MCP, Identity, Memory, Actions, catálogo de dispositivos ou entitlements.

## Objetivo

Validar topologia de **um computador central e três clientes virtuais** antes de expor portas de produção. Os clientes são instâncias lógicas com credenciais distintas; **não são VMs, PCs físicos cadastrados ou dispositivos online**. O laboratório não altera `ordax_targets`, Product Presence, Runtime ou a Loja.

```text
PC virtual 1 ----┐
PC virtual 2 ----┼----> Relay (loopback; porta dinâmica) ---> adapter injetado no teste
PC virtual 3 ----┘       |
                         └----> resposta vinculada somente ao solicitante

BLOQUEADO: PC1 <-> PC2; PC1 <-> PC3; PC2 <-> PC3
BLOQUEADO: consultar peers, escolher outro device_id, reutilizar segredo de peer
```

## Executar

Na raiz do repositório, com Node.js >= 22 e sem instalação de dependências:

```sh
node --test control-plane/labs/relay/relay.test.mjs
node --test control-plane/labs/relay/scoped-mcp.test.mts
node --test control-plane/labs/relay/relay-mcp.e2e.test.mts
```

Os testes exercitam HTTP real em `127.0.0.1`, com três credenciais aleatórias geradas somente em memória. Cobrem segregação de resultados, negação de discovery/target entre PCs, credenciais cruzadas, campos extras, replay idempotente por dispositivo, conflito de ID e falha do adapter sem vazamento de dados. O adapter devolve **respostas de teste**; não há acesso a GPT, Grok, assinatura, memória, Runtime ou inferência real.

O listener somente loopback é deliberado: não expor essa rota de teste na LAN nem utilizá-la como ingress Product. O armazenamento de credenciais/replay é efêmero **somente de laboratório**, não um novo SSOT. No ambiente real, autenticação, quotas, auditoria, replay durável e decisões de acesso devem ser feitos pelos contratos Product e Intelligence existentes.

## Fronteira de isolamento

Os testes provam segregação **no protocolo de laboratório**. Não provam isolamento de rede, kernel ou filesystem: as três identidades foram exercitadas por um único processo de testes no mesmo host. Para afirmar que três máquinas não se enxergam, executar um E2E adicional em **três VMs completas**, com discos/snapshots separados, contas/dispositivos distintos, switch privado ou VLAN e políticas ACL/firewall verificadas. A única rota permitida deverá ser **cliente -> Relay central**; não habilitar tráfego lateral, compartilhamento de arquivos, descoberta mDNS/NetBIOS/SMB ou roteamento indireto entre clientes. Testar scan e handshake negados entre todo par de VMs, além de reboot, revogação, sessão expirada, concorrência e falha do servidor. Um endpoint com sessão administrativa geral não atende ao requisito de invisibilidade.

Se a mesma conta OrdaX for aberta diretamente em todos os PCs e o catálogo da conta listar seus dispositivos, o requisito de **não descoberta** deixa de estar garantido. Clientes Relay precisam de identidade/credencial própria com escopo *somente para o hub*, nunca do token de operador/developer que lista todos os targets.

## Studio e plugin MCP

O Studio central é a **interface administradora**, mas o Relay deve permanecer um serviço autônomo quando sua janela fechar. O plugin `ordax-chatgpt` atual habilita **ChatGPT -> ações OrdaX**, não `OrdaX -> inferência da sessão Web do ChatGPT`. Sua instalação não prova uma API de inferência nem autoriza redistribuir sessões do ChatGPT aos clientes. Não usar scraping, cookies compartilhados ou automatização da interface Web para habilitar roteamento de modelo.

Para conectar inferência real: criar adapter de provider autorizado ligado ao `ordax.intelligence/1` e ao `ordax.model-router/1`; no remoto, validar entitlement `ai.external.compute`, consumo real, políticas de egress, consentimento e contexto por conta/Space. Não adicionar Provider SDK ao Studio.

## Critérios de promoção (ainda pendentes)

1. Adaptador Product autenticado para dispositivos de laboratório, com autorização exata de **spoke -> hub**, sem descoberta de peers; testes de revogação e segmentação por conta/Space.
2. Transporte de inferência pelo Intelligence/Model Router com streaming, cancelamento, recibo, isolamento e idempotência de status; sem duplicar o broker/Memory.
3. Painel Relay dentro do Studio consumindo estado real do Platform/Runtime, sem chaves e sem dispositivos fictícios no inventário.
4. Três VMs/dispositivos de teste *realmente isolados* na rede; testes negativos de tráfego lateral com logs, políticas e snapshots.
5. Provedor de IA autorizado e E2E real, com comprovação separada de source, build, deploy, conta e dispositivo. Nenhuma destas etapas foi comprovada pelo laboratório atual.

**Regra:** o resultado dos testes não autoriza automaticamente habilitar o Relay público.

## Atualização: isolamento de ferramentas e resultados

O módulo `control-plane/labs/relay/scoped-mcp.ts` encapsula os **mesmos handlers MCP publicados** e exige um escopo imutável obtido por um resolvedor confiável autenticado no servidor. No laboratório, esse resolvedor usa uma credencial efêmera distinta para cada PC virtual. Escopo: sujeito/cliente, UUID do dispositivo, Space, projeto, pasta raiz e ações de leitura permitidas. O modelo não consegue substituir o `device_id` ou escolher outra pasta/projeto: respostas fora da vinculação são negadas antes de chegar ao executor. A consulta de resultados também compara o UUID retornado pelo servidor com o escopo autenticado; solicitação `request_id` de outro PC é recusada sem conteúdo do outro cliente. Nenhum modelo recebe acesso ao token administrativo central.

O E2E de laboratório envia três solicitações HTTP em paralelo (`analise a pasta 1`), chama o manipulador MCP real com **adapter/seleção de ferramentas de teste**, recebe respostas diferentes de três executores fictícios e tenta provocar intencionalmente um erro de seleção de PC. **Esses testes não usam um ChatGPT real, não leem pastas físicas e não provam isolamento de rede entre VMs.** Seus resultados são evidência de contrato e transporte sob fixtures, não de um serviço de IA compartilhada funcionando em produção.

As respostas públicas de status Product agora devem identificar o dispositivo de origem **obtido do registro do servidor**, não de um palpite do modelo. O Studio/Runtime rejeita status de outro dispositivo, além de já exigir request ID, ação e projeto corretos. Contratos antigos sem `device_id` são tratados como indisponíveis/sem prova na observação nativa, não como sucesso.
