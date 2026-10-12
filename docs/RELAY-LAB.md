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

## Contrato de isolamento atualizado

Toda resposta do adapter de inferência deve ter exatamente `{deviceId, requestId, result}`. O serviço compara ambas as identidades com as obtidas na autenticação da solicitação antes de entregar ou reutilizar qualquer resposta. Resultados incompatíveis falham fechados. A revogação de um cliente apaga sua credencial e os seus resultados retidos no cache de teste; uma resposta atrasada não recebe autorização só porque o trabalho começou antes da revogação.

O wrapper `scopeRelayMcp` recebe **três dependências obrigatórias**: handlers MCP existentes, resolvedor autenticado de escopo imutável e `verifyReceipt(request, requestId, scope)`. Esta terceira dependência deve consultar a autoridade **canônica de resultados por sujeito e cliente exatos**; sem atestado positivo, nenhum status é liberado. A verificação acontece no servidor e os IDs privados do usuário e do cliente não são adicionados ao resultado público do plugin. O laboratório usa uma tabela de resultados de teste com sujeito/cliente vinculados; em produção, a integração exige o RPC Product exato, o transporte e os gates próprios do owner.

Não é suficiente comparar apenas `device_id`: dois clientes podem compartilhar permissões para um computador, mas ainda devem ter históricos e resultados isolados. A conta do PC central não autoriza que os clientes secundários consultem ações uns dos outros. O produto não deve encaminhar tokens do operador para o cliente. O teste deste documento não é prova de que as VMs ou o GPT comercial estejam conectados.

## Evolução do protocolo de laboratório — cancelamento e observabilidade

O loopback possui duas operações de cliente (ambas autenticadas por segredo próprio do dispositivo):

- `POST /v1/infer` recebe exatamente `{request_id,prompt}`. O serviço vincula o dispositivo à credencial no transporte; o adapter **deve** devolver `{deviceId,requestId,result}` com ambos os identificadores iguais aos originais. Não aceita troca sugerida pelo modelo.
- `POST /v1/cancel` recebe exatamente `{request_id}`. Só pode cancelar uma solicitação em andamento pertencente à **mesma credencial**. Não divulga se IDs de outros clientes existem, nem permite consultar dispositivos ou históricos de terceiros.

Há prazo máximo configurável para inferência no laboratório (padrão 20 s, intervalo 25 ms–60 s), propagação do `AbortSignal` ao adapter, um trabalho ativo por cliente e até 32 clientes por processo. Cancelamentos, timeouts e falhas registram um resultado terminal para o ID; o mesmo ID **não é reenviado** ao adapter, inclusive quando o cliente tenta novamente após a conexão cair. Recibos são mantidos em memória com capacidade fixa (padrão 128, máximo 128) e não são expulsos automaticamente: o laboratório recusa novas operações ao atingir o limite. A revogação apaga recibos de seu dispositivo e interrompe solicitações pendentes. Essas regras ajudam os testes, mas **não substituem idempotência e cancelamento duráveis** na autoridade Product/Intelligence em produção.

A interface administrativa de laboratório é `GET /v1/admin/status`, disponível **somente** quando `startRelayLab` recebe um `adminToken` distinto de todos os tokens de clientes. O listener permanece exclusivamente em `127.0.0.1`. A resposta não lista IDs, nomes, arquivos, texto dos prompts nem resultados: publica o esquema `ordax.relay-lab-status/1` e contagens de clientes cadastrados, trabalhos ativos, recibos, falhas, cancelamentos e timeouts. Ausência de token de operador impede a existência da rota. O Studio central pode ler essa observação por seu host local (`ordax-apps/docs/RELAY-ADMIN-LAB.md`), mantendo o token somente no processo servidor.

**Limites que não podem ser confundidos com prontidão:** `AbortSignal` pode sinalizar interrupção, mas um provedor que o ignore ainda pode produzir trabalho externo; por isso a autoridade de execução deve exigir recibo e idempotência próprios. Credenciais e recibos em memória não substituem persistência e revogação Product, e contagem de clientes configurados não comprova PCs conectados, isolamento por firewall ou IA compartilhada em produção.

A suíte inclui isolamento entre três clientes, carga com 16 clientes / 80 solicitações, rejeição de acesso cruzado, pressão por cliente, falhas sem replay, revogação, timeout e status central autenticado. Para auditoria, executar `node --test control-plane/labs/relay/*.test.mjs` **e** `node --test control-plane/labs/relay/*.test.mts` em Node com suporte a TypeScript nativo ou usar o CI oficial, que executa as suítes explicitamente.

## Laboratório de isolamento de rede com contêineres

O workflow `.github/workflows/relay-container-isolation.yml` executa um cenário complementar no GitHub Actions, com **um hub e três clientes Node.js em contêineres distintos**. Cada cliente está em uma rede Docker interna exclusiva (`pair1`, `pair2`, `pair3`). O hub pertence às três redes, mas elas não compartilham clientes. **Nenhuma porta é publicada no host**; o Relay continua vinculado a loopback dentro do contêiner central e uma ponte TCP somente de laboratório encaminha conexões das redes privadas.

O teste exige simultaneamente: (a) acesso ao sentinel TCP da **própria** rede, para provar que a sondagem de rede funciona; (b) incapacidade de conectar ao sentinel TCP de qualquer **outra** rede, por IP conhecido; (c) ausência de descoberta DNS dos sentinels dos demais clientes; (d) cada cliente realiza `POST /v1/infer` com sua própria credencial e recebe somente seu identificador, request ID e conteúdo de teste; (e) o endpoint de inventário de peers permanece indisponível. As credenciais são geradas no job, não gravadas no repositório. Cada sentinel mantém uma porta TCP ativa para que a falha lateral não possa ser falsamente atribuída a um destino desligado.

O job deve ser interpretado como **prova de isolamento de rede entre os contêineres desse cenário**, não isolamento de kernel entre VMs, nem acesso físico a computadores, execução por GPT real ou prontidão de um serviço comercial. Contêineres compartilham o kernel do runner e o hub continua sendo uma máquina privilegiada, multirrede. O adaptador de inferência dentro deste laboratório produz uma resposta explícita de teste; o fluxo MCP real com três processos locais é comprovado separadamente por `spoke-process.e2e.test.mts`.

Para reprodução manual em um host Docker de teste, definir os três segredos efêmeros `RELAY_TEST_SPOKE1_TOKEN`, `RELAY_TEST_SPOKE2_TOKEN`, `RELAY_TEST_SPOKE3_TOKEN` com valores diferentes de pelo menos 32 caracteres, iniciar os serviços `hub` e `sentinel1` a `sentinel3`, executar cada serviço `spokeN` e encerrar com `docker compose down --volumes --remove-orphans`. Não executar essa topologia em uma rede de produção nem publicar suas portas. Para auditoria da execução automática, consultar o workflow no GitHub Actions.

O teste de processos (`control-plane/labs/relay/spoke-process.e2e.test.mts`) usa três processos separados e pastas de teste distintas, exercitando o manipulador MCP publicado e verificando bloqueios de troca de dispositivo/projeto, mas **não cria VMs ou separação de rede**. Ambos os testes são necessários; nenhum pode substituir o outro.

## Prova complementar em Windows

O workflow `.github/workflows/relay-windows-process.yml` executa `spoke-process.e2e.test.mts` em `windows-latest` com Node.js 22, separadamente da suíte Linux. Três processos Node independentes recebem credenciais e diretórios de teste próprios, enviam pedidos HTTP ao Relay, passam pelo manipulador MCP existente e retornam resultados com identidade vinculada ao cliente. O teste também verifica um pedido com destino deliberadamente trocado e tentativa de consultar o recibo de outra identidade.

O teste Windows prova comportamento do protocolo e da leitura de pastas na plataforma de execução; não é VM, não testa firewall local entre PCs físicos e não significa que a sessão real ChatGPT do Studio seja um endpoint de inferência. O teste Docker usa redes próprias e complementa, mas não substitui, o resultado Windows. Ambos são acionáveis por `workflow_dispatch` sem credenciais de produção.

## Dependência de migração Product

O cutover da autoridade canônica PostgreSQL no Control Plane permanece acompanhado pela issue [#42](https://github.com/ordaxsystems/ordax-platform/issues/42). Não conectar clientes Relay reais aos handlers D1 antigos, nem criar gateway/memória paralelos para contornar o cutover. A integração definitiva precisa consultar o dono canônico de identidade/grants, obter o destino imutável do cliente autenticado e registrar a ação/recibo com owner, client e device, egress consentido e idempotência durável antes de disponibilizar o serviço de inferência. A existência do MCP ChatGPT conectado **não** é prova de canal de inferência reverso.

## Ponte de autorização canônica (somente leitura)

Foi adicionado um candidato de integração com **OAuth Product assinado + RPCs PostgreSQL existentes**, sem criar outra autoridade ou expor um endpoint remoto. A implementação e os testes estão em `control-plane/cloudflare/src/product_relay_receipt.ts`, `control-plane/labs/relay/canonical-readonly.ts` e `control-plane/tests/product_relay_*.test.mts`. O contrato, seus limites e o bloqueio até o cutover #42 estão detalhados em [RELAY-CANONICAL-AUTH.md](RELAY-CANONICAL-AUTH.md). Esse caminho recusa qualquer gravação pelo executor legado e valida usuário, cliente OAuth, dispositivo e UUID do projeto antes de apresentar um recibo. Não confundir essa leitura autorizada com inferência, pareamento ou execução de ações reais pelo Relay.


## SSOT de homologação dos três PCs emulados — 11/10/2026

**A arquitetura de teste já inclui três PCs emulados**. Para não confundir os níveis de prova:

- A **Platform** mantém o único Relay experimental em `control-plane/labs/relay/relay.mjs`, reutilizado pelo Apps sem outro broker ou executor.
- O ensaio de **três contêineres** `control-plane/labs/relay/network/compose.yml` oferece três identidades com segredos próprios e **três redes Docker `internal` separadas**, com sentinelas inacessíveis aos peers. São três clientes de rede emulados, **não** três PCs físicos ou instalações completas do OrdaX OS.
- A CI `ORDAX Relay Container Isolation` passa a executar também **em PRs**. Cada cliente tenta falsificar as identidades dos **outros dois**, totalizando seis combinações negadas; os três utilizam **o mesmo UUID de solicitação** simultaneamente e cada resposta continua segregada por cliente. A repetição do próprio pedido deve ser idempotente, e reutilizar o UUID com outro prompt deve retornar conflito, nunca sobrescrever o recibo.
- O Apps tem outro ensaio complementar de **três processos Windows independentes** com portas HTTP e cookies distintos, sobre **um host físico**; não declarar isolamento de kernel nesse caso.

Critério de evidência: logs de cada execução e SHA do GitHub devem demonstrar os três processos/contêineres, origem/credencial e isolamento. Aprovação dos ensaios **não** fornece uma sessão autenticada de ChatGPT, nem cadastro Product real: o Worker definitivo `ordax-mcp` permanece bloqueado até a homologação exigida no SSOT da Platform.
