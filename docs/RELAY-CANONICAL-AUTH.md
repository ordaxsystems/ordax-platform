# Relay — integração canônica de autorização e leitura (candidato)

**Estado:** código e testes integrados à `main`, **não exposto em produção**, sem dispositivo de cliente cadastrado automaticamente e sem inferência por ChatGPT Web.

## Autoridades reutilizadas

- `control-plane/cloudflare/src/product_auth.ts` verifica assinatura e validade do **OAuth Product MCP**. O usuário e o `client_id` vêm de claims autenticadas, jamais de cabeçalhos inventados pelo cliente, prompt ou resposta do modelo.
- `control-plane/cloudflare/src/product_postgres_store.ts` fornece `ordax_list_product_targets_v1` e `ordax_get_product_action_v1`. Os dois RPCs PostgreSQL recebem **owner + client exatos**. Não há novas tabelas, bancos ou sistema paralelo de grants.
- `control-plane/cloudflare/src/product_relay_receipt.ts` verifica se o recibo do RPC pertence ao **mesmo usuário, cliente OAuth, dispositivo, projeto UUID e capacidade** do escopo previamente autorizado, sem devolver o conteúdo do recibo nem detalhes de falha ao verificador.
- `control-plane/labs/relay/canonical-readonly.ts` compõe os manipuladores MCP existentes com esses RPCs, em modo estritamente **leitura**: sessão, um único target autorizado e consulta do status de uma ação preexistente. Operações novas são negadas; **não há fallback para D1**.

## Escolha imutável do PC

O caminho de **leitura sem vínculo explícito de operação** só aceita um único dispositivo retornado pela autoridade Product e um único grant de projeto para impedir escolhas ambíguas. Já o caminho de **submissão com `TrustedRelayOperation` persistida** suporta vários computadores autorizados na mesma conta: seleciona exatamente o UUID do dispositivo previamente associado à operação pelo host e revalida sua permissão Product. Se não houver correspondência, se houver dispositivos duplicados na projeção, projeto ambíguo ou grant vencido, a chamada é recusada. A IA nunca escolhe um dispositivo pela ordem da lista, por nome de PC ou por campos em seu payload.

Esse limite é deliberado. Para múltiplos dispositivos legítimos, o Produto deve prover um **pareamento explícito e persistido em sua autoridade canônica**, com seleção feita pelo proprietário e não pelo LLM. Não contornar a ambiguidade criando outra tabela ou cache de dispositivos no Studio.

O resultado só é revelado após uma segunda confirmação pelo RPC, vinculada ao sujeito e ao exato cliente OAuth. Dois clientes autorizados a acessar **o mesmo PC** ainda têm recibos independentes. Revalidar o catálogo no acesso impede que um grant revogado continue permitindo novas consultas, sem precisar distribuir tokens do usuário ou administrador entre clientes.

## Contratos e compatibilidade

O escopo de leitura no laboratório usa `projectId` **UUID** e exige o `project_id` correspondente no resultado canônico. Escopos com `projectId` não podem chamar `createAction` pelo executor legado. A forma com `project` slug fica limitada aos testes legados já existentes, não é uma tradução implícita para o PostgreSQL.

A rota pública do plugin ainda usa o ciclo D1 até concluir a migração da [issue #42](https://github.com/ordaxsystems/ordax-platform/issues/42). **Estes módulos não alteram o endpoint público** e não permitem executar comandos remotos; o serviço Relay de inferência ainda precisa consumir `ordax.intelligence/1` e `ordax.model-router/1` quando a autoridade de egress e execução estiver comprovada.

## Provas

Executar os testes com Node.js 22+:

```sh
node --test control-plane/tests/product_relay_receipt.test.mts
node --test control-plane/tests/product_relay_canonical_mcp.test.mts
```

Eles verificam token OAuth assinado, usuário e cliente distintos, três clientes concorrentes, uso do mesmo PC por clientes diferentes, revogação de grants, ações e projetos indevidos, impossibilidade de escrever pelo candidato read-only, resultado de cliente incorreto, múltiplos targets e indisponibilidade da autoridade. O CI oficial executa ambos pela suíte `control-plane/tests/*.test.mts`.

**Limitação da prova:** os testes usam o manipulador MCP real e o validador de OAuth assinado, mas simulam as respostas das consultas RPC; não executam uma consulta live no banco, não criam VMs ou contas de usuário reais e não fornecem inferência externa. O Product PostgreSQL e suas políticas continuam como responsáveis pelas decisões reais.

## Envio candidato pela fila PostgreSQL (sem D1 e sem nova fila)

O adaptador `control-plane/cloudflare/src/product_relay_submit.ts` introduz a outra metade do percurso Product, ainda **sem endpoint público**. Ele consome `authenticateProductMcpClientRequest`, `ordax_list_product_targets_v1` e `ordax_enqueue_product_action_v1`. O resolvedor puro `product_relay_scope.ts` é **compartilhado** pelo candidato MCP de leitura e pelo candidato de submissão, mantendo SSOT de escolha do dispositivo/projeto.

`createCanonicalRelayActionSubmitHandler` agora exige **duas entradas separadas**: o POST JSON do modelo contém **somente** `action` e `arguments`; o segundo parâmetro, `TrustedRelayOperation`, é fornecido exclusivamente pelo host de execução autorizado e contém `subjectId`, `clientId`, `deviceId`, `spaceId`, `projectId` e `operationId` persistido. A ausência desse vínculo provoca recusa HTTP 403. O usuário precisa apresentar OAuth assinado; o servidor confirma sujeito e cliente exatos, consulta grants Product e rejeita qualquer destino diferente do vínculo autenticado. Mesmo com grant válido, o modelo não pode enviar campos de dispositivo/projeto/Space/operação/idempotência no corpo JSON (HTTP 400). As ações permanecem somente leitura de projeto (`project.text_read`, `workspace.text_read`, `workspace.directory_list`, `workspace.file_stat`), com caminhos relativos e parâmetros limitados. A resolução final da pasta e a proteção contra symlinks/junctions continuam no Runtime que efetivamente lê o filesystem.

O host autorizado deve **gerar e persistir** um `operationId` UUID uma única vez, antes do primeiro envio, associado ao usuário, cliente e destino. O handler deriva internamente a chave `relay-<operationId>` e a encaminha ao RPC PostgreSQL existente, que compara escopo, cliente e hash do conteúdo, registrando o `effect_id` durável. Em reconexões e falhas incertas, reutiliza-se exatamente o mesmo vínculo; nunca se autoriza criar outro UUID pelo modelo. O Studio já persiste um `operation.id` antes de despachar pelo Runtime legado, mas esse identificador local **não é autorização de servidor**: a integração final precisa validar o registro Product e converter o slug de projeto em UUID apenas pela autoridade canônica, nunca por suposição. O gateway cria expiração de cinco minutos para novos envios. A confirmação devolve `request_id`, `effect_id`, status, `replayed`, dispositivo e projeto — ela **não significa que o Runtime terminou a ação**. Conflitos retornam 409; falhas de transporte resultam em indisponibilidade sem criar outra chave.

O teste `control-plane/tests/product_relay_submit.test.mts` cobre OAuth, três clientes, troca de destino, ambiguidades/revogação, paths adversariais, replay sem duplicação, conflito de payload e falha da autoridade. O teste `control-plane/tests/product_relay_submit_receipt_e2e.test.mts` percorre **submissão pela autoridade PostgreSQL simulada → manipulador MCP existente → recibo** para três clientes assinados, confirma isolamento cruzado, consulta após revogação e replay do identificador original. Nenhum teste é prova de aplicação real de comandos, banco live, modelo real ou múltiplos dispositivos cadastrados.

**Bloqueio arquitetural restante:** o MCP público ainda usa um body legado sem operação persistida, cliente OAuth canônico de execução ou projeto UUID. O segundo parâmetro de `createCanonicalRelayActionSubmitHandler` não pode ser gerado a partir desse body nem de headers arbitrários. Até que o transporte confiável consiga fornecer o vínculo de operação do owner Product e o cutover PostgreSQL da issue #42 esteja concluído, o adaptador continua fora da rota pública. Não usar flag, fallback D1 ou tradução oportunista de slug para contornar isso.

## Auditoria de permissões do PostgreSQL real

A infraestrutura Product foi conferida em modo **somente leitura**, com catálogo SQL do projeto canônico: os três RPCs necessários existem, seus `EXECUTE` estão concedidos ao `ordax_edge_executor` e negados aos papéis públicos, e o ledger aplicado corresponde às versões `applied_version` do registro oficial. As tabelas de fila/audit permanecem sob RLS e sem `SELECT` direto aos papéis públicos. Evidências, políticas consultadas e limites dessa conferência: [RELAY-PRODUCT-LIVE-AUDIT.md](RELAY-PRODUCT-LIVE-AUDIT.md). **Isso não conclui o cutover da issue #42 nem ativa o Relay remoto.**

## Observação de compatibilidade do plugin público

Uma verificação real, somente leitura, usando o plugin MCP atualmente conectado (`mcp_tool_surface_revision=2026-10-07.1`, 87 ferramentas) enviou `projects.list` ao único computador autorizado, e o recibo terminou com `status=succeeded`. Porém, a projeção **pública desse recibo não incluiu `device_id`**, mesmo sendo um campo já contemplado no código canônico de resultados. Sem esse vínculo, **não há prova verificável do PC de execução** na resposta da rota pública atualmente conectada. Não interpretar essa operação como validação E2E de roteamento multi-PC.

O candidato Relay recusa resultados sem `device_id` e o teste de regressão em `scoped-mcp.test.mts` exige recusa explícita. A migração #42 e o rollout coordenado deverão assegurar que o novo caminho MCP devolva `device_id` e `project_id` validados pela autoridade Product PostgreSQL. A ausência de um deles não pode ser suprida pelo GPT, pela interface ou por uma suposição de "PC selecionado". O plugin atual permanece funcional para os casos existentes, mas **não é transportador multiusuário pronto**.

## Decisão de produto — controle amplo por conta e dispositivo

O Relay experimental de leitura **não** define o conjunto máximo de capacidades do produto final. O acesso de usuário ao próprio computador deve reutilizar o **Computer Control do Runtime**, o catálogo de ações tipadas e os grants Product já existentes. O proprietário autentica sua Conta OrdaX e vincula o dispositivo; a autorização local de Full Access pode ser mantida até revogação, sem necessidade de uma nova confirmação para cada tarefa comum.

A separação obrigatória é **usuário autenticado + cliente OAuth exato + dispositivo previamente autorizado**, validada em cada dispatch e recibo. Uma mensagem do LLM, um `device_id` inventado ou um resultado do provider não podem trocar o proprietário ou o destino. No modo Full Access, não transformar o Relay em uma política própria de raízes de projeto ou lista de aplicativos: esse alcance pertence à política local do Runtime e às permissões do sistema operacional. As proteções internas de integridade do Runtime e o fluxo de auditoria continuam independentes.

O provedor de IA segue suas próprias regras de conteúdo, mas isso **não substitui as fronteiras de identidade, destino e autorização do OrdaX**. Alertas do modelo não são prova de que um dado foi encaminhado apenas ao usuário correto. Artefatos e respostas multimodais devem carregar o vínculo canônico da operação/usuário/cliente/dispositivo e ser apresentados exclusivamente ao solicitante original; o transporte central não deve publicar inventário de peers.

O candidato `product_relay_submit.ts` continua limitado a leitura **por ainda não estar ligado ao transporte completo**, não como regra permanente para MCP, ChatGPT, Grok ou outras IAs. Não contornar a ausência de integração declarando operações não comprovadas como disponíveis.


## Central — escopo MCP por cliente OAuth (incremento de 11/10/2026)

O owner canônico do filtro MCP Product é agora `control-plane/cloudflare/src/product_mcp_scoped.ts` e a composição `control-plane/cloudflare/src/product_central_mcp.ts`. Os módulos homônimos em `control-plane/labs/relay` são **somente reexports**, preservando os testes e importadores antigos; não existe segundo filtro ou segunda autoridade.

`createCanonicalCentralMcpGateway()` combina o gateway existente de **quatro ferramentas de leitura**, as RPCs PostgreSQL canônicas, o OAuth de assinatura validada e o resolvedor de destino. Não está instalado no Worker público ou no Studio Central. A composição recusa, antes de consultar status ou expor inventário, um `client_id` sem exatamente **um** dispositivo/projeto autorizado; um token que conceda dois PCs continua proibido mesmo quando o prompt informa um UUID. Resultados de status só saem após atestação independente de cliente, dispositivo, projeto e capacidade. O cliente OAuth suporta sua forma pública canônica completa (incluindo `.`, `:`, `-` e até 160 caracteres); não restringir incorretamente a uma regex de laboratório.

**Limite decisivo:** este vínculo é `(sujeito OAuth, client_id OAuth) → PC`, **não** `(conversa no ChatGPT) → PC`. A interface Projetos do ChatGPT, o texto do prompt e o `chat_id` visto pelo Studio não fornecem atestação de autorização ao servidor MCP. Se duas conversas usarem a MESMA instalação/conexão OAuth do plugin, o backend não distingue uma da outra. Portanto, para um único operador compartilhar a Central entre PCs, ainda é necessário um mecanismo suportado de conexão/credencial isolada e identificável por conversa ou um transporte próprio autorizado que ateste a sessão ao chamador. Sem isso, **não ativar** encaminhamento automático e não conceder vários dispositivos ao mesmo cliente OAuth esperando que o GPT escolha corretamente.

Essa restrição preserva o Studio WebBridge existente e os grants PostgreSQL, sem segunda fila, D1, ação remota ou segredo em prompt. A nova suíte `product_central_mcp.test.mts` verifica três clientes assinados, separação de alvos, cabeçalhos falsos, tentativa de seleção pelo modelo, múltiplos grants, revogação, recibo corrompido e ausência de credencial. A CI também executa os testes de laboratório pelas reexportações antigas para detectar drift. Suíte/CI verde não comprova OAuth real do ChatGPT, três PCs físicos ou comandos Runtime reais.


## Admissão por conversa da Central — contrato interno bloqueado por autoridade (11/10/2026)

A nova implementação `control-plane/cloudflare/src/product_central_admission.ts` verifica, a **cada** operação, três provas independentes: (1) token Product OAuth assinado, sujeito e cliente exato; (2) um único dispositivo/projeto elegível para esse cliente via RPC PostgreSQL canônica; (3) correspondência exata de `conversationId`, `requestId`, dispositivo, projeto, Space, cliente e sujeito com um **registro durável previamente autorizado**, comprovado por `verifySession`. O registro e a função de consulta devem existir na autoridade canônica de sessão/consentimento; não podem ser substituídos por atributos DOM, JSON de ferramenta, texto do prompt, cabeçalho ou `@ORDAX`. O módulo **recusa inicialização** sem esse verificador. Não cria banco, cookie, OAuth próprio ou tabela concorrente.

`createCanonicalCentralSessionMcpGateway` conecta a admissão ao **mesmo** protocolo Product MCP read-only já existente, executando-a em cada leitura, inclusive consulta de inventário e recibos, antes de chamar os manipuladores. Nem este gateway nem `verifySession` estão expostos/implantados no Worker público. O laboratório e o canary publicado continuam sem capacidade de controlar computadores. A ausência atual de uma autoridade real de `conversationId → OAuth client → PC` significa que **o encaminhamento de ChatGPT Web da Central permanece desativado**.

**Não confundir**: a assinatura OAuth atesta a conexão/cliente; o identificador observado pelo navegador identifica a conversa, mas **não** prova sua titularidade. A ponte Studio ainda precisa conectar uma atestação de sessão suportada pelo provedor, ou isolar clientes OAuth por conexão, com a associação persistida e validada no owner Product. Sem essa prova, nem um ChatGPT Project nem uma mensagem estruturada autorizam ferramentas. `verifySession` é um *contrato obrigatório*, não uma implementação fictícia da autoridade ausente.

Regressões em `product_central_admission.test.mts`: OAuth assinado, isolamento de dois clientes/conversas, troca de ID do chat/operação, parâmetros forjados, grants múltiplos, revogação, ausência de registro e revalidação de cada chamada MCP. Os testes injetam consulta simulada de registros, **não** afirmam autenticação de chats ChatGPT reais ou E2E em três computadores físicos.


## Marcador de sessão MCP do ChatGPT — correlação, não autoridade (11/10/2026)

A [documentação oficial de plugins](https://developers.openai.com/plugins/reference) documenta que o ChatGPT envia `params._meta["openai/session"]` nas chamadas MCP `tools/call`. O [changelog de 15/01/2026](https://developers.openai.com/plugins/changelog) descreve o valor como identificador **anonimizado** da sessão do ChatGPT, próprio para correlacionar chamadas de uma conversa. Não é necessariamente igual ao identificador da URL `/c/...` observado pelo Studio WebBridge. **Não inventar equivalência entre eles.**

A composição ainda inativa `createCanonicalCentralSessionMcpGateway` agora exige, antes de qualquer RPC Product no `tools/call`, que o marcador vindo de `params._meta` corresponda ao `sessionId` da **associação de sessão confiável fornecida pelo owner**. Um marcador diferente, ausente ou colocado dentro de `arguments` é recusado; `initialize`/`tools/list` não exigem esse metadado porque são etapas de descoberta. A admissão continua verificando OAuth assinado, cliente exato, um único PC/projeto Product e `verifySession` durável. A verificação é feita em **toda chamada**, não só na primeira.

**Limites de segurança:** `_meta["openai/session"]` é informação enviada pelo cliente MCP e, portanto, **pode ser forjada por um cliente malicioso**. Não é assinatura, token, segredo, permissão ou prova de titularidade do ChatGPT. Sem OAuth e registro confiável não concede acesso; mesmo com a comparação de igualdade, continua obrigatório um mecanismo que estabeleça a associação inicial `sessionId → solicitação Central → dispositivo` por um canal autenticado e com proteção contra replay. O ChatGPT pode fornecer um correlator, mas não fornece automaticamente ao Studio a autorização para agir em outro computador. A composição continua **não montada em produção**.

Testes: `product_central_admission.test.mts` usa mensagens MCP reais em formato JSON-RPC, OAuth assinado, grants canônicos injetados, sessões A/B, metadados faltantes/trocados e tentativa de mover o marcador para parâmetros do modelo. **Esses testes não são uma captura ao vivo do _meta emitido pelo ChatGPT**. A prova real em conversa ChatGPT → plugin → Runtime no Windows foi executada separadamente.


## Central: PC sem Space/projeto não é autorização de projeto (11/10/2026)

A fonte real do Product, `public.ordax_list_product_targets_v1`, expõe
`grant_groups[].space_id` e `grant_groups[].project_id`, **mas não**
`scope_kind`. No PostgreSQL, a constraint do grant define explicitamente
`scope_kind=device` com `project_id=NULL`; para o fluxo de Central somente
leitura, exigir **os dois campos NULL** é a distinção inequívoca, sem criar
outro campo ou mecanismo paralelo. Um Space fornecido pelo modelo jamais
converte essa concessão em project grant.

A função `selectCanonicalRelayDeviceScope` extrai do catálogo por owner +
OAuth client exato apenas capacidades inofensivas e explicitamente concedidas
(`computer.access_status`, `computer.active_window`,
`computer.processes`, `computer.screen_info`, `computer.windows`) em modo
**read**. Não enfileira tarefas, não amplia Full Access, não concede leitura
de arquivo nem transforma a permissão em `createAction`.
`selectCanonicalRelayProjectScope` continua independente e aceita somente
grants com Space e projeto UUID explícitos.

O gateway de leitura sem associação de conversa exige **um único PC e um
único tipo de autoridade**; quando um OAuth client possui grants de ambos os
tipos, recusa a ambiguidade. Já a admissão **de uma conversa confiavelmente
persistida no Product** aceita o PC exato da associação, inclusive quando
o mesmo client OAuth tem vários PCs, mas consulta
`verifySession` **antes** de usar o `deviceId` para selecionar um alvo no
catálogo. Sem esse owner durável, nem o UUID no prompt, nem a URL Web, nem o
marcador MCP OpenAI são prova de autorização.

Para grants device-scoped, `spaceId` e `projectId` devem ser NULL juntos;
pares misturados NULL/UUID falham. Os recibos precisam confirmar o mesmo
`device_id`, `project_id=NULL`, ação autorizada, sujeito, OAuth client e
identificador da solicitação. A entrada legada de escrita continua negada
quando o grant é do computador. Testes em
`product_central_device_scope.test.mts` exercem o payload real do RPC,
múltiplos alvos, revogação, mistura de escopos, tentativas de escrita e
marcador de sessão.

**Escopo:** fonte + testes, NÃO implantação. O Worker canary permanece
somente leitura e não existe associação de conversas persistida em produção.


## MCP: isolamento real de leitura após atestação da sessão

O Product OAuth pode ter **vários PCs autorizados no mesmo client_id**.
O seletor genérico do plugin sem contexto continua negando a ambiguidade
corretamente; porém a Central com `verifySession` já possui a associação
imutável entre pedido e PC. Essa associação deve ser a fonte da seleção
do destino **também nas consultas subsequentes**, não só na admissão inicial.

`createCanonicalCentralSessionMcpGateway` reaproveita
`createCanonicalCentralAdmissionVerifier` para gerar o
resolver de `scopeRelayMcp` em cada chamada. Após a assinatura OAuth,
o client_id exato, o registro durável da conversa e os grants atuais do
PostgreSQL passarem, esse resolver limita `ordax_targets` a **um PC**
e permite consultar somente os recibos cujo `device_id`, `project_id`,
capability, request_id, sujeito e client correspondam à mesma admissão.
Nunca retorna inventário de um PC vizinho e nunca consulta um recibo
através de outros clientes. A revogação invalida o próximo acesso.
`_meta["openai/session"]` é conferido na requisição JSON-RPC original
antes de chamadas internas, como correlação, sem substituir OAuth.

O `createAction` permanece recusado. O plugin canary público continua
sem essa composição até existir um owner Product que persista e prove
`verifySession` de verdade. Os testes de 2 PCs e dois tipos de scope
usam JWTs criptograficamente assinados **em laboratório**; não representam
um ChatGPT real, não foram implantados no Worker e não criaram grants.
