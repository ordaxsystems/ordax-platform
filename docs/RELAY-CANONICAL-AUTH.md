# Relay — integração canônica de autorização e leitura (candidato)

**Estado:** código e testes integrados à `main`, **não exposto em produção**, sem dispositivo de cliente cadastrado automaticamente e sem inferência por ChatGPT Web.

## Autoridades reutilizadas

- `control-plane/cloudflare/src/product_auth.ts` verifica assinatura e validade do **OAuth Product MCP**. O usuário e o `client_id` vêm de claims autenticadas, jamais de cabeçalhos inventados pelo cliente, prompt ou resposta do modelo.
- `control-plane/cloudflare/src/product_postgres_store.ts` fornece `ordax_list_product_targets_v1` e `ordax_get_product_action_v1`. Os dois RPCs PostgreSQL recebem **owner + client exatos**. Não há novas tabelas, bancos ou sistema paralelo de grants.
- `control-plane/cloudflare/src/product_relay_receipt.ts` verifica se o recibo do RPC pertence ao **mesmo usuário, cliente OAuth, dispositivo, projeto UUID e capacidade** do escopo previamente autorizado, sem devolver o conteúdo do recibo nem detalhes de falha ao verificador.
- `control-plane/labs/relay/canonical-readonly.ts` compõe os manipuladores MCP existentes com esses RPCs, em modo estritamente **leitura**: sessão, um único target autorizado e consulta do status de uma ação preexistente. Operações novas são negadas; **não há fallback para D1**.

## Escolha imutável do PC

O candidato só aceita um **único dispositivo** retornado pela autoridade Product para o cliente OAuth, e um **único grant de projeto** com UUID de projeto e Space canônicos e capacidade de leitura. Vários dispositivos, vários grants elegíveis, identidade inválida, projeto sem UUID ou ausência de capacidade causam negação. Não se escolhe o primeiro da lista, não há resolução por nome e não se permite ao modelo fornecer um novo destino.

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

O contrato aceito por `createCanonicalRelayActionSubmitHandler` é um POST JSON estritamente tipado com **somente** `device_id`, `space_id`, `project_id`, `action`, `arguments` e `idempotency_key`. O cliente precisa apresentar OAuth assinado; o servidor autentica o sujeito e o cliente, obtém os targets/grants da autoridade Product e rejeita qualquer escolha de PC/projeto/Space diferente da **única** vinculação autorizada. As ações atualmente aceitas são somente leitura de projeto (`project.text_read`, `workspace.text_read`, `workspace.directory_list`, `workspace.file_stat`), com caminhos relativos validados e parâmetros limitados. A autoridade definitiva da pasta e a proteção contra symlinks/junctions permanecem no Runtime que efetivamente lê o filesystem.

A chave de idempotência é obrigatória, estável para a **mesma instrução** e não pode ser substituída ao repetir uma solicitação cujo resultado seja incerto. O futuro transporte tipado deverá gerar e persistir esse identificador antes de qualquer tentativa e reutilizá-lo em reconexões/retries; o texto do modelo nunca deve gerar chaves para forçar nova execução. Essa chave é enviada, sem tradução, ao RPC existente, que compara escopo, cliente e hash do conteúdo e registra o `effect_id` numa autoridade durável. O gateway cria uma expiração curta (cinco minutos) para novas ações e não permite `expires_at` escolhido pelo modelo. O resultado da submissão não afirma que a leitura já foi realizada: somente devolve o recibo canônico com `request_id`, `effect_id`, status, `replayed`, dispositivo e projeto. A consulta do efeito continua no Product status canônico. Conflitos retornam 409; falhas de comunicação retornam indisponibilidade sem criar outro request ID.

O teste `control-plane/tests/product_relay_submit.test.mts` cobre OAuth, três clientes, troca de destino, ambiguidades/revogação, paths adversariais, replay sem duplicação, conflito de payload e falha da autoridade. O teste `control-plane/tests/product_relay_submit_receipt_e2e.test.mts` percorre **submissão pela autoridade PostgreSQL simulada → manipulador MCP existente → recibo** para três clientes assinados, confirma isolamento cruzado, consulta após revogação e replay do identificador original. Nenhum teste é prova de aplicação real de comandos, banco live, modelo real ou múltiplos dispositivos cadastrados.

**Bloqueio arquitetural restante:** o MCP público atual constrói o body legado sem `idempotency_key` ou UUID do projeto, então **não pode** ser conectado por um remapeamento oportunista de slug, um request ID fictício ou token do Studio. Até que um transporte versionado com identidade persistida e o cutover PostgreSQL da issue #42 estejam prontos, o adaptador fica desvinculado do Worker público. Não criar feature flag para habilitar por fora da migração nem fallback D1.
