# Central session — Owner target inspection (migrações governadas; recursos OFF)

O problema de [#291](https://github.com/ordaxsystems/ordax-platform/issues/291) possui dois clientes OAuth independentes e um grant de ação no Notebook offline, enquanto o Desktop só tem discovery para o cliente conectado. Conceder mais um grant de ação sem uma seleção atestada criaria `central_device_target_ambiguous`.

## Primeira fronteira candidata (somente leitura)

O endpoint `GET /v3/owner/central-session-targets?client_id=<UUID>` permanece **OFF** salvo `CENTRAL_OWNER_TARGET_PREFLIGHT_ENABLED=enabled`, e a migração `control-plane/supabase/migrations/20261028145500_owner_central_session_targets_v1.sql` exige implantação governada e feature flag explícito. Exige JWT Owner verificado e client OAuth consentido ainda ativo; o identificador de Owner nunca vem do pedido. Retorna exclusivamente os dispositivos elegíveis pelo mesmo `private.ordax_central_device_grant_eligible_v1` usado na sessão real, com presença/Runtime readiness como metadados de disponibilidade. Não considera estar online como permissão nem escolhe automaticamente qualquer dispositivo.

O estado `owner_selection_required` é informativo: `attested=false`, `dispatch_authorized=false`, `owner_choice_performed=false`. Essa entrega **não seleciona, concede, revoga, confirma, enfileira nem executa**; não habilitar somente por estar na source. O erro de 26/10 exige implementação distinta de seleção explícita, curta e transacional do Owner para challenge vinculado a cliente+sessão, confirmação pelo dispositivo credenciado e posterior E2E. Sem ela, o sistema **deve seguir falhando fechado**.

## Provas exigidas antes de ativação

Owner sem JWT, cliente OAuth diferente, duplicidade de parâmetros, target sem grant, device offline, grant expirado/revogado, conjunto incompleto e concorrência têm de falhar fechados. Quando houver a fase de escolha, nenhum `device_id` vindo dos argumentos do ChatGPT poderá definir autoridade, e os grants do Notebook devem permanecer independentes. Governança de migration, CI e E2E são requisitos separados.


## Segunda fronteira candidata — Owner decide o dispositivo da sessão (27/10/2026)

**Código consolidado na PR #293; migração preparada em `control-plane/supabase/migrations/20261028145600_central_owner_device_selection_v1.sql`.** Mesmo depois de aplicar a migração, a seleção continua proibida enquanto `CENTRAL_OWNER_SELECTION_ENABLED` estiver OFF; nenhum grant novo ou alteração de credencial decorre da migração.

A estrutura canônica `private.ordax_central_device_session_challenges` passa a
aceitar `state=awaiting_owner` com `device_id=NULL`. A unicidade por
`owner_user_id,client_id,session_sha256` engloba `awaiting_owner` e `pending`.
Quando a função de grants vigente identifica mais de um alvo para o OAuth
client assinado, o mesmo `ordax_open_central_device_session_v1` cria um
ticket limitado a **5 minutos**; **não** escolhe o único online, não concede
acesso e não dá ao modelo poder de escolha. Uma sessão já atestada e vigente
permanece ligada ao seu dispositivo original.

O endpoint **separadamente gated**
`GET /v3/owner/central-session-selections?client_id=<UUID>` lista somente
tickets aguardando escolha por um Owner autenticado e cliente OAuth consentido.
A resposta omite o hash do marcador privado da sessão. O
`POST /v3/owner/central-session-selections` recebe **exatamente**
`{client_id,challenge_id,device_id}`, sem campos extras ou parâmetros de
query. O Worker injeta a identidade Owner a partir de JWT assinado; no POST/GET
de seleção exige ainda **sessão Owner**: JWT direto da conta ou JWT OAuth PKCE
assinado para o cliente de primeira parte autorizado em
`PRODUCT_OWNER_OAUTH_CLIENT_ID` (configuração pública canônica no Worker).
Clientes OAuth delegados ao ChatGPT não autorizam esta rota; um
`client_id` inexistente ou divergente falha fechado;
a função `ordax_owner_select_central_device_v1` trava a mesma linha com
`FOR UPDATE`, revalida consentimento, grant de ação pelo helper SSOT, presença
fresca e digest do Runtime, e torna o ticket `pending` por **2 minutos**.
Seleções simultâneas não podem sobrescrever o alvo vencedor.

Quando houver **dois ou mais tickets de sessões distintas** aguardando
escolha para o mesmo Owner+cliente OAuth, o seletor recusa com
`owner_central_selection_ambiguous`: sem prova visível da conversa,
escolher só por UUID não pode bindar a sessão errada. A abertura dos desafios
e a escolha compartilham um lock transacional por Owner+cliente para que duas
aberturas concorrentes não escapem da checagem. Um ticket expirado não conta
para essa ambiguidade. Esse bloqueio não substitui uma UI de identificação
segura da sessão, necessária antes do rollout.

A seleção **não equivale** a atestação nem despacho. O Runtime mantém a
rota Device original de polling/confirm e só pode confirmar com credencial do
dispositivo selecionado. Confirmação revalida grant atual; resolução da
sessão também o revalida. Grants A/B não são emprestados ou revogados.
O MCP `resolveOrBootstrapAttestedSession` retorna
`central_session_owner_selection_required` prontamente, sem ocupar 24 s
de polling enquanto uma pessoa precisa decidir.

**`CENTRAL_OWNER_SELECTION_ENABLED` permanece OFF** independentemente do
flag read-only `CENTRAL_OWNER_TARGET_PREFLIGHT_ENABLED`. Nenhuma feature é
habilitada pelo mero merge de source; a migração exige implantação governada e validação de status antes da liberação.
Antes da promoção, exigir revisão de migração contra a definição SQL ativa,
E2E Owner e Runtime nativo com o cliente exato, tickets expirados/múltiplas
sessões, confirmação e receipt de uma ação exclusivamente de leitura,
verificação do UX para o Owner identificar a sessão correta, e critérios
claros de retirada/revogação.

**Provas na PR:** `control-plane/tests/central_owner_device_selection_sql.test.mts`
executa no PGlite a abertura canônica, alteração da tabela original,
OAuth Owner, 2 dispositivos, um ticket sem device, Owner seleciona,
Device errado não confirma, Device exato confirma, grant revogado falha,
corridas de escolha e tickets expirados. O teste
`owner_central_device_selection_route.test.mts` cobre JWT, schema estrito
e flags. A CI é fonte de verdade para o head específico; não tratar docs
ou CI como deploy no Supabase.
