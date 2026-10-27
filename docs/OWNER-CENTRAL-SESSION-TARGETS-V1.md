# Central session — Owner target inspection (proposta não implantada)

O problema de [#291](https://github.com/ordaxsystems/ordax-platform/issues/291) possui dois clientes OAuth independentes e um grant de ação no Notebook offline, enquanto o Desktop só tem discovery para o cliente conectado. Conceder mais um grant de ação sem uma seleção atestada criaria `central_device_target_ambiguous`.

## Primeira fronteira candidata (somente leitura)

O endpoint `GET /v3/owner/central-session-targets?client_id=<UUID>` permanece **OFF** salvo `CENTRAL_OWNER_TARGET_PREFLIGHT_ENABLED=enabled`, e a proposta SQL em `control-plane/supabase/proposals/owner_central_session_targets_v1.sql` **não está em migrations nem aplicada**. Exige JWT Owner verificado e client OAuth consentido ainda ativo; o identificador de Owner nunca vem do pedido. Retorna exclusivamente os dispositivos elegíveis pelo mesmo `private.ordax_central_device_grant_eligible_v1` usado na sessão real, com presença/Runtime readiness como metadados de disponibilidade. Não considera estar online como permissão nem escolhe automaticamente qualquer dispositivo.

O estado `owner_selection_required` é informativo: `attested=false`, `dispatch_authorized=false`, `owner_choice_performed=false`. Essa entrega **não seleciona, concede, revoga, confirma, enfileira nem executa**; não habilitar somente por estar na source. O erro de 26/10 exige implementação distinta de seleção explícita, curta e transacional do Owner para challenge vinculado a cliente+sessão, confirmação pelo dispositivo credenciado e posterior E2E. Sem ela, o sistema **deve seguir falhando fechado**.

## Provas exigidas antes de ativação

Owner sem JWT, cliente OAuth diferente, duplicidade de parâmetros, target sem grant, device offline, grant expirado/revogado, conjunto incompleto e concorrência têm de falhar fechados. Quando houver a fase de escolha, nenhum `device_id` vindo dos argumentos do ChatGPT poderá definir autoridade, e os grants do Notebook devem permanecer independentes. Governança de migration, CI e E2E são requisitos separados.
