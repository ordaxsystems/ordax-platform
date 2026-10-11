# Central — associação durável de sessão no PostgreSQL canônico

**Owner:** OrdaX Product/Platform. **Migration:** `20261007213500_central_durable_conversation_binding_v1.sql`.

A `private.ordax_central_conversation_bindings` é o único registro que
associa `request_id`, sujeito do Supabase, **client_id OAuth assinado**, PC,
Space/projeto (ambos nulos para um grant device), conversa observada no Web
e hash SHA-256 do marcador `_meta["openai/session"]` do provedor.

Não armazena texto das conversas, tokens, cookies, credenciais nem o marcador
original. Não substitui `ordax_remote_capability_grants` nem é executor,
broker, fila de ações ou histórico paralelo.

## Contrato servidor

- `ordax_bind_central_conversation_v1` — grava **uma associação imutável**
  por request e recusa a reutilização da sessão ou conversa por outro pedido.
  Exige dono Auth elegível, PC ativo, grant canônico read vigente para o
  cliente exato, escopo exato e validade de no máximo **30 minutos**.
  Idempotência somente quando todos os campos e a expiração coincidirem.
- `ordax_verify_central_conversation_v1` — comparação exata de **todos**
  os campos, estado ativo, prazo, elegibilidade atual e grant atual.
  Revogação, expiração ou troca de cliente/PC são negadas imediatamente.
- `ordax_revoke_central_conversation_v1` — revogação por sujeito, cliente e
  request, sem procurar outras conversas. Não reutiliza marker.
- `createPostgresCentralSessionVerifier` — implementa o callback obrigatório
  `verifySession` que já existia em `product_central_admission.ts` usando
  a RPC do owner canônico via Hyperdrive, sem caches ou queda para D1.
  Marcador ausente, resposta SQL inválida e falha de conectividade negam.

As funções são `SECURITY DEFINER` com `search_path=''`, ACL explícita
para **somente `ordax_edge_executor`**, sem acesso direto à tabela privada.
`anon`, `authenticated`, `service_role` e
`ordax_edge_runtime` não podem registrar/verificar/revogar.
A tabela usa RLS forçada; `ordax_edge_executor` também não recebe SELECT
direto. Teste `central_conversation_binding_postflight.sql` valida as ACLs
no PostgreSQL efetivamente instalado, sem inserir dados.

## Regra obrigatória de confiança

**O marcador `openai/session` NÃO é uma assinatura de identidade ou
autorização.** O chamador de `bindProductCentralConversation` deve ser o
serviço Product confiável, **depois** de autenticar o pedido original recebido
na Central e **obter atestação independente do host** de que a conversa e
o marcador pertencem ao turno em processamento. Receber o marcador via uma
chamada do próprio modelo, por query string ou corpo MCP NÃO fornece essa
atestação. O SQL não inventa nem substitui essa prova.

A produção ainda **não** conecta um host que forneça atestação independente.
Portanto, a existência de uma função `bind` não libera seu uso a partir
de um endpoint público; o canary Product MCP permanece só leitura.
Não habilitar a ligação Central → ChatGPT → ferramenta até esse host existir.
O `confirmChat` depois da resposta observada pela WebBridge não autoriza
chamadas do plugin que aconteçam *durante* a geração daquela resposta.

## Homologação exigida

1. Publicar a migration e aprovar o postflight real; confirmar ACL zero para
   papéis cliente e nenhuma associação registrada sem consentimento.
2. Parear o Runtime real e conceder grant ao client_id OAuth efetivamente
   criado com PKCE/consentimento no ChatGPT, sem importar tokens legados.
3. Implantar **um único** caminho Product autenticado para atestar o host
   (sem marcador fornecido pelo modelo), registrar/expirar/revogar sessões e
   iniciar a conversa em um WebBridge.
4. Repetir E2E com 2/3 PCs distintos, dois clientes e conversas independentes:
   PC cruzado, Space forjado, marker trocado, revogação, falhas de rede e
   retries devem negar antes de enfileirar.

**A PR desta implementação prova a autoridade persistente e as barreiras,
não prova o passo 3.** O plugin legado e a falha P0 #118 continuam separados.
