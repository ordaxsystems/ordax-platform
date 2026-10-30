# OrdaX Control Plane — limites de arquitetura e migração

**Estado:** contrato de desenvolvimento. Autoridade persistente atual: PostgreSQL.
Este documento descreve dependências reais; não certifica portabilidade automática
de procedimentos, esquemas ou dados para outro banco.

## 1. Responsabilidades que não devem se misturar

| Camada | Responsabilidade | Proibido |
| --- | --- | --- |
| Worker HTTP e MCP | autenticação, parsing, roteamento, resposta | SQL e instanciar drivers |
| Serviços Produto | fluxos de dispositivo, Space, jobs e políticas | criar banco paralelo ou ignorar identidade |
| Persistência Produto | chamadas RPC autorizadas e mapeamento de resultados | receber permissões do cliente sem verificar autoridade |
| Adaptador de banco | sessão, conexão, query e encerramento | lógica de negócio, autorizações, HTTP |
| Dados binários | bytes em object storage e metadados persistentes canônicos | metadados divergentes ou fallback silencioso |

### Fonte de verdade

- Conta, dispositivos, permissões, jobs e recibos persistentes: PostgreSQL.
- Hyperdrive: transporte de conexão; não é outro banco.
- Workers: processamento e API; não armazenam autoridade durável do Produto.
- Nenhum D1, Durable Object de negócio ou dupla gravação.
- Recurso Cloudflare **existente** não implica binding ativo no Worker.

## 2. Limite concreto introduzido

`src/data_postgres_driver.ts` é o único módulo autorizado a importar o
cliente `pg`. Publica o contrato `DatabaseSession` (`connect`, `query`, `end`).

Os stores chamam `openPostgresSession`; nenhuma rota precisa conhecer o driver.
O contexto de autorização e as chamadas RPC PostgreSQL continuam nos stores:
ainda são específicas do banco **por contrato**. Isso é intencional e
auditável — alterar o driver não migra automaticamente esses RPCs.

## 3. Migração futura para outro sistema

1. Inventariar operações de domínio, RPCs, privilégios, constraints e índices.
2. Definir um novo adaptador e um contrato equivalente por operação.
3. Reproduzir atomicidade, idempotência, ownership e revogação de credenciais.
4. Importar dados com checagem de contagem, checksums e vínculos de identidade.
5. Executar testes de contrato, concorrência, falha, recuperação e auditoria.
6. Trocar a autoridade explicitamente numa única versão, **sem dual-write**.
7. Remover a implementação antiga após provar que não há consumidores ativos.

**Nunca:** inferir sucesso por HTTP 2xx isolado, abrir fallback para conta velha,
expor segredo, copiar esquema 1:1 sem avaliar semântica ou retirar gates de CI.

## 4. Regras verificáveis

O teste `control-plane/tests/database_driver_boundary.test.mts` impede novas
importações diretas de `pg` nos módulos TS da raiz do Worker, uso do driver
pela rota e reintrodução de D1 naquele ponto. Esse teste não substitui
análise de alterações futuras em subpastas nem testes de migração de dados.

## 5. Estado conhecido e lacunas

- Worker principal foi reduzido a rotas canônicas, sem D1 ativo.
- PostgreSQL é a única autoridade persistente implementada para Produto.
- Artefatos legados e execução D1 antiga foram aposentados; essas APIs não
  passam a funcionar no PostgreSQL apenas pela remoção de D1.
- O agente nativo possui ciclo PostgreSQL integrado, mas a ativação em
  dispositivos e sua prova com credenciais reais permanecem separadas.
- A publicação do Worker canônico de produção precisa comprovar conta,
  identidade, credenciais e gates antes de qualquer alteração ao vivo.
