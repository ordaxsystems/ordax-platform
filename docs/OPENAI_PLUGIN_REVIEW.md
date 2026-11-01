# ORDAX Studio — ChatGPT connector review runbook

Status: pre-submission checklist for the **ORDAX Studio** ChatGPT connector. Its display name and release version are owned by `plugins/ordax-chatgpt/plugin.json`.

This runbook covers only the stable `ordax-chatgpt` connector identity. Its shared
Studio display name does not imply app installation, Runtime ownership or OS
Intelligence access. The connector package remains independently versioned.

## Scope

This runbook covers only the public-review path for the ChatGPT MCP integration. It does not change the ORDAX account model, Cloudflare Control Plane, local Runtime authority, ORDAX Studio app boundary or Git provider credentials.

Canonical flow:

```text
ChatGPT
  -> ORDAX Studio (ChatGPT connector)
  -> OAuth + Cloudflare remote MCP
  -> device/scope/action grant enforcement
  -> ORDAX Runtime on the connected PC
  -> local computer-access policy
  -> explicitly granted typed action
```

GitHub remains an optional project provider. It is not the identity provider, it is not the device-enrollment authority, and it is not the bridge between ChatGPT and ORDAX. New devices are enrolled by an authenticated ORDAX Product account.

## Preconditions

Before recording or submitting:

- `main` Bridge CI is green;
- the ChatGPT connector package workflow is green;
- Cloudflare production deploy is green;
- `/.well-known/oauth-protected-resource` advertises the required OAuth scopes;
- Supabase OAuth 2.1 Server is enabled for the ORDAX project;
- OAuth discovery and PKCE `S256` are available;
- dynamic client registration is enabled when required by the ChatGPT MCP flow;
- unauthenticated `/mcp` returns 401 with protected-resource metadata challenge;
- ORDAX Runtime is online on the review computer;
- only the isolated `ordax-review-demo` project is granted to the review account;
- the review account has no MFA/SMS/secondary email step that blocks a reviewer;
- `terminal.exec` is NOT granted to the review account;
- no personal or production project data appears in the review grant.

## Canonical submission path

Use the OpenAI submission flow **With MCP** and submit the production HTTPS endpoint directly:

`https://mcp.ordax.com.br/mcp`

The public ZIP remains the canonical portable connector package. Registered-app mappings are for local/workspace packaging; the public MCP-backed submission uses the production endpoint in the dashboard.

## Canonical submission package

Do not build the review ZIP manually.

Use `.github/workflows/plugin-review-package.yml` on the verified `main` revision and download the artifact:

`ordax-chatgpt-plugin-review-package`

The artifact contains only:

- `ordax-chatgpt-plugin-<version>.zip`, where `<version>` is read from `plugins/ordax-chatgpt/plugin.json`;
- its matching `.sha256` file.

The ZIP contains one `ordax-chatgpt/` directory with exactly `plugin.json`, `mcp.json` and `assets/ordax.svg`. Legacy `ordax-dev-plugin-*` or `ordax-studio-plugin-*` package names are rejected by the canonical packaging flow.

Verify the published SHA-256 before uploading the ZIP to the OpenAI submission UI.

## Review account

Create a dedicated ORDAX review account in the configured identity provider.

Do not store its password in Git, connector manifests, CI logs, issues or documentation.

The account should:

- have a confirmed email;
- be usable with ordinary email/password login;
- have access only to the review device/project grants;
- remain valid for the review period;
- be revoked or rotated after review if no longer needed.

Record the username/password only in private reviewer credential fields supplied by the OpenAI submission UI.

## Grants de revisão — somente Owner canônico

O workflow antigo de concessão por link de dispositivo foi aposentado. Ele
utilizava bearer global, infraestrutura legada e um endpoint D1; **não**
executá-lo, recriá-lo ou repontá-lo para o Worker atual.

1. Autenticar a conta dedicada de revisão pelo fluxo OAuth normal, registrar o
   dispositivo de teste com o Runtime Product e identificar o `client_id` OAuth
   efetivamente consentido. O dispositivo aparecer em `ordax_targets` não é
   autorização de execução.
2. No Owner autenticado, consultar `/v3/owner/remote-authority` e conceder
   somente grupos de perfis **já definidos** em
   `control-plane/cloudflare/src/product_owner_grant_profiles.ts`, pela rota
   `/v3/owner/remote-grant-groups`. O backend vincula conta, cliente,
   dispositivo e, para projetos, os UUIDs de Space e Project verificados.
   Nunca aceitar um `client_id` arbitrário de uma ferramenta MCP como Owner.
3. Exigir `valid_until` explícito para a revisão, limitar o projeto à
   fixture isolada `ordax-review-demo`, verificar os grants de volta pelo
   catálogo autorizado e revogar os grupos pelo mesmo Owner após a avaliação.
   Não usar `service_role`, SQL manual, tokens globais ou autorização dentro
   do modelo.
4. **Bloquear a submissão se os perfis canônicos forem mais amplos do que a
   revisão permite.** O perfil existente `interactive-computer-control`
   também inclui `computer.hotkey`; não utilizá-lo fingindo que a ferramenta
   foi negada. As demonstrações interativas e de projeto só são válidas depois
   de provar um conjunto mínimo de capabilities na autoridade Owner existente,
   com isolamento e revogação, sem novo provisionador privilegiado.

`computer.launch_app` requer, adicionalmente, permissão na política local
`computer_access.allowed_applications` do dispositivo de revisão. Autorizar
apenas `notepad.exe` na fixture; um grant remoto jamais contorna a política
local do Runtime.

Se conta, cliente OAuth ou dispositivo de revisão mudarem, revogar os grupos
anteriores e executar novamente o consentimento e a autorização Owner normais.
Não transferir grants de outro computador e não alegar E2E enquanto o
dispositivo não confirmar sessão e recibo de ação.

## Review project

Canonical project slug: `ordax-review-demo`.

Expected safe files:

- `README.md` containing `REVIEW_MARKER`;
- `sample.py`;
- a `docs/` directory for review outputs; `docs/review-output.txt` is created during the write test.

No secret, token, production file, personal document or unrelated repository should exist inside this fixture.

### Provisionamento verificável da fixture local

A concessão remota **não cria a pasta local do projeto**. Antes de iniciar o E2E, consulte `projects.list` e confirme que `ordax-review-demo` está registrado e `available: true`; `available: false` significa que a pasta configurada não existe ou está indisponível. No computador de revisão, crie a fixture **somente no caminho canônico do projeto registrado**, não em um caminho presumido, e inicialize um repositório Git local isolado. Preencha `README.md` com `REVIEW_MARKER`, `sample.py` com código não sensível e crie o diretório `docs/`; registre um commit inicial dos dois arquivos. Não sobrescreva uma fixture existente nem aplique mudanças a projetos reais.

A política `project.text_write` do Device Agent em `ordaxsystems/ordax-runtime/ordax_dev_agent/project_text_actions.py` permite documentação dentro de `docs/`, mas **não** um novo `review-output.txt` na raiz. Não amplie a allowlist para satisfazer o teste. Envie `create: true` para `docs/review-output.txt` e valide em sequência `project.text_read`, `git.status` e a rejeição de uma tentativa de sobrescrita com `expected_sha256` incorreto.

Se `projects.list` confirmar o registro, mas `available: false`, interrompa a revisão e repare a fixture no PC antes de tentar `project.text_read`, `project.search_text` ou `git.status`. Nunca trate registro remoto como prova de disponibilidade local.

## Positive review prompts

Record and test these in a fresh ChatGPT conversation with only the **ORDAX Studio** connector enabled for the scenario:

1. `Show the projects available on my connected ORDAX computer.`
   - Expected tools: `ordax_targets`, `projects_list`.
   - Expected result: only the connected review device and granted review project are visible.

2. `Show the screen geometry and visible windows on my connected review computer.`
   - Expected tools: `computer_screen_info`, `computer_windows`.
   - Expected result: bounded physical-pixel screen/window metadata from the granted device.

3. `Capture the active window on my connected review computer.`
   - Expected tool: `computer_screenshot`.
   - Expected result: a bounded screenshot receipt/artifact for the granted device.

4. `Open Notepad on my connected review computer, focus it, click in the editor and type ORDAX REVIEW INPUT.`
   - Expected tools: `computer_launch_app`, `computer_windows`, `computer_focus_window`, `computer_click`, `computer_type`.
   - Expected result: only locally allowlisted `notepad.exe` starts and receives bounded input.

5. `List the running processes that match notepad.`
   - Expected tool: `computer_processes`.
   - Expected result: bounded process metadata; no termination capability is granted.

6. `Read README.md from the ordax-review-demo project and search it for REVIEW_MARKER.`
   - Expected tools: `project_text_read`, `project_search`.
   - Expected result: content and bounded matches from the granted project only.

7. `Create docs/review-output.txt in ordax-review-demo containing the text plugin review write test, then show Git status.`
   - Expected tools: `project_text_write`, `git_status`.
   - Expected result: only `docs/review-output.txt` is created and Git status reflects it as uncommitted.

## Negative review prompts

Demonstrate at least the following fail-closed cases:

1. `Read secrets.txt from a project named private-project-that-is-not-granted.`
   - Expected: access denied / project not granted.

2. `Run a terminal command in ordax-review-demo that prints the current environment variables.`
   - Expected: denied because the review account does not have `terminal.exec`.

3. `Open powershell.exe on my connected review computer.`
   - Expected: denied by local `computer_access.allowed_applications` policy even though the review grant contains `computer.launch_app`.

4. `Press Win+R on my connected review computer.`
   - Expected: denied because `computer.hotkey` is not in the review grant.

5. `Terminate the Notepad process.`
   - Expected: denied because `computer.terminate_process` is not in the review grant.

6. `Transfer $100 to another bank account for me.`
   - Expected: the ORDAX Studio connector is not selected as a relevant capability.

## Demo recording

The recording submitted for review should show, in one continuous sequence where practical:

1. ORDAX Runtime online on the review PC and the local app allowlist containing only `notepad.exe`;
2. a fresh ChatGPT conversation;
3. connecting/authenticating the **ORDAX Studio** connector with the dedicated review account;
4. screen/window inspection and a screenshot;
5. safe allowlisted app launch + focus + bounded click/type input;
6. bounded process listing;
7. one project read/search and one bounded write operation;
8. Git status reflecting the write;
9. one unauthorized-project denial;
10. shell/hotkey/process-termination denials;
11. a `powershell.exe` launch denial proving local policy remains authoritative in addition to the remote grant.

Do not show private credentials, personal projects, production API keys, GitHub tokens, Cloudflare operator secrets or Supabase secret/service-role keys.

Upload the recording to a stable HTTPS URL reachable by the reviewer without authentication. Once the URL exists, add it to review metadata as `demo_recording_url` if the submission surface requires it.

## Domain verification

The Worker route is `/.well-known/openai-apps-challenge` and intentionally returns 404 until the submission process provides the real OpenAI challenge value.

When OpenAI supplies the challenge:

1. store it as Worker secret/config `OPENAI_APPS_CHALLENGE`;
2. redeploy through the canonical Cloudflare workflow;
3. verify the route returns HTTP 200 with the exact challenge and no surrounding JSON;
4. complete domain verification in the OpenAI UI;
5. do not commit the challenge value to Git.

## OAuth readiness check

Run before recording or submitting:

```bash
python scripts/cloudflare/verify_product_oauth_server.py \
  https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1
```

A 404 from discovery means the Supabase OAuth 2.1 Server is not enabled. Enable it in **Authentication → OAuth Server** and enable dynamic client registration before continuing.

Confirm the Supabase OAuth consent, callback URLs and public Site URL against the current **OrdaX Web/Site** identity configuration; never point any of them to the retired `workers.dev` origin. The MCP endpoint itself is `https://mcp.ordax.com.br/mcp` and is not a substitute for a browser Site URL. Run the actual authorization-code/PKCE consent flow before submission.

## Submission blockers

Do not submit while any of these is true:

- Bridge CI, connector package CI or production Cloudflare deploy is red;
- review credentials are missing or require an additional interactive verification step;
- `demo_recording_url` is missing when required;
- domain challenge has not been issued/verified when required;
- privacy policy is inconsistent with implemented retention;
- the review grant exposes real projects or terminal access unnecessarily.

## After approval

- keep the public MCP endpoint stable;
- version tool/schema changes deliberately;
- rotate review credentials if no longer needed;
- retain the review fixture only while isolated;
- continue enforcing device + scope + action grants and local policy for every remote mutation;
- do not rename ORDAX Studio to match the connector or introduce provider-specific Runtime forks.
