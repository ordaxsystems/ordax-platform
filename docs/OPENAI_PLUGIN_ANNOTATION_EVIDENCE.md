# ORDAX Dev ÔÇö OpenAI MCP annotation review evidence

Generated from the canonical public tool surface on `control-plane/cloudflare/src/mcp_http.ts`.

This document is reviewer-facing evidence for the OpenAI plugin submission. The server advertises explicit boolean `readOnlyHint`, `destructiveHint`, and `openWorldHint` values for every public MCP tool. The justifications below explain why each value matches the tool's behavior.

| Tool | readOnly | destructive | openWorld | Justification |
| --- | :---: | :---: | :---: | --- |
| `ordax_session` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `ordax_profile` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `ordax_targets` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `ordax_action_status` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `app_intelligence_catalog` | true | false | false | Reads the bounded version-bound App Intelligence catalog already packaged on the authenticated ORDAX device; it does not modify device, app, project, or external state. |
| `app_intelligence_detail` | true | false | false | Reads the declarative manifest for one exact app id from the packaged App Intelligence registry; the manifest carries no execution authority and does not modify external state. |
| `repository_catalog` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `handoff_get` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `handoff_create` | false | false | false | Creates additive state or starts/adopts a local capability without deleting or overwriting existing user data by default. |
| `project_inventory` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `project_text_read` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `project_text_write` | false | true | false | Can overwrite, patch, move, remove, save, or otherwise modify existing project/Blender state, so it is treated as potentially destructive. |
| `project_text_patch` | false | true | false | Can overwrite, patch, move, remove, save, or otherwise modify existing project/Blender state, so it is treated as potentially destructive. |
| `projects_list` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `project_create` | false | false | false | Creates a new project only inside the configured ORDAX workspace, without overwriting an existing path; the action requires an explicit grant. |
| `project_import` | false | false | false | Registers an existing directory only inside the configured ORDAX workspace; it does not overwrite project contents, arbitrary external paths are rejected, and the action requires an explicit grant. |
| `project_search` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `project_read_batch` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `project_health` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `project_briefing` | true | false | false | Reads a sanitized bounded briefing, including durable continuation state, without modifying project state. |
| `continuity_state` | true | false | false | Reads the non-expiring continuation state already stored for the granted project. |
| `continuity_update` | false | true | false | Replaces the previously stored ORDAX continuation metadata for the granted project; it does not modify source files but is conservatively classified as destructive because existing state is overwritten. |
| `project_preview_status` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `workspace_file_stat` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `workspace_directory_list` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `workspace_text_read` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `workspace_text_write` | false | true | false | Can overwrite, patch, move, remove, save, or otherwise modify existing project/Blender state, so it is treated as potentially destructive. |
| `workspace_text_patch` | false | true | false | Can overwrite, patch, move, remove, save, or otherwise modify existing project/Blender state, so it is treated as potentially destructive. |
| `workspace_directory_create` | false | false | false | Creates additive state or starts/adopts a local capability without deleting or overwriting existing user data by default. |
| `workspace_path_remove` | false | true | false | Can overwrite, patch, move, remove, save, or otherwise modify existing project/Blender state, so it is treated as potentially destructive. |
| `workspace_path_move` | false | true | false | Can overwrite, patch, move, remove, save, or otherwise modify existing project/Blender state, so it is treated as potentially destructive. |
| `git_status` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `git_diff` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `git_command` | false | true | true | Can execute commands or Git operations that may modify project state and may contact open-ended external destinations; explicit grants and host confirmation are required. |
| `terminal_exec` | false | true | true | Can execute commands or Git operations that may modify project state and may contact open-ended external destinations; explicit grants and host confirmation are required. |
| `computer_terminal_exec` | false | true | true | Executes arbitrary commands on an Owner-authorized device without a project; requires an explicit device-native-terminal or full-computer-control grant plus local Full Access policy, with bounded output, timeout and audit. |
| `computer_process_status` | true | false | false | Reads sanitized state only for supervised processes in the Owner-granted device namespace. |
| `computer_process_list` | true | false | false | Lists supervised processes on the authorized device; cannot inspect project or arbitrary host process state. |
| `computer_process_logs` | true | false | false | Reads bounded output from one ORDAX-owned device process. |
| `computer_process_start` | false | true | true | Starts a supervised process under an explicit device-native-process or full-computer-control grant and local Full Access; may affect local and external systems. |
| `computer_process_write_stdin` | false | true | true | Writes bounded input to one validated ORDAX-owned device process; can cause side effects. |
| `computer_process_stop` | false | true | false | Stops only a validated ORDAX-owned device process, not arbitrary OS processes. |
| `process_status` | true | false | false | Reads bounded sanitized state for one ORDAX-owned persistent process without exposing ownership tokens or local control paths. |
| `process_list` | true | false | false | Lists sanitized ORDAX-owned persistent process state for the granted project without changing process state. |
| `process_logs` | true | false | false | Reads a bounded tail from an ORDAX-owned process log and does not modify the process. |
| `process_start` | false | true | true | Starts an argv-based project process that may modify local state or contact external destinations; it requires an explicit process.start grant. |
| `process_write_stdin` | false | true | true | Input sent to a running process can trigger local or external side effects, so it requires an explicit process.write_stdin grant. |
| `process_stop` | false | true | false | Stops only a process whose ORDAX ownership is revalidated; it does not target arbitrary system processes. |
| `browser_status` | true | false | false | Reads metadata for an ORDAX-owned browser session without changing browser or project state. |
| `browser_list` | true | false | false | Lists ORDAX-owned browser sessions for the granted project without changing them. |
| `browser_snapshot` | true | false | true | Reads bounded page text and interactive element metadata from the current browser page; the page may be an open-world web destination. |
| `browser_screenshot` | true | false | true | Captures pixels from the current ORDAX-managed browser page through CDP without requiring that page to be foreground. |
| `browser_start` | false | false | true | Starts an isolated ORDAX-owned Chromium session and may load an open-world URL; protected consumer AI pages remain blocked from automation. |
| `browser_navigate` | false | false | true | Changes only the managed browser navigation state but may contact an open-world web destination. |
| `browser_click` | false | true | true | A page click can submit forms or trigger external side effects, so it requires an explicit action grant and is conservatively destructive/open-world. |
| `browser_type` | false | true | true | Typing into a web page can change or submit external state, so it is conservatively destructive/open-world. |
| `browser_stop` | false | true | false | Stops only an ORDAX-owned browser process and discards its ephemeral session state. |
| `computer_windows` | true | false | false | Reads bounded visible-window metadata from the interactive Windows desktop. |
| `computer_active_window` | true | false | false | Reads metadata for the foreground Windows window. |
| `computer_screenshot` | true | false | false | Captures the authorized local desktop or active window for visual inspection. |
| `computer_screen_info` | true | false | false | Reads bounded local monitor geometry, virtual-desktop bounds, and cursor position without changing device state. |
| `computer_clipboard_read` | true | false | false | Reads bounded Unicode text from the authorized local clipboard without modifying external state. |
| `computer_focus_window` | false | false | false | Brings one existing visible local window to the foreground without changing its data. |
| `computer_click` | false | true | true | A desktop click can activate arbitrary applications or external services, so it requires an explicit grant and is conservatively destructive/open-world. |
| `computer_mouse_move` | false | false | true | Moves the pointer within validated local screen bounds; the target may belong to an open-world application, but pointer movement alone does not mutate stored data. |
| `computer_drag` | false | true | true | A drag gesture can move, drop, or otherwise change state in arbitrary local or externally connected applications, so it is conservatively destructive/open-world. |
| `computer_clipboard_write` | false | false | false | Replaces bounded Unicode text in the local clipboard; it changes local transient state but does not contact an external destination by itself. |
| `computer_launch_app` | false | false | true | Starts one validated and locally allowlisted Windows executable without shell expansion; both the remote action grant and local computer-access policy must allow it, and the launched application may contact open-world destinations. |
| `computer_scroll` | false | false | false | Sends bounded scrolling to the local interactive desktop without directly changing stored data. |
| `computer_type` | false | true | true | Desktop typing can change local or external application state, so it requires an explicit grant and is conservatively destructive/open-world. |
| `computer_hotkey` | false | true | true | A validated desktop hotkey can trigger local or external application actions, so it is conservatively destructive/open-world. |
| `computer_access_status` | true | false | false | Reads the effective non-secret local computer-access policy, including allowed roots and resolved allowed applications, without changing device state. |
| `computer_file_stat` | true | false | false | Reads bounded metadata for one locally allowed computer path. |
| `computer_directory_list` | true | false | false | Lists filesystem entries only inside roots allowed by the local ORDAX computer-access policy. |
| `computer_text_read` | true | false | false | Reads bounded UTF-8 text only from a locally allowed computer path. |
| `computer_search` | true | false | false | Performs a bounded local filename/text search inside an allowed computer root. |
| `computer_processes` | true | false | false | Lists bounded local process metadata without changing process state. |
| `computer_terminate_process` | false | true | false | Terminates one local non-critical process only after PID and expected process name are revalidated; ORDAX and protected system processes are refused. |
| `computer_text_write` | false | true | false | Creates or replaces local text inside an allowed root; replacing existing content requires a SHA-256 precondition. |
| `computer_text_patch` | false | true | false | Mutates an existing allowed local text file using exact replacements and a SHA-256 precondition. |
| `computer_directory_create` | false | false | false | Creates additive local directory state only inside a root allowed by local policy. |
| `computer_path_move` | false | true | false | Moves or renames allowed local filesystem state and can replace a destination file only when overwrite is explicit. |
| `computer_path_remove` | false | true | false | Removes an allowed local file or directory; recursive directory removal must be explicit and configured roots cannot be removed. |
| `artifacts_list` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `artifact_preview` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `blender_status` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `blender_scene_snapshot` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `blender_object_inspect` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `blender_modeling_schema` | true | false | false | Reads or computes bounded data from the authenticated ORDAX account/device/project and does not modify external state. |
| `blender_start` | false | false | false | Creates additive state or starts/adopts a local capability without deleting or overwriting existing user data by default. |
| `blender_transform` | false | true | false | Can overwrite, patch, move, remove, save, or otherwise modify existing project/Blender state, so it is treated as potentially destructive. |
| `blender_create_primitive` | false | false | false | Creates additive state or starts/adopts a local capability without deleting or overwriting existing user data by default. |
| `blender_apply_material` | false | true | false | Can overwrite, patch, move, remove, save, or otherwise modify existing project/Blender state, so it is treated as potentially destructive. |
| `blender_save` | false | true | false | Can overwrite, patch, move, remove, save, or otherwise modify existing project/Blender state, so it is treated as potentially destructive. |

## Classification policy

- **Read-only**: retrieval, bounded inspection, health/status, search, preview metadata, and artifact/file reads.
- **Non-destructive write**: additive state such as creating a handoff, directory, primitive, or starting/adopting Blender.
- **Destructive/write**: operations that can overwrite, patch, move, delete, save, transform, execute commands, or otherwise mutate existing state.
- **Open-world**: Git/terminal commands and managed-browser or desktop-input operations that can reach arbitrary external destinations are marked open-world. Private ORDAX account/device/project reads are not open-world merely because the Control Plane is remotely hosted.

The runtime still enforces account, device, project, Space, and action grants independently of these host-facing hints.
