import { OWNER_DEVICE_COMPUTER_GRANT_PROFILES } from "./product_action_scope.ts";
import { readBoundedJsonObject } from "./request_json.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";

export type JsonObject = Record<string, unknown>;

type Handler = (request: Request) => Promise<Response>;
type StatusHandler = (request: Request, requestId: string) => Promise<Response>;

export interface OrdaxMcpHandlers {
  session: Handler;
  targets: Handler;
  createAction: Handler;
  getAction: StatusHandler;
}

interface ToolSpec {
  name: string;
  description: string;
  action?: string;
  projectRequired?: boolean;
  properties?: Record<string, JsonObject>;
  required?: string[];
}

const STRING = { type: "string" };
const OAUTH_SCOPES = ["openid", "email", "offline_access"];
const NUMBER = { type: "number" };
const BOOLEAN = { type: "boolean" };
const DEVICE = { type: "string", description: "ORDAX device UUID returned by ordax_targets." };
const PROJECT = { type: "string", description: "Local Runtime project slug; not a Space UUID, canonical cloud Project ID, or GitHub repository identity." };
const REPOSITORY_PROJECT = { type: "string", pattern: "^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", description: "Verified GitHub owner/repository connected to one canonical ORDAX Project; not a local path, slug, Space or authorization grant." };
const SPACE = { type: "string", description: "Optional canonical OrdaX Space UUID for scope disambiguation. Omission never bypasses account, device, project, grant or Runtime policy." };
const WAIT = { type: "integer", minimum: 0, maximum: 20000, default: 8000, description: "How long the gateway waits for completion before returning a request_id." };
const STRING_ARRAY = { type: "array", items: STRING, minItems: 1, maxItems: 256 };
const ENV_OBJECT = { type: "object", maxProperties: 64, additionalProperties: { anyOf: [{ type: "string" }, { type: "number" }, { type: "boolean" }] } };
const PROCESS_ENV_OBJECT = { type: "object", maxProperties: 64, additionalProperties: { type: "string" } };
const PROCESS_ARGV = { type: "array", items: { type: "string", minLength: 1, maxLength: 8192 }, minItems: 1, maxItems: 128 };
const PROCESS_STDIN_TEXT = { type: "string", maxLength: 65536 };
const REPLACEMENTS = {
  type: "array",
  minItems: 1,
  maxItems: 100,
  items: {
    type: "object",
    properties: {
      old: STRING,
      new: STRING,
      expected_count: { type: "integer", minimum: 1, maximum: 10000 },
    },
    required: ["old", "new"],
    additionalProperties: false,
  },
};

const MCP_TOOL_SURFACE_REVISION = "2026-10-18.3";

const TOOLS: ToolSpec[] = [
  { name: "ordax_session", description: "Inspect whether the current ORDAX Product connection is authenticated." },
  { name: "ordax_profile", description: "Return the authenticated OrdaX account subject id for connector identity display. Compatibility tool: not an OS Profile, Profile Pack, Space or preferences." },
  { name: "ordax_targets", description: "List authorized ORDAX devices, reported presence, Spaces and grants. Offline devices require their Runtime to reconnect for local work; unknown presence is not proof of connectivity. This does not discover cloud executors or synchronize repository files." },
  { name: "ordax_action_status", description: "Read the status/result of a previously queued ORDAX action.", properties: { request_id: STRING }, required: ["request_id"] },
  { name: "app_intelligence_catalog", description: "Read the compact version-bound App Intelligence catalog from the connected ORDAX device. Use this only to discover which app semantics are available; it grants no execution authority.", action: "intelligence.app_catalog", properties: { device_id: DEVICE, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "app_intelligence_detail", description: "Read declarative instructions, intents, parameters and examples for one exact app_id from the connected ORDAX device. This never grants permission to execute the app.", action: "intelligence.app_detail", properties: { device_id: DEVICE, space_id: SPACE, app_id: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "app_id"] },
  { name: "repository_catalog", description: "List canonical repositories on an ORDAX device; use this to disambiguate a named project/repository before resuming work.", action: "workspace.repository_catalog", properties: { device_id: DEVICE, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "handoff_get", description: "Load an expiring ORDAX continuation handoff for a fresh client conversation.", action: "handoff.get", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, handoff_id: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "handoff_id"] },
  { name: "handoff_create", description: "Create an expiring continuation handoff so work can resume in a fresh client conversation.", action: "handoff.create", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, summary: STRING, next_action: STRING, completed: { type: "array", items: STRING, maxItems: 100 }, blockers: { type: "array", items: STRING, maxItems: 100 }, changed_paths: { type: "array", items: STRING, maxItems: 100 }, ttl_hours: { type: "integer", minimum: 1, maximum: 168 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "summary"] },
  { name: "project_inventory", description: "Inspect a bounded inventory of one registered project.", action: "project.inventory", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, max_depth: { type: "integer", minimum: 1, maximum: 12 }, max_entries: { type: "integer", minimum: 1, maximum: 10000 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "project_text_read", description: "Read a granted text file inside a registered project.", action: "project.text_read", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path"] },
  { name: "project_text_write", description: "Write a granted project text file with SHA-256 concurrency protection.", action: "project.text_write", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, content: STRING, expected_sha256: STRING, create: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path", "content"] },
  { name: "project_text_patch", description: "Patch a granted project text file using exact replacements and a SHA-256 precondition.", action: "project.text_patch", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, expected_sha256: STRING, replacements: { type: "array", items: { type: "object" }, maxItems: 100 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path", "expected_sha256", "replacements"] },
  { name: "projects_list", description: "List granted projects. Use this first when the user asks to continue/resume project work but the target project is not yet known.", action: "projects.list", properties: { device_id: DEVICE, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "project_create", description: "Create and register a new project inside the device's configured ORDAX workspace.", action: "workspace.project_create", properties: { device_id: DEVICE, space_id: SPACE, slug: STRING, name: STRING, apps: { type: "array", items: { type: "string", enum: ["blender", "unity"] }, maxItems: 2, uniqueItems: true }, set_default: BOOLEAN, git_init: BOOLEAN, readme: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "slug"] },
  { name: "project_import", description: "Register an existing directory inside the configured ORDAX workspace; arbitrary paths outside the workspace are rejected by the runtime.", action: "workspace.bind_project", properties: { device_id: DEVICE, space_id: SPACE, slug: STRING, relative_path: STRING, apps: { type: "array", items: { type: "string", enum: ["blender", "unity"] }, maxItems: 2, uniqueItems: true }, set_default: BOOLEAN, blender_scripts_dir: STRING, blend_file: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "slug", "relative_path"] },
  { name: "project_search", description: "Search text across a granted project.", action: "project.search_text", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, query: STRING, max_results: { type: "integer", minimum: 1, maximum: 100 }, max_files: { type: "integer", minimum: 50, maximum: 5000 }, case_sensitive: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "query"] },
  { name: "project_read_batch", description: "Read several granted project text files in one bounded call.", action: "project.text_read_batch", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, paths: { type: "array", items: STRING, minItems: 1, maxItems: 16 }, max_total_bytes: { type: "integer", minimum: 65536, maximum: 786432 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "paths"] },
  { name: "project_health", description: "Inspect sanitized project, Git, memory and adapter health.", action: "agent.project_health", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "project_briefing", description: "Load durable project state plus bounded relevant memory/source context. In a fresh chat, use this after identifying the project when the user asks to continue, resume, pick up, or review ongoing project work; pass the user intent as query when useful.", action: "agent.project_briefing", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, query: STRING, recall_limit: { type: "integer", minimum: 1, maximum: 50 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "continuity_state", description: "Read the non-expiring continuation state for a granted project.", action: "continuity.get", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "continuity_update", description: "Persist non-expiring project progress for future conversations.", action: "continuity.update", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, summary: STRING, next_action: STRING, completed: { type: "array", items: STRING, maxItems: 100 }, blockers: { type: "array", items: STRING, maxItems: 100 }, changed_paths: { type: "array", items: STRING, maxItems: 100 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "summary"] },
  { name: "project_preview_status", description: "Inspect the project's supervised preview/runtime state.", action: "project.preview_status", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "workspace_file_stat", description: "Inspect any path inside a granted project.", action: "workspace.file_stat", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "workspace_directory_list", description: "List directories anywhere inside a granted project.", action: "workspace.directory_list", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, max_depth: { type: "integer", minimum: 1, maximum: 12 }, max_entries: { type: "integer", minimum: 1, maximum: 5000 }, include_hidden: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "workspace_text_read", description: "Read UTF-8 text anywhere inside a granted project with optional line ranges.", action: "workspace.text_read", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, start_line: { type: "integer", minimum: 1 }, end_line: { type: "integer", minimum: 1 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path"] },
  { name: "workspace_text_write", description: "Create or replace project text with SHA-256 concurrency protection.", action: "workspace.text_write", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, content: STRING, expected_sha256: STRING, create: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path", "content"] },
  { name: "workspace_text_patch", description: "Patch arbitrary project text using exact replacements and SHA-256 guards.", action: "workspace.text_patch", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, expected_sha256: STRING, replacements: REPLACEMENTS, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path", "expected_sha256", "replacements"] },
  { name: "workspace_directory_create", description: "Create a directory inside a granted project.", action: "workspace.directory_create", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, parents: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path"] },
  { name: "workspace_path_remove", description: "Remove a project path. Recursive directory removal requires recursive=true.", action: "workspace.path_remove", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, path: STRING, expected_sha256: STRING, recursive: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "path"] },
  { name: "workspace_path_move", description: "Move or rename a path inside a granted project.", action: "workspace.path_move", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, source: STRING, destination: STRING, expected_sha256: STRING, overwrite: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "source", "destination"] },
  { name: "git_status", description: "Read bounded Git status for a granted project.", action: "git.status", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "git_diff", description: "Read a bounded Git diff for a granted project.", action: "git.diff", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, paths: { type: "array", items: STRING, maxItems: 50 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "git_command", description: "Run an approved Git subcommand against a granted project. Repository hooks may execute, but credential/config inspection is blocked and authenticated remote URLs are redacted.", action: "git.command", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, args: { type: "array", items: STRING, minItems: 1, maxItems: 128 }, timeout_seconds: { type: "integer", minimum: 1, maximum: 1800 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "args"] },
  { name: "terminal_exec", description: "Execute a foreground command with the local OS user's permissions. Requires an explicit terminal.exec grant.", action: "terminal.exec", projectRequired: true, properties: { device_id: DEVICE, project: REPOSITORY_PROJECT, space_id: SPACE, cwd: STRING, argv: STRING_ARRAY, command: STRING, shell: BOOLEAN, timeout_seconds: { type: "integer", minimum: 1, maximum: 1800 }, env: ENV_OBJECT, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "process_status", description: "Inspect one ORDAX-owned persistent process.", action: "process.status", projectRequired: true, properties: { device_id: DEVICE, project: REPOSITORY_PROJECT, space_id: SPACE, process_id: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "process_id"] },
  { name: "process_list", description: "List ORDAX-owned persistent processes for a granted project.", action: "process.list", projectRequired: true, properties: { device_id: DEVICE, project: REPOSITORY_PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "process_logs", description: "Read a bounded log tail from an ORDAX-owned persistent process.", action: "process.logs", projectRequired: true, properties: { device_id: DEVICE, project: REPOSITORY_PROJECT, space_id: SPACE, process_id: STRING, max_bytes: { type: "integer", minimum: 1024, maximum: 262144 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "process_id"] },
  { name: "process_start", description: "Start a persistent argv-based process supervised by ORDAX inside a granted project. Requires an explicit process.start grant.", action: "process.start", projectRequired: true, properties: { device_id: DEVICE, project: REPOSITORY_PROJECT, space_id: SPACE, argv: PROCESS_ARGV, cwd: STRING, env: PROCESS_ENV_OBJECT, wait_seconds: { type: "number", minimum: 0.1, maximum: 5 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "argv"] },
  { name: "process_write_stdin", description: "Send bounded stdin to an ORDAX-owned persistent process. Requires an explicit process.write_stdin grant.", action: "process.write_stdin", projectRequired: true, properties: { device_id: DEVICE, project: REPOSITORY_PROJECT, space_id: SPACE, process_id: STRING, text: PROCESS_STDIN_TEXT, newline: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "process_id", "text"] },
  { name: "process_stop", description: "Stop an ORDAX-owned persistent process. Requires an explicit process.stop grant.", action: "process.stop", projectRequired: true, properties: { device_id: DEVICE, project: REPOSITORY_PROJECT, space_id: SPACE, process_id: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "process_id"] },
  { name: "browser_status", description: "Read status for one ORDAX-managed Chromium session.", action: "browser.status", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, session_id: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "session_id"] },
  { name: "browser_list", description: "List ORDAX-managed Chromium sessions for a granted project.", action: "browser.list", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "browser_snapshot", description: "Read a bounded DOM/text snapshot from an ORDAX-managed Chromium session.", action: "browser.snapshot", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, session_id: STRING, max_elements: { type: "integer", minimum: 20, maximum: 500 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "session_id"] },
  { name: "browser_screenshot", description: "Capture an ORDAX-managed browser page through CDP, including while the Studio preview is not foreground.", action: "browser.screenshot", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, session_id: STRING, width: { type: "integer", minimum: 320, maximum: 2560 }, height: { type: "integer", minimum: 240, maximum: 1600 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "session_id"] },
  { name: "browser_start", description: "Start an isolated ORDAX-managed Chromium session. Consumer AI pages remain protected from programmatic browser automation.", action: "browser.start", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, url: STRING, headless: BOOLEAN, wait_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "browser_navigate", description: "Navigate an ORDAX-managed Chromium session to an allowed http/https URL.", action: "browser.navigate", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, session_id: STRING, url: STRING, wait_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "session_id", "url"] },
  { name: "browser_click", description: "Click an element identified by a current ORDAX browser snapshot.", action: "browser.click", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, session_id: STRING, node_id: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "session_id", "node_id"] },
  { name: "browser_type", description: "Enter text into an editable element in an ORDAX-managed browser session.", action: "browser.type", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, session_id: STRING, node_id: STRING, text: STRING, clear: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "session_id", "node_id", "text"] },
  { name: "browser_stop", description: "Stop an ORDAX-owned Chromium session.", action: "browser.stop", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, session_id: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "session_id"] },
  { name: "computer_windows", description: "List visible windows on the interactive Windows desktop.", action: "computer.windows", properties: { device_id: DEVICE, space_id: SPACE, max_items: { type: "integer", minimum: 1, maximum: 500 }, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "computer_active_window", description: "Inspect the current foreground Windows desktop window.", action: "computer.active_window", properties: { device_id: DEVICE, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "computer_screenshot", description: "Capture the full Windows desktop or active window for visual inspection.", action: "computer.screenshot", properties: { device_id: DEVICE, space_id: SPACE, mode: { type: "string", enum: ["desktop", "active_window"] }, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "computer_screen_info", description: "Inspect monitor geometry, virtual desktop bounds and cursor position.", action: "computer.screen_info", properties: { device_id: DEVICE, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "computer_clipboard_read", description: "Read bounded Unicode text from the interactive Windows clipboard.", action: "computer.clipboard_read", properties: { device_id: DEVICE, space_id: SPACE, max_bytes: { type: "integer", minimum: 1, maximum: 1048576 }, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "computer_focus_window", description: "Bring one visible Windows window to the foreground.", action: "computer.focus_window", properties: { device_id: DEVICE, space_id: SPACE, handle: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "handle"] },
  { name: "computer_click", description: "Send a bounded mouse click to the interactive Windows desktop. Requires an explicit grant.", action: "computer.click", properties: { device_id: DEVICE, space_id: SPACE, x: { type: "integer" }, y: { type: "integer" }, button: { type: "string", enum: ["left", "right", "middle"] }, clicks: { type: "integer", minimum: 1, maximum: 3 }, wait_for_completion_ms: WAIT }, required: ["device_id", "x", "y"] },
  { name: "computer_mouse_move", description: "Move the pointer to a validated virtual-desktop coordinate.", action: "computer.mouse_move", properties: { device_id: DEVICE, space_id: SPACE, x: { type: "integer" }, y: { type: "integer" }, duration_ms: { type: "integer", minimum: 0, maximum: 5000 }, wait_for_completion_ms: WAIT }, required: ["device_id", "x", "y"] },
  { name: "computer_drag", description: "Perform one bounded drag gesture on the interactive Windows desktop.", action: "computer.drag", properties: { device_id: DEVICE, space_id: SPACE, from_x: { type: "integer" }, from_y: { type: "integer" }, to_x: { type: "integer" }, to_y: { type: "integer" }, button: { type: "string", enum: ["left", "right", "middle"] }, duration_ms: { type: "integer", minimum: 50, maximum: 5000 }, wait_for_completion_ms: WAIT }, required: ["device_id", "from_x", "from_y", "to_x", "to_y"] },
  { name: "computer_clipboard_write", description: "Replace Unicode text in the interactive Windows clipboard. Requires an explicit grant.", action: "computer.clipboard_write", properties: { device_id: DEVICE, space_id: SPACE, text: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "text"] },
  { name: "computer_launch_app", description: "Launch one validated Windows executable without shell expansion. Requires an explicit grant.", action: "computer.launch_app", properties: { device_id: DEVICE, space_id: SPACE, application: STRING, args: { type: "array", items: STRING, maxItems: 32 }, wait_for_completion_ms: WAIT }, required: ["device_id", "application"] },
  { name: "computer_scroll", description: "Send bounded scrolling to the interactive Windows desktop.", action: "computer.scroll", properties: { device_id: DEVICE, space_id: SPACE, amount: { type: "integer", minimum: -100, maximum: 100 }, horizontal: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "amount"] },
  { name: "computer_type", description: "Type bounded Unicode text into the interactive Windows desktop. Requires an explicit grant.", action: "computer.type", properties: { device_id: DEVICE, space_id: SPACE, text: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "text"] },
  { name: "computer_hotkey", description: "Send a bounded validated hotkey chord to the interactive Windows desktop. Requires an explicit grant.", action: "computer.hotkey", properties: { device_id: DEVICE, space_id: SPACE, keys: { type: "array", items: STRING, minItems: 1, maxItems: 6 }, wait_for_completion_ms: WAIT }, required: ["device_id", "keys"] },
  { name: "computer_access_status", description: "Read the local ORDAX computer-access policy and allowed filesystem roots.", action: "computer.access_status", properties: { device_id: DEVICE, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "computer_file_stat", description: "Inspect a file or directory allowed by the local computer-access policy.", action: "computer.file_stat", properties: { device_id: DEVICE, space_id: SPACE, path: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "path"] },
  { name: "computer_directory_list", description: "List a directory tree allowed by the local computer-access policy.", action: "computer.directory_list", properties: { device_id: DEVICE, space_id: SPACE, path: STRING, max_depth: { type: "integer", minimum: 1, maximum: 12 }, max_entries: { type: "integer", minimum: 1, maximum: 5000 }, include_hidden: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "path"] },
  { name: "computer_text_read", description: "Read bounded UTF-8 text from an allowed computer path.", action: "computer.text_read", properties: { device_id: DEVICE, space_id: SPACE, path: STRING, start_line: { type: "integer", minimum: 1 }, end_line: { type: "integer", minimum: 1 }, wait_for_completion_ms: WAIT }, required: ["device_id", "path"] },
  { name: "computer_search", description: "Search names or bounded text content under an allowed computer root.", action: "computer.search", properties: { device_id: DEVICE, space_id: SPACE, root: STRING, query: STRING, mode: { type: "string", enum: ["name", "content", "both"] }, max_results: { type: "integer", minimum: 1, maximum: 500 }, max_depth: { type: "integer", minimum: 1, maximum: 12 }, include_hidden: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "root", "query"] },
  { name: "computer_processes", description: "List bounded system process metadata on the authorized computer.", action: "computer.processes", properties: { device_id: DEVICE, space_id: SPACE, query: STRING, max_items: { type: "integer", minimum: 1, maximum: 1000 }, wait_for_completion_ms: WAIT }, required: ["device_id"] },
  { name: "computer_terminate_process", description: "Terminate one non-critical process only when expected_name still matches the PID.", action: "computer.terminate_process", properties: { device_id: DEVICE, space_id: SPACE, pid: { type: "integer", minimum: 1 }, expected_name: STRING, force: BOOLEAN, tree: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "pid", "expected_name"] },
  { name: "computer_text_write", description: "Create or replace text at an allowed computer path with SHA-256 concurrency protection.", action: "computer.text_write", properties: { device_id: DEVICE, space_id: SPACE, path: STRING, content: STRING, expected_sha256: STRING, create: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "path", "content"] },
  { name: "computer_text_patch", description: "Patch allowed computer text using exact replacements and a SHA-256 precondition.", action: "computer.text_patch", properties: { device_id: DEVICE, space_id: SPACE, path: STRING, expected_sha256: STRING, replacements: REPLACEMENTS, wait_for_completion_ms: WAIT }, required: ["device_id", "path", "expected_sha256", "replacements"] },
  { name: "computer_directory_create", description: "Create a directory within the local computer-access policy.", action: "computer.directory_create", properties: { device_id: DEVICE, space_id: SPACE, path: STRING, parents: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "path"] },
  { name: "computer_path_move", description: "Move or rename an allowed computer path.", action: "computer.path_move", properties: { device_id: DEVICE, space_id: SPACE, source: STRING, destination: STRING, overwrite: BOOLEAN, expected_sha256: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "source", "destination"] },
  { name: "computer_path_remove", description: "Remove an allowed computer path. Recursive directory removal requires recursive=true.", action: "computer.path_remove", properties: { device_id: DEVICE, space_id: SPACE, path: STRING, recursive: BOOLEAN, expected_sha256: STRING, wait_for_completion_ms: WAIT }, required: ["device_id", "path"] },
  { name: "artifacts_list", description: "List bounded artifact metadata for a granted project.", action: "artifacts.list", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, max_items: { type: "integer", minimum: 1, maximum: 100 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "artifact_preview", description: "Read a bounded preview of a granted project artifact.", action: "artifact.preview", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, artifact_name: STRING, project_artifact_path: STRING, thumbnail: BOOLEAN, max_bytes: { type: "integer", minimum: 1, maximum: 262144 }, max_width: { type: "integer", minimum: 1, maximum: 4096 }, max_height: { type: "integer", minimum: 1, maximum: 4096 }, quality: { type: "integer", minimum: 1, maximum: 100 }, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "blender_status", description: "Read sanitized live Blender status for a project.", action: "blender.live_status", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "blender_scene_snapshot", description: "Inspect a bounded snapshot of the live Blender scene.", action: "blender.live_scene_snapshot", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, max_objects: { type: "integer", minimum: 1, maximum: 10000 }, object_names: { type: "array", items: STRING, maxItems: 256 }, timeout_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "blender_object_inspect", description: "Inspect one live Blender object by name or ORDAX object id.", action: "blender.live_object_inspect", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, object_name: STRING, ordax_object_id: STRING, timeout_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "blender_modeling_schema", description: "Read the validated live Blender modeling contracts and guards.", action: "blender.live_modeling_schema", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "blender_start", description: "Adopt or start the project's visible Blender session without opening duplicate windows.", action: "blender.live_start", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, wait_seconds: NUMBER, timeout_seconds: NUMBER, pid: { type: "integer", minimum: 1 }, adopt_blank: BOOLEAN, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "blender_transform", description: "Apply a validated transform to one live Blender object.", action: "blender.live_object_transform", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, object_name: STRING, ordax_object_id: STRING, location: { type: "array", items: NUMBER, minItems: 3, maxItems: 3 }, rotation_euler: { type: "array", items: NUMBER, minItems: 3, maxItems: 3 }, scale: { type: "array", items: NUMBER, minItems: 3, maxItems: 3 }, dimensions: { type: "array", items: NUMBER, minItems: 3, maxItems: 3 }, timeout_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
  { name: "blender_create_primitive", description: "Create a bounded validated primitive in the live Blender scene.", action: "blender.live_create_primitive", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, name: STRING, primitive: STRING, location: { type: "array", items: NUMBER, minItems: 3, maxItems: 3 }, size: NUMBER, radius: NUMBER, depth: NUMBER, segments: { type: "integer" }, timeout_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "name", "primitive"] },
  { name: "blender_apply_material", description: "Apply a validated material to one live Blender object.", action: "blender.live_material_apply", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, object_name: STRING, ordax_object_id: STRING, material_name: STRING, base_color: { type: "array", items: NUMBER, minItems: 3, maxItems: 4 }, roughness: NUMBER, metallic: NUMBER, transmission: NUMBER, alpha: NUMBER, ior: NUMBER, surface_render_method: STRING, transparency_overlap: BOOLEAN, timeout_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project", "material_name"] },
  { name: "blender_save", description: "Save the granted live Blender project.", action: "blender.live_save", projectRequired: true, properties: { device_id: DEVICE, project: PROJECT, space_id: SPACE, target_path: STRING, timeout_seconds: NUMBER, wait_for_completion_ms: WAIT }, required: ["device_id", "project"] },
];

const READ_ONLY_TOOLS = new Set([
  "ordax_session",
  "ordax_profile",
  "ordax_targets",
  "ordax_action_status",
  "app_intelligence_catalog",
  "app_intelligence_detail",
  "repository_catalog",
  "handoff_get",
  "project_inventory",
  "project_text_read",
  "projects_list",
  "project_search",
  "project_read_batch",
  "project_health",
  "project_briefing",
  "continuity_state",
  "project_preview_status",
  "workspace_file_stat",
  "workspace_directory_list",
  "workspace_text_read",
  "git_status",
  "git_diff",
  "artifacts_list",
  "artifact_preview",
  "blender_status",
  "blender_scene_snapshot",
  "blender_object_inspect",
  "blender_modeling_schema",
  "browser_status",
  "browser_list",
  "browser_snapshot",
  "browser_screenshot",
  "computer_windows",
  "computer_active_window",
  "computer_screenshot",
  "computer_screen_info",
  "computer_clipboard_read",
  "computer_access_status",
  "computer_file_stat",
  "computer_directory_list",
  "computer_text_read",
  "computer_search",
  "computer_processes",
  "process_status",
  "process_list",
  "process_logs",
]);

const DESTRUCTIVE_TOOLS = new Set([
  "project_text_write",
  "project_text_patch",
  "continuity_update",
  "workspace_text_write",
  "workspace_text_patch",
  "workspace_path_remove",
  "workspace_path_move",
  "git_command",
  "terminal_exec",
  "process_start",
  "process_write_stdin",
  "process_stop",
  "blender_transform",
  "blender_apply_material",
  "blender_save",
  "browser_click",
  "browser_type",
  "browser_stop",
  "computer_click",
  "computer_drag",
  "computer_type",
  "computer_hotkey",
  "computer_text_write",
  "computer_text_patch",
  "computer_path_move",
  "computer_path_remove",
  "computer_terminate_process",
]);

const NON_DESTRUCTIVE_WRITE_TOOLS = new Set([
  "project_create",
  "project_import",
  "handoff_create",
  "workspace_directory_create",
  "blender_start",
  "blender_create_primitive",
  "browser_start",
  "browser_navigate",
  "computer_focus_window",
  "computer_mouse_move",
  "computer_scroll",
  "computer_clipboard_write",
  "computer_launch_app",
  "computer_directory_create",
]);

const OPEN_WORLD_TOOLS = new Set([
  "git_command",
  "terminal_exec",
  "process_start",
  "process_write_stdin",
  "browser_snapshot",
  "browser_screenshot",
  "browser_start",
  "browser_navigate",
  "browser_click",
  "browser_type",
  "computer_click",
  "computer_mouse_move",
  "computer_drag",
  "computer_type",
  "computer_hotkey",
  "computer_launch_app",
]);

const TOOL_TITLES: Record<string, string> = {
  ordax_session: "Check ORDAX account session",
  ordax_profile: "Identify connected ORDAX account",
  ordax_targets: "List authorized ORDAX devices",
  ordax_action_status: "Check ORDAX action status",
  app_intelligence_catalog: "List App Intelligence catalog",
  app_intelligence_detail: "Read App Intelligence detail",
  repository_catalog: "List device repositories",
  handoff_get: "Load continuation handoff",
  handoff_create: "Create continuation handoff",
  project_inventory: "Inspect project inventory",
  project_text_read: "Read project text file",
  project_text_write: "Write project text file",
  project_text_patch: "Patch project text file",
  projects_list: "List device projects",
  project_create: "Create ORDAX project",
  project_import: "Import existing ORDAX project",
  project_search: "Search project text",
  project_read_batch: "Read project files",
  project_health: "Inspect project health",
  project_briefing: "Load project briefing",
  continuity_state: "Read project continuity",
  continuity_update: "Update project continuity",
  project_preview_status: "Inspect project preview",
  workspace_file_stat: "Inspect project path",
  workspace_directory_list: "List project directory",
  workspace_text_read: "Read workspace text",
  workspace_text_write: "Write workspace text",
  workspace_text_patch: "Patch workspace text",
  workspace_directory_create: "Create workspace directory",
  workspace_path_remove: "Remove workspace path",
  workspace_path_move: "Move workspace path",
  git_status: "Read Git status",
  git_diff: "Read Git diff",
  git_command: "Run Git command",
  terminal_exec: "Run project command",
  process_status: "Inspect persistent process",
  process_list: "List persistent processes",
  process_logs: "Read persistent process logs",
  process_start: "Start persistent process",
  process_write_stdin: "Send process input",
  process_stop: "Stop persistent process",
  browser_status: "Inspect managed browser status",
  browser_list: "List managed browsers",
  browser_snapshot: "Inspect browser page",
  browser_screenshot: "Capture browser page",
  browser_start: "Start managed browser",
  browser_navigate: "Navigate managed browser",
  browser_click: "Click browser element",
  browser_type: "Type in browser element",
  browser_stop: "Stop managed browser",
  computer_windows: "List desktop windows",
  computer_active_window: "Inspect active desktop window",
  computer_screenshot: "Capture desktop",
  computer_screen_info: "Inspect desktop screens",
  computer_clipboard_read: "Read desktop clipboard",
  computer_focus_window: "Focus desktop window",
  computer_click: "Click desktop",
  computer_mouse_move: "Move desktop pointer",
  computer_drag: "Drag on desktop",
  computer_clipboard_write: "Write desktop clipboard",
  computer_launch_app: "Launch desktop application",
  computer_scroll: "Scroll desktop",
  computer_type: "Type on desktop",
  computer_hotkey: "Send desktop hotkey",
  computer_access_status: "Inspect computer access policy",
  computer_file_stat: "Inspect computer path",
  computer_directory_list: "List computer directory",
  computer_text_read: "Read computer text",
  computer_search: "Search computer files",
  computer_processes: "List system processes",
  computer_terminate_process: "Terminate system process",
  computer_text_write: "Write computer text",
  computer_text_patch: "Patch computer text",
  computer_directory_create: "Create computer directory",
  computer_path_move: "Move computer path",
  computer_path_remove: "Remove computer path",
  artifacts_list: "List project artifacts",
  artifact_preview: "Preview project artifact",
  blender_status: "Inspect Blender status",
  blender_scene_snapshot: "Inspect Blender scene",
  blender_object_inspect: "Inspect Blender object",
  blender_modeling_schema: "Read Blender modeling capabilities",
  blender_start: "Start or adopt Blender",
  blender_transform: "Transform Blender object",
  blender_create_primitive: "Create Blender primitive",
  blender_apply_material: "Apply Blender material",
  blender_save: "Save Blender project",
};

function toolAnnotations(name: string): JsonObject {
  const readOnly = READ_ONLY_TOOLS.has(name);
  const destructive = DESTRUCTIVE_TOOLS.has(name);
  const nonDestructiveWrite = NON_DESTRUCTIVE_WRITE_TOOLS.has(name);
  const effectClassCount = Number(readOnly) + Number(destructive) + Number(nonDestructiveWrite);
  if (effectClassCount !== 1) {
    throw new Error(`MCP tool must have exactly one explicit effect classification: ${name}`);
  }
  return {
    readOnlyHint: readOnly,
    destructiveHint: destructive,
    openWorldHint: OPEN_WORLD_TOOLS.has(name),
    idempotentHint: readOnly,
  };
}

function toolInvocationText(name: string): { invoking: string; invoked: string } {
  const title = TOOL_TITLES[name] ?? name.replace(/_/g, " ");
  return {
    invoking: `${title}…`.slice(0, 64),
    invoked: `${title} complete`.slice(0, 64),
  };
}

function responseJson(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: {
    "content-type": "application/json; charset=utf-8", "cache-control": "no-store",
  } });
}

function rpcResult(id: unknown, result: unknown): Response {
  return responseJson({ jsonrpc: "2.0", id, result });
}

function rpcError(id: unknown, code: number, message: string, data?: unknown): Response {
  return responseJson({ jsonrpc: "2.0", id: id ?? null, error: { code, message, ...(data === undefined ? {} : { data }) } });
}

async function bodyJson(response: Response): Promise<JsonObject> {
  return await readBoundedJsonObject(response, 2 * 1024 * 1024) ?? {};
}

const ACTION_STATUSES = new Set(["queued", "leased", "running", "succeeded", "failed", "cancelled"]);
export function isProductActionStatus(value: unknown): value is string {
  return typeof value === "string" && ACTION_STATUSES.has(value);
}

function publicErrorCode(value: unknown, fallback: string): string {
  return typeof value === "string" && /^[a-z][a-z0-9_]{1,119}$/.test(value) ? value : fallback;
}

// Shared public projection for HTTP discovery and MCP; never grant resolution.
export function sanitizeTargets(payload: JsonObject): JsonObject {
  if (payload.ok !== true || !Array.isArray(payload.targets)) {
    return { ok: false, error: "targets_invalid_response", targets: [] };
  }
  const rawTargets = payload.targets;
  const boundedText = (value: unknown, limit = 128): string | null =>
    typeof value === "string" && value.length <= limit && !/[\x00-\x1f]/.test(value) ? value : null;
  const timestamp = (value: unknown): string | null => {
    const text = boundedText(value, 40);
    return text && Number.isFinite(Date.parse(text)) ? new Date(text).toISOString() : null;
  };
  const targets = rawTargets.slice(0, 100).flatMap((raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return [];
    const target = raw as JsonObject;
    if (typeof target.device_id !== "string" || !/^[a-zA-Z0-9:_-]{1,128}$/.test(target.device_id)) return [];
    const rawGrants = Array.isArray(target.grants) ? target.grants : [];
    const grants = rawGrants.flatMap((rawGrant) => {
      if (!rawGrant || typeof rawGrant !== "object" || Array.isArray(rawGrant)) return [];
      const grant = rawGrant as JsonObject;
      return [{
        space_id: typeof grant.space_id === "string" ? grant.space_id : null,
        actions: Array.isArray(grant.actions) ? grant.actions.filter((item) => typeof item === "string") : [],
        projects: Array.isArray(grant.projects) ? grant.projects.filter((item) => typeof item === "string") : [],
      }];
    });
    // Canonical PostgreSQL targets use device_name/grant_groups; legacy D1
    // uses name/grants. Both are descriptive projections of authorized rows.
    const rawGroups = Array.isArray(target.grant_groups) ? target.grant_groups : [];
    const grantGroups = rawGroups.slice(0, 128).flatMap((rawGroup) => {
      if (!rawGroup || typeof rawGroup !== "object" || Array.isArray(rawGroup)) return [];
      const group = rawGroup as JsonObject;
      const rawCapabilities = Array.isArray(group.capabilities) ? group.capabilities : [];
      const capabilities = rawCapabilities.slice(0, 128).flatMap((rawCapability) => {
        if (!rawCapability || typeof rawCapability !== "object" || Array.isArray(rawCapability)) return [];
        const item = rawCapability as JsonObject;
        const capability = boundedText(item.capability);
        return capability && ["read", "write"].includes(String(item.access_mode))
          ? [{ capability, access_mode: item.access_mode }] : [];
      });
      return [{
        profile_key: boundedText(group.profile_key),
        space_id: boundedText(group.space_id),
        project_id: boundedText(group.project_id),
        valid_until: timestamp(group.valid_until),
        capabilities,
      }];
    });
    const name = boundedText(target.device_name) ?? boundedText(target.name) ?? "ORDAX device";
    return [{
      device_id: typeof target.device_id === "string" ? target.device_id : "",
      name,
      device_name: name,
      online: typeof target.online === "boolean" ? target.online : null,
      last_seen_at: timestamp(target.last_seen_at),
      device_kind: boundedText(target.device_kind),
      channel: boundedText(target.channel),
      link_id: typeof target.link_id === "string" ? target.link_id : null,
      grants,
      grant_groups: grantGroups,
    }];
  });
  return { ok: payload.ok !== false, targets };
}

function sanitizeActionPayload(payload: JsonObject, requestId?: string): JsonObject {
  const invalid = { ok: false, pending: false, error: "action_status_invalid_response",
    ...(requestId ? { request_id: requestId } : {}) };
  if (payload.ok !== true) return { ...invalid,
    error: publicErrorCode(payload.error, "action_status_invalid_response") };
  const matchesId = (value: unknown): value is string => typeof value === "string"
    && /^[A-Za-z0-9:_-]{1,128}$/.test(value)
    && (!requestId || value === requestId || (isCanonicalUuid(value)
      && isCanonicalUuid(requestId) && value.toLowerCase() === requestId.toLowerCase()));
  if (payload.pending === true && !Object.hasOwn(payload, "action")) {
    if (!matchesId(payload.request_id)) return invalid;
    return {
      ok: payload.ok !== false,
      pending: true,
      request_id: requestId ?? (typeof payload.request_id === "string" ? payload.request_id : ""),
      message: typeof payload.message === "string" ? payload.message : "Action is still running.",
    };
  }
  const rawAction = payload.action;
  if (rawAction && typeof rawAction === "object" && !Array.isArray(rawAction)) {
    const action = rawAction as JsonObject;
    if (!matchesId(action.request_id) || !isProductActionStatus(action.status)
      || typeof action.action !== "string" || action.action.length > 120
      || !/^[a-z][a-z0-9._-]+$/.test(action.action)) return invalid;
    const status = action.status;
    const pending = !["succeeded", "failed", "cancelled"].includes(status);
    const runtimeKind = action.execution_runtime_kind;
    const runtimeVersion = action.execution_agent_version;
    const provenanceUnknown = (runtimeKind === null || runtimeKind === undefined)
      && (runtimeVersion === null || runtimeVersion === undefined);
    const provenanceValid = typeof runtimeKind === "string"
      && ["ordax-os", "desktop-agent", "mobile-client", "other"].includes(runtimeKind)
      && typeof runtimeVersion === "string"
      && runtimeVersion.length >= 1 && runtimeVersion.length <= 80
      && runtimeVersion === runtimeVersion.trim()
      && !/[\x00-\x1f\x7f]/u.test(runtimeVersion);
    if (!provenanceUnknown && !provenanceValid) return invalid;
    return {
      ok: payload.ok !== false,
      pending,
      request_id: requestId ?? (typeof action.request_id === "string" ? action.request_id : ""),
      action: {
        name: typeof action.action === "string" ? action.action : "",
        ...(isCanonicalUuid(action.device_id) ? { device_id: action.device_id } : {}),
        project: typeof action.project === "string" ? action.project : null,
        ...(isCanonicalUuid(action.project_id) ? { project_id: action.project_id } : {}),
        status,
        result: action.result ?? null,
        error_code: typeof action.error_code === "string" ? action.error_code : null,
        runtime_kind: provenanceValid ? runtimeKind : null,
        runtime_version: provenanceValid ? runtimeVersion : null,
      },
    };
  }
  return invalid;
}

function textToolResult(payload: unknown, isError = false): JsonObject {
  const text = JSON.stringify(payload, null, 2);
  const structured = payload && typeof payload === "object" && !Array.isArray(payload) ? payload : { value: payload };
  return { content: [{ type: "text", text }], structuredContent: structured, isError };
}

function cloneWithAuth(source: Request, url: string, method: string, body?: unknown): Request {
  const headers = new Headers();
  const auth = source.headers.get("authorization");
  if (auth) headers.set("authorization", auth);
  if (body !== undefined) headers.set("content-type", "application/json");
  return new Request(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
}

function toolDefinitions(allowedTools?: ReadonlySet<string>): JsonObject[] {
  return TOOLS.filter(tool => !allowedTools || allowedTools.has(tool.name)).map((tool) => {
    const invocation = toolInvocationText(tool.name);
    return {
      name: tool.name,
      title: TOOL_TITLES[tool.name] ?? tool.name.replace(/_/g, " "),
      description: tool.description,
      securitySchemes: [{ type: "oauth2", scopes: OAUTH_SCOPES }],
      annotations: toolAnnotations(tool.name),
      _meta: {
        securitySchemes: [{ type: "oauth2", scopes: OAUTH_SCOPES }],
        ...(tool.name === "ordax_profile" ? { "openai/profile": true } : {}),
        "openai/toolInvocation/invoking": invocation.invoking,
        "openai/toolInvocation/invoked": invocation.invoked,
      },
      inputSchema: {
        type: "object",
        properties: tool.properties ?? {},
        required: tool.required ?? [],
        additionalProperties: false,
      },
      outputSchema: tool.name === "ordax_profile"
        ? {
            type: "object",
            properties: {
              id: { type: "string", minLength: 1, pattern: "\\S", description: "Opaque authenticated account subject ID; not a Profile Pack or Space ID." },
            },
            required: ["id"],
            additionalProperties: false,
          }
        : {
            type: "object",
            additionalProperties: true,
          },
    };
  });
}

function specFor(name: string): ToolSpec | undefined {
  return TOOLS.find((tool) => tool.name === name);
}

type OwnerGrantHint = {
  profile: string;
  surface: string;
};

// Runtime-independent guidance: OS system settings own Native permissions;
// Windows Studio is only the Owner permission UI for the external Runtime.
const COMPUTER_GRANT_SURFACE = "OrdaX OS: Permissões do sistema | Windows: ORDAX Studio > Acesso ao computador";
const BROWSER_GRANT_SURFACE = "OrdaX OS: Permissões do sistema | Windows: ORDAX Studio > Navegador gerenciado";
const APP_INTELLIGENCE_GRANT_SURFACE = "OrdaX OS: Permissões do sistema | Windows: ORDAX Studio > Inteligência de aplicativos";
const PROJECT_GRANT_SURFACE = "OrdaX OS: Permissões do sistema e Spaces | Windows: ORDAX Studio > Autorizações MCP de projetos";

const OWNER_GRANT_HINT_BY_ACTION = new Map<string, OwnerGrantHint>([
  ...[
    "intelligence.app_catalog",
    "intelligence.app_detail",
  ].map((action) => [action, { profile: "app-intelligence-read", surface: APP_INTELLIGENCE_GRANT_SURFACE }] as const),
  ...Object.entries(OWNER_DEVICE_COMPUTER_GRANT_PROFILES).flatMap(([profile, actions]) =>
    actions.map((action) => [action, { profile, surface: COMPUTER_GRANT_SURFACE }] as const),
  ),
  ...[
    "browser.click",
    "browser.list",
    "browser.navigate",
    "browser.screenshot",
    "browser.snapshot",
    "browser.start",
    "browser.status",
    "browser.stop",
    "browser.type",
  ].map((action) => [action, { profile: "project-browser-automation", surface: BROWSER_GRANT_SURFACE }] as const),
  ["terminal.exec"].map((action) =>
    [action, { profile: "project-native-terminal", surface: PROJECT_GRANT_SURFACE }] as const),
  ["process.start", "process.status", "process.list", "process.logs",
    "process.write_stdin", "process.stop"].map((action) =>
    [action, { profile: "project-native-process", surface: PROJECT_GRANT_SURFACE }] as const),
]);

function authorizationHintForAction(action: string): JsonObject | null {
  const hint = OWNER_GRANT_HINT_BY_ACTION.get(action);
  if (!hint) return null;
  const computerAlternative = action.startsWith("computer.")
    ? {
        alternative_owner_profile: "full-computer-control",
        alternative_profile_requires_local_full_access: true,
      }
    : {};
  return {
    required_owner_profile: hint.profile,
    authorization_surface: hint.surface,
    authorization_required: true,
    ...computerAlternative,
  };
}

async function waitForAction(source: Request, requestId: string, timeoutMs: number, handlers: OrdaxMcpHandlers): Promise<JsonObject> {
  const deadline = Date.now() + timeoutMs;
  while (true) {
    const statusRequest = cloneWithAuth(source, new URL(`/v3/product/actions/${requestId}`, source.url).toString(), "GET");
    let statusResponse: Response;
    try { statusResponse = await handlers.getAction(statusRequest, requestId); }
    catch { return { ok: false, pending: false, request_id: requestId, error: "action_status_unavailable" }; }
    const payload = await bodyJson(statusResponse);
    if (!statusResponse.ok) return { ok: false, pending: false, request_id: requestId,
      upstream_status: statusResponse.status, error: "action_status_unavailable" };
    const projected = sanitizeActionPayload(payload, requestId);
    if (projected.ok !== true || projected.pending === false) return projected;
    if (Date.now() >= deadline) return sanitizeActionPayload({ ok: true, pending: true, request_id: requestId, message: "Action is still running; call ordax_action_status with this request_id." }, requestId);
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

async function callTool(source: Request, name: string, args: JsonObject, handlers: OrdaxMcpHandlers, advertisedToolCount: number): Promise<JsonObject> {
  if (name === "ordax_session") {
    const response = await handlers.session(cloneWithAuth(source, new URL("/v3/product/session", source.url).toString(), "GET"));
    const payload = await bodyJson(response);
    const authenticated = response.ok && payload.ok === true;
    return textToolResult(
      authenticated
        ? {
            ok: true,
            authenticated: true,
            mcp_tool_surface_revision: MCP_TOOL_SURFACE_REVISION,
            mcp_tool_count: advertisedToolCount,
          }
        : {
            ok: false,
            authenticated: false,
            error: "authentication_required",
            mcp_tool_surface_revision: MCP_TOOL_SURFACE_REVISION,
            mcp_tool_count: advertisedToolCount,
          },
      !authenticated,
    );
  }
  if (name === "ordax_profile") {
    const response = await handlers.session(cloneWithAuth(source, new URL("/v3/product/session", source.url).toString(), "GET"));
    const payload = await bodyJson(response);
    const session = payload.session;
    const subjectId = session && typeof session === "object" && !Array.isArray(session)
      ? (session as JsonObject).subject_id
      : null;
    if (!response.ok || payload.ok !== true || typeof subjectId !== "string" || !subjectId.trim()) {
      return textToolResult({ ok: false, error: "profile_unavailable" }, true);
    }
    return textToolResult({ id: subjectId });
  }
  if (name === "ordax_targets") {
    const response = await handlers.targets(cloneWithAuth(source, new URL("/v3/product/targets", source.url).toString(), "GET"));
    const payload = await bodyJson(response);
    const projected = response.ok ? sanitizeTargets(payload) : { ok: false, error: publicErrorCode(payload.error, "targets_unavailable") };
    return textToolResult(projected, projected.ok !== true);
  }
  if (name === "ordax_action_status") {
    const requestId = typeof args.request_id === "string" ? args.request_id : "";
    if (!requestId) return textToolResult({ ok: false, error: "request_id_required" }, true);
    if (!/^[A-Za-z0-9:_-]{1,128}$/.test(requestId)) return textToolResult({ ok: false, error: "product_request_id_invalid" }, true);
    let response: Response;
    try { response = await handlers.getAction(cloneWithAuth(source, new URL(`/v3/product/actions/${requestId}`, source.url).toString(), "GET"), requestId); }
    catch { return textToolResult({ ok: false, pending: false, request_id: requestId, error: "action_status_unavailable" }, true); }
    const payload = await bodyJson(response);
    const projected = response.ok ? sanitizeActionPayload(payload, requestId)
      : { ok: false, pending: false, request_id: requestId, error: "action_status_unavailable" };
    return textToolResult(projected, projected.ok !== true);
  }

  const spec = specFor(name);
  if (!spec?.action) return textToolResult({ ok: false, error: "tool_not_found", tool: name }, true);
  const deviceId = typeof args.device_id === "string" ? args.device_id : "";
  const project = spec.projectRequired && typeof args.project === "string" ? args.project : null;
  // A supplied but invalid Space must never be silently converted into
  // an unscoped action. The canonical Product authority still decides whether
  // the exact UUID is granted; the MCP boundary only validates the input.
  if (Object.prototype.hasOwnProperty.call(args, "space_id") && !isCanonicalUuid(args.space_id)) {
    return textToolResult({ ok: false, error: "space_id_invalid" }, true);
  }
  const spaceId = typeof args.space_id === "string" ? args.space_id : null;
  const rawWait = typeof args.wait_for_completion_ms === "number" && Number.isFinite(args.wait_for_completion_ms) ? args.wait_for_completion_ms : 8000;
  const waitMs = Math.max(0, Math.min(20000, Math.floor(rawWait)));
  const actionArgs: JsonObject = {};
  for (const [key, value] of Object.entries(args)) {
    if (!["device_id", "project", "space_id", "wait_for_completion_ms"].includes(key)) actionArgs[key] = value;
  }
  const createRequest = cloneWithAuth(source, new URL("/v3/product/actions", source.url).toString(), "POST", {
    device_id: deviceId,
    space_id: spaceId,
    action: spec.action,
    project,
    arguments: actionArgs,
  });
  const created = await handlers.createAction(createRequest);
  const createdPayload = await bodyJson(created);
  if (!created.ok) {
    if (spec.projectRequired && createdPayload.error === "product_project_scope_not_found") {
      // A missing Owner-managed Space/project/repository/device association
      // precedes grant evaluation. Never suggest a Windows global grant,
      // fabricate a project ID, or surface private repository metadata.
      return textToolResult({
        ok: false,
        error: "product_project_scope_not_found",
        setup_required: "space_project_repository_device_binding",
        owner_action: "register_project_and_device_in_ordax_owner",
      }, true);
    }
    if (createdPayload.error === "product_grant_not_resolved") {
      const hint = authorizationHintForAction(spec.action);
      return textToolResult({ ok: false, error: "product_grant_not_resolved", ...hint }, true);
    }
    return textToolResult({ ok: false, error: publicErrorCode(createdPayload.error, "product_action_unavailable") }, true);
  }
  const requestId = typeof createdPayload.request_id === "string" ? createdPayload.request_id : "";
  if (createdPayload.ok !== true || !/^[A-Za-z0-9:_-]{1,128}$/.test(requestId)) {
    return textToolResult({ ok: false, error: "product_request_id_missing" }, true);
  }
  const finalPayload = await waitForAction(source, requestId, waitMs, handlers);
  const action = finalPayload.action;
  const failed = finalPayload.ok === false || Boolean(action && typeof action === "object" && !Array.isArray(action) && String((action as JsonObject).status ?? "") !== "succeeded" && !finalPayload.pending);
  return textToolResult(finalPayload, failed);
}

export async function handleOrdaxMcp(request: Request, handlers: OrdaxMcpHandlers, allowedTools?: ReadonlySet<string>): Promise<Response> {
  if (request.method === "GET") return new Response(null, { status: 405, headers: { allow: "POST" } });
  if (request.method !== "POST") return new Response(null, { status: 405, headers: { allow: "GET, POST" } });

  let sessionProbe: Response;
  try { sessionProbe = await handlers.session(cloneWithAuth(request, new URL("/v3/product/session", request.url).toString(), "GET")); }
  catch { return responseJson({ ok: false, error: "product_session_unavailable" }, 503); }
  if (!sessionProbe.ok) {
    const headers = new Headers(sessionProbe.headers);
    headers.set("www-authenticate", `Bearer resource_metadata="${new URL("/.well-known/oauth-protected-resource", request.url).toString()}"`);
    return new Response(sessionProbe.body, { status: sessionProbe.status, headers });
  }
  const sessionPayload = await bodyJson(sessionProbe);
  if (sessionPayload.ok !== true) return responseJson({ ok: false, error: "product_session_invalid_response" }, 503);

  let message: JsonObject;
  try {
    const raw = await readBoundedJsonObject(request, 1024 * 1024);
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("invalid");
    message = raw as JsonObject;
  } catch {
    return rpcError(null, -32700, "Parse error");
  }
  if (message.jsonrpc !== "2.0" || typeof message.method !== "string") return rpcError(message.id, -32600, "Invalid Request");
  const id = message.id;
  const method = message.method;
  if (method === "notifications/initialized") return new Response(null, { status: 202 });
  if (method === "ping") return rpcResult(id, {});
  if (method === "initialize") return rpcResult(id, {
    protocolVersion: "2025-06-18",
    capabilities: { tools: { listChanged: false } },
    serverInfo: { name: "OrdaX Platform", version: "0.5.0" },
    instructions: "Use OrdaX Platform MCP only when the user asks to work with an authorized OrdaX device or one of its registered projects. List authorized devices before project-scoped work when the target is unknown. The device hosting this conversation is not automatically the execution target. Select the user's intended device and project; do not silently switch targets. Device kind, account login and reported presence do not grant file, desktop or mobile capabilities. Use only tools authorized and supported by the selected device; do not infer phone file or sensor access from a mobile catalog entry. A cloud-hosted conversation, stored file or GitHub repository does not establish a cloud executor. Respect project boundaries and the user's explicit intent. Write, execute, Git and Blender mutation tools remain grant- and audit-protected by the ORDAX Runtime.",
  });
  if (method === "tools/list") return rpcResult(id, { tools: toolDefinitions(allowedTools) });
  if (method === "tools/call") {
    const params = message.params;
    if (!params || typeof params !== "object" || Array.isArray(params)) return rpcError(id, -32602, "Invalid params");
    const name = typeof (params as JsonObject).name === "string" ? String((params as JsonObject).name) : "";
    const rawArgs = (params as JsonObject).arguments;
    const args = rawArgs && typeof rawArgs === "object" && !Array.isArray(rawArgs) ? rawArgs as JsonObject : {};
    if (!specFor(name) || (allowedTools && !allowedTools.has(name))) return rpcError(id, -32601, "Tool not found", { tool: name });
    try {
      return rpcResult(id, await callTool(request, name, args, handlers, toolDefinitions(allowedTools).length));
    } catch {
      return rpcResult(id, textToolResult({ ok: false, error: "ordax_mcp_internal_error" }, true));
    }
  }
  return rpcError(id, -32601, "Method not found");
}
