export type ProductActionScope = "device" | "project";

/**
 * Canonical action-scope boundary used by Product grants.
 *
 * Device-scoped actions operate on the linked device itself and must not need a
 * synthetic project id. Project-scoped actions remain bound to an explicit
 * registered project grant.
 *
 * Keep this list explicit: adding a new remote capability requires a reviewed
 * scope decision instead of inheriting authority from a prefix match.
 */
export const PROJECT_BROWSER_ACTIONS = new Set<string>([
  "browser.click",
  "browser.list",
  "browser.navigate",
  "browser.screenshot",
  "browser.snapshot",
  "browser.start",
  "browser.status",
  "browser.stop",
  "browser.type",
]);

export const PROJECT_CONTINUITY_ACTIONS = new Set<string>([
  "agent.project_briefing",
  "continuity.get",
  "continuity.update",
  "handoff.create",
  "handoff.get",
]);

export const REPOSITORY_CATALOG_DEVICE_ACTIONS = new Set<string>([
  "workspace.repository_catalog",
]);

export const APP_INTELLIGENCE_DEVICE_ACTIONS = new Set<string>([
  "intelligence.app_catalog",
  "intelligence.app_detail",
]);

export const COMPUTER_DEVICE_ACTIONS = new Set<string>([
  "computer.access_status",
  "computer.active_window",
  "computer.click",
  "computer.clipboard_read",
  "computer.clipboard_write",
  "computer.directory_create",
  "computer.directory_list",
  "computer.drag",
  "computer.file_stat",
  "computer.focus_window",
  "computer.hotkey",
  "computer.launch_app",
  "computer.mouse_move",
  "computer.path_move",
  "computer.path_remove",
  "computer.processes",
  "computer.screen_info",
  "computer.screenshot",
  "computer.scroll",
  "computer.search",
  "computer.terminate_process",
  "computer.text_patch",
  "computer.text_read",
  "computer.text_write",
  "computer.type",
  "computer.windows",
]);

export const DEVICE_SCOPED_ACTIONS = new Set<string>([
  ...COMPUTER_DEVICE_ACTIONS,
  ...APP_INTELLIGENCE_DEVICE_ACTIONS,
  ...REPOSITORY_CATALOG_DEVICE_ACTIONS,
]);

export function isDeviceScopedAction(action: string): boolean {
  return DEVICE_SCOPED_ACTIONS.has(action);
}

export function productActionScope(
  action: string,
  projectScopedActions: ReadonlySet<string>,
): ProductActionScope {
  if (DEVICE_SCOPED_ACTIONS.has(action)) return "device";
  return projectScopedActions.has(action) ? "project" : "device";
}

/**
 * Enforces the canonical project binding shape before grant resolution.
 *
 * Device actions must use project=null. Project actions must provide a concrete
 * project. This prevents fake project ids from being used to model device
 * authority and prevents a project action from silently degrading to a device
 * grant.
 */
export function projectBindingMatchesScope(
  action: string,
  project: string | null,
  projectScopedActions: ReadonlySet<string>,
): boolean {
  const scope = productActionScope(action, projectScopedActions);
  return scope === "device" ? project === null : project !== null;
}

/** MCP authorization profile hints; not grant writers or an authorization authority. */
export const INTERACTIVE_COMPUTER_CONTROL_MODE = "interactive-computer-control";
export const FILESYSTEM_COMPUTER_CONTROL_MODE = "computer-filesystem";
export const CLIPBOARD_COMPUTER_CONTROL_MODE = "computer-clipboard";
export const PROCESS_COMPUTER_CONTROL_MODE = "computer-process-control";
export const OBSERVE_COMPUTER_CONTROL_MODE = "computer-observe";
const MAX_BODY_BYTES = 16 * 1024;

export const OWNER_DEVICE_COMPUTER_GRANT_PROFILES: Readonly<Record<string, readonly string[]>> = {
  [INTERACTIVE_COMPUTER_CONTROL_MODE]: [
    "computer.access_status",
    "computer.active_window",
    "computer.click",
    "computer.drag",
    "computer.focus_window",
    "computer.hotkey",
    "computer.launch_app",
    "computer.mouse_move",
    "computer.processes",
    "computer.screen_info",
    "computer.screenshot",
    "computer.scroll",
    "computer.type",
    "computer.windows",
  ],
  [FILESYSTEM_COMPUTER_CONTROL_MODE]: [
    "computer.access_status",
    "computer.directory_create",
    "computer.directory_list",
    "computer.file_stat",
    "computer.path_move",
    "computer.path_remove",
    "computer.search",
    "computer.text_patch",
    "computer.text_read",
    "computer.text_write",
  ],
  [CLIPBOARD_COMPUTER_CONTROL_MODE]: [
    "computer.clipboard_read",
    "computer.clipboard_write",
  ],
  [PROCESS_COMPUTER_CONTROL_MODE]: [
    "computer.processes",
    "computer.terminate_process",
  ],
  // Least-privilege observation profile for attested Product-MCP sessions.
  // Keep this entry last so authorization hints prefer it over broader profiles
  // for capabilities shared with interactive/process-control grants.
  [OBSERVE_COMPUTER_CONTROL_MODE]: [
    "computer.access_status",
    "computer.active_window",
    "computer.processes",
    "computer.screen_info",
    "computer.windows",
  ],
};
