export type ProductActionScope = "device" | "project";

/**
 * Canonical action-scope boundary used by Product grants.
 *
 * Device-scoped actions operate on the linked device itself and must not need a
 * synthetic project id. Project-scoped actions remain bound to an explicit
 * registered project grant.
 *
 * Keep this list explicit: adding a new remote Computer capability requires a
 * reviewed scope decision instead of inheriting authority from a prefix match.
 */
export const PROJECT_BROWSER_ACTIONS = new Set<string>([
  "browser.click",
  "browser.list",
  "browser.navigate",
  "browser.screenshot",
  "browser.snapshot",
  "browser.start",
  "browser.tab_open",
  "browser.tabs",
  "browser.status",
  "browser.stop",
  "browser.type",
]);

/**
 * Project Blender actions use the attested Project Catalog link. Device Blender
 * uses separate capability identities and grants, with the same typed operations.
 */
export const PROJECT_BLENDER_ACTIONS = new Set<string>([
  "blender.live_status",
  "blender.live_scene_snapshot",
  "blender.live_object_inspect",
  "blender.live_modeling_schema",
  "blender.live_start",
  "blender.live_object_transform",
  "blender.live_create_primitive",
  "blender.live_rig_create",
  "blender.live_material_apply",
  "blender.live_save",
]);

// Separate capability identities prevent a project grant from becoming a device grant.
export const DEVICE_BLENDER_ACTIONS = new Set<string>(
  [...PROJECT_BLENDER_ACTIONS].map(action => action.replace("blender.live_", "computer.blender_")),
);
export function deviceBlenderAction(projectAction: string): string | null {
  return PROJECT_BLENDER_ACTIONS.has(projectAction)
    ? projectAction.replace("blender.live_", "computer.blender_") : null;
}
/** Read-only image and metadata actions confined to an attested Project Artifacts root. */
export const PROJECT_ARTIFACT_ACTIONS = new Set<string>(["artifacts.list", "artifact.preview"]);
export const PROJECT_LOCAL_SERVICE_ACTIONS = new Set<string>(["artifact.local_service_preview"]);

export const PROJECT_CONTINUITY_ACTIONS = new Set<string>([
  "agent.project_briefing", "continuity.get", "continuity.update", "handoff.create", "handoff.get",
]);
export const REPOSITORY_CATALOG_DEVICE_ACTIONS = new Set<string>([
  "workspace.repository_catalog",
]);

export const APP_INTELLIGENCE_DEVICE_ACTIONS = new Set<string>([
  "intelligence.app_catalog",
  "intelligence.app_detail",
]);

// OS-owned Aura and MCP consult the same bounded, current-account Intelligence.
// No tool execution, model selection or Memory writes are granted here.
export const NATIVE_INTELLIGENCE_DEVICE_ACTIONS = new Set<string>([
  "ordax.intelligence.respond",
]);

export const NATIVE_SURFACE_DEVICE_ACTIONS = new Set<string>([
  "ordax.surface.status",
  "ordax.surface.open",
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
  "computer.process_start",
  "computer.process_status",
  "computer.process_list",
  "computer.process_logs",
  "computer.process_write_stdin",
  "computer.process_stop",
  "computer.screen_info",
  "computer.screenshot",
  "computer.scroll",
  "computer.search",
  "computer.terminate_process",
  "computer.terminal_exec",
  "computer.text_patch",
  "computer.text_read",
  "computer.text_write",
  "computer.transfer_begin",
  "computer.transfer_chunk",
  "computer.transfer_status",
  "computer.transfer_commit",
  "computer.transfer_abort",
  "computer.type",
  "computer.windows",
]);

export const USB_MEDIA_DEVICE_ACTIONS = new Set<string>([
  "usb.list",
  "usb.inspect",
]);

export const DEVICE_SCOPED_ACTIONS = new Set<string>([
  ...USB_MEDIA_DEVICE_ACTIONS,
  "forge.app_read",
  ...COMPUTER_DEVICE_ACTIONS,
  ...DEVICE_BLENDER_ACTIONS,
  ...APP_INTELLIGENCE_DEVICE_ACTIONS,
  ...NATIVE_SURFACE_DEVICE_ACTIONS,
  ...NATIVE_INTELLIGENCE_DEVICE_ACTIONS,
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
export const TEXT_EDIT_COMPUTER_CONTROL_MODE = "computer-text-edit";
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
  // Independent least-privilege grant: text read/write/patch only. No delete,
  // move, arbitrary process, shell, browser, or unbounded filesystem access.
  [TEXT_EDIT_COMPUTER_CONTROL_MODE]: [
    "computer.directory_list",
    "computer.file_stat",
    "computer.text_read",
    "computer.text_write",
    "computer.transfer_begin",
    "computer.transfer_chunk",
    "computer.transfer_status",
    "computer.transfer_commit",
    "computer.transfer_abort",
    "computer.text_patch",
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
    "computer.transfer_begin",
    "computer.transfer_chunk",
    "computer.transfer_status",
    "computer.transfer_commit",
    "computer.transfer_abort",
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
