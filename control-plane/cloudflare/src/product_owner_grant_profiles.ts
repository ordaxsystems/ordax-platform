import {
  APP_INTELLIGENCE_DEVICE_ACTIONS,
  COMPUTER_DEVICE_ACTIONS,
  OWNER_DEVICE_COMPUTER_GRANT_PROFILES,
  PROJECT_BROWSER_ACTIONS,
} from "./product_action_scope.ts";

export type OwnerGrantProfile = Readonly<{
  scope: "device" | "project";
  capabilities: readonly Readonly<{ capability: string; accessMode: "read" | "write" }>[];
}>;

const WRITE_ACTIONS = new Set<string>([
  "computer.click", "computer.clipboard_write", "computer.directory_create",
  "computer.drag", "computer.focus_window", "computer.hotkey", "computer.launch_app",
  "computer.mouse_move", "computer.path_move", "computer.path_remove", "computer.scroll",
  "computer.terminate_process", "computer.text_patch", "computer.text_write", "computer.type",
  "browser.click", "browser.navigate", "browser.start", "browser.stop", "browser.type",
  "terminal.exec", "process.start", "process.write_stdin", "process.stop",
]);

export function productCapabilityAccessMode(capability: string): "read" | "write" {
  return WRITE_ACTIONS.has(capability) ? "write" : "read";
}

function profile(scope: "device" | "project", capabilities: Iterable<string>): OwnerGrantProfile {
  const names = [...new Set(capabilities)].sort();
  return Object.freeze({
    scope,
    capabilities: Object.freeze(names.map((capability) => Object.freeze({
      capability, accessMode: productCapabilityAccessMode(capability),
    }))),
  });
}

const fullComputer = profile("device", COMPUTER_DEVICE_ACTIONS);
const computerProfiles = Object.fromEntries(Object.entries(OWNER_DEVICE_COMPUTER_GRANT_PROFILES)
  .map(([key, capabilities]) => [key, profile("device", capabilities)]));

export const OWNER_MCP_GRANT_PROFILES: Readonly<Record<string, OwnerGrantProfile>> = Object.freeze({
  "full-computer-control": fullComputer,
  ...computerProfiles,
  "app-intelligence-read": profile("device", APP_INTELLIGENCE_DEVICE_ACTIONS),
  "project-browser-automation": profile("project", PROJECT_BROWSER_ACTIONS),
  "project-native-terminal": profile("project", ["terminal.exec"]),
  "project-native-process": profile("project", [
    "process.start", "process.status", "process.list", "process.logs",
    "process.write_stdin", "process.stop",
  ]),
});

export function ownerMcpGrantProfile(key: string): OwnerGrantProfile | null {
  return OWNER_MCP_GRANT_PROFILES[key] ?? null;
}
