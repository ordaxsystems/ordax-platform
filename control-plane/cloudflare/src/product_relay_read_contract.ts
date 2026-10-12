/**
 * Single read-only action/input boundary consumed by the trusted Relay and
 * the scoped MCP projection. This only validates shape/path: it never
 * authorizes a device, selects a project or grants an action.
 */
import { RELAY_PROJECT_READ_CAPABILITIES } from "./product_relay_scope.ts";

const MAX_PATH = 512;
function validSegment(part: string): boolean {
  return part.length > 0 && part !== "." && part !== ".."
    && !part.endsWith(" ") && !part.endsWith(".")
    && part.normalize("NFKC") === part
    && !/[\\:%\x00-\x1f\x7f\u2215\u2044\uFF0F]/u.test(part)
    && !/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i.test(part);
}

function segments(path: unknown): string[] | null {
  if (typeof path !== "string" || path.length < 1 || path.length > MAX_PATH
    || path.startsWith("/") || path.endsWith("/")) return null;
  const parts = path.split("/");
  return parts.every(validSegment) ? parts : null;
}

/** Fail closed on ambiguous filesystem names, drive syntax and traversal. */
export function canonicalReadPath(path: unknown): path is string {
  return segments(path) !== null;
}

/** A root selected by a trusted resolver is NOT supplied by the model. */
export function canonicalPathWithinRoot(root: unknown, path: unknown): boolean {
  const base = segments(root), requested = segments(path);
  return base !== null && requested !== null && base.length <= requested.length
    && base.every((part, index) => requested[index] === part);
}

/** No remote permission is inferred from this deterministic argument parser. */
export function validCanonicalReadActionArguments(
  action: string, value: unknown, root?: string,
): value is Record<string, unknown> {
  if (!RELAY_PROJECT_READ_CAPABILITIES.has(action)
    || !value || typeof value !== "object" || Array.isArray(value)) return false;
  const data = value as Record<string, unknown>;
  if (!canonicalReadPath(data.path)
    || (root !== undefined && !canonicalPathWithinRoot(root, data.path))) return false;
  const allowed = action === "workspace.directory_list"
    ? ["path", "max_depth", "max_entries", "include_hidden"]
    : action === "workspace.text_read" ? ["path", "start_line", "end_line"] : ["path"];
  for (const [key, field] of Object.entries(data)) {
    if (!allowed.includes(key)) return false;
    if (key === "path") continue;
    if (key === "include_hidden" && typeof field === "boolean") continue;
    if (key === "max_depth" && Number.isInteger(field) && (field as number) >= 1 && (field as number) <= 12) continue;
    if (key === "max_entries" && Number.isInteger(field) && (field as number) >= 1 && (field as number) <= 5000) continue;
    if ((key === "start_line" || key === "end_line")
      && Number.isInteger(field) && (field as number) >= 1 && (field as number) <= 1000000) continue;
    return false;
  }
  return !(typeof data.start_line === "number" && typeof data.end_line === "number"
    && data.start_line > data.end_line);
}
