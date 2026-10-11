/**
 * Deterministic, fail-closed Product Relay target projection.
 * The input MUST be the canonical owner + exact-client target RPC result.
 * No model-selected device, UI slug, local device cache or legacy D1 fallback.
 */
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";

export const RELAY_PROJECT_READ_CAPABILITIES = new Set<string>([
  "project.text_read",
  "workspace.directory_list",
  "workspace.file_stat",
  "workspace.text_read",
]);

export type ProductRelayProjectScope = Readonly<{
  deviceId: string;
  spaceId: string;
  projectId: string;
  allowedActions: readonly string[];
}>;

function record(item: unknown): item is Record<string, unknown> {
  return Boolean(item) && typeof item === "object" && !Array.isArray(item);
}

/**
 * A trusted host may explicitly bind a device when the same owner/client has
 * several authorized devices. Without a host binding, ambiguity is denied:
 * the model and the MCP request body may never pick the first target.
 */
export function selectCanonicalRelayProjectScope(
  catalog: unknown, trustedDeviceId?: string,
): ProductRelayProjectScope | null {
  if (!record(catalog) || catalog.ok !== true || !Array.isArray(catalog.targets)
    || catalog.targets.length < 1 || catalog.targets.length > 128
    || (trustedDeviceId !== undefined && !isCanonicalUuid(trustedDeviceId))) return null;
  const ids = new Set<string>();
  for (const value of catalog.targets) {
    if (!record(value) || !isCanonicalUuid(value.device_id)
      || ids.has(value.device_id.toLowerCase())) return null;
    ids.add(value.device_id.toLowerCase());
  }
  if (trustedDeviceId === undefined && catalog.targets.length !== 1) return null;
  const matching = trustedDeviceId === undefined
    ? catalog.targets
    : catalog.targets.filter(target =>
      (target as Record<string,unknown>).device_id === trustedDeviceId
      || String((target as Record<string,unknown>).device_id).toLowerCase() === trustedDeviceId.toLowerCase());
  if (matching.length !== 1 || !record(matching[0])) return null;
  const target = matching[0];
  if (!isCanonicalUuid(target.device_id) || !Array.isArray(target.grant_groups)
    || target.grant_groups.length < 1 || target.grant_groups.length > 128) return null;

  const eligible: ProductRelayProjectScope[] = [];
  for (const value of target.grant_groups) {
    if (!record(value) || !Array.isArray(value.capabilities)
      || value.capabilities.length < 1 || value.capabilities.length > 128) return null;
    const expires = value.valid_until;
    if (expires !== undefined && expires !== null
      && (typeof expires !== "string" || !Number.isFinite(Date.parse(expires)))) return null;
    // A stale projection cannot grant access past a canonical grant deadline.
    if (typeof expires === "string" && Date.parse(expires) <= Date.now()) return null;
    if (!isCanonicalUuid(value.project_id) || !isCanonicalUuid(value.space_id)) continue;
    const allowed: string[] = [];
    const seen = new Set<string>();
    for (const entry of value.capabilities) {
      if (!record(entry) || typeof entry.capability !== "string"
        || (entry.access_mode !== "read" && entry.access_mode !== "write")
        || seen.has(entry.capability)) return null;
      seen.add(entry.capability);
      if (entry.access_mode === "read" && RELAY_PROJECT_READ_CAPABILITIES.has(entry.capability)) {
        allowed.push(entry.capability);
      }
    }
    if (allowed.length > 0) {
      eligible.push(Object.freeze({
        deviceId: target.device_id,
        spaceId: value.space_id,
        projectId: value.project_id,
        allowedActions: Object.freeze([...allowed].sort()),
      }));
    }
  }
  // Never pick an arbitrary project or device in the presence of ambiguity.
  return eligible.length === 1 ? eligible[0] : null;
}
