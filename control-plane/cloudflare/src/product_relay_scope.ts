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

// Device grants (null Space and null project) are distinct from grants that
// permit project data. Only low-risk, read-only PC metadata is exposed here.
// A grant to inspect the computer NEVER authorizes access to project files.
export const RELAY_DEVICE_READ_CAPABILITIES = new Set<string>([
  "computer.access_status",
  "computer.active_window",
  "computer.processes",
  "computer.screen_info",
  "computer.windows",
]);

export type ProductRelayProjectScope = Readonly<{
  deviceId: string;
  spaceId: string;
  projectId: string;
  allowedActions: readonly string[];
}>;

export type ProductRelayDeviceScope = Readonly<{
  deviceId: string;
  spaceId: null;
  projectId: null;
  allowedActions: readonly string[];
}>;

function record(item: unknown): item is Record<string, unknown> {
  return Boolean(item) && typeof item === "object" && !Array.isArray(item);
}

/**
 * Only a Product-authorized target projection may be supplied here.
 * Optional trustedDeviceId is server-owned and must be attested by a durable
 * request/session record; it is never read from a model/tool argument.
 *
 * Without such binding there MUST be precisely one target for the client.
 */
function selectedCanonicalTarget(
  catalog: unknown, trustedDeviceId?: string,
): Record<string, unknown> | null {
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
  const matches = trustedDeviceId === undefined
    ? catalog.targets
    : catalog.targets.filter(value =>
        (value as Record<string, unknown>).device_id.toString().toLowerCase()
        === trustedDeviceId.toLowerCase());
  if (matches.length !== 1 || !record(matches[0])) return null;
  const target = matches[0];
  return Array.isArray(target.grant_groups)
    && target.grant_groups.length >= 1 && target.grant_groups.length <= 128
    ? target : null;
}

// Null means invalid/untrusted grant projection, [] means a valid grant with
// no capability in the current read-only allowlist.
function readCapabilities(value: unknown, allowed: ReadonlySet<string>): string[] | null {
  if (!record(value) || !Array.isArray(value.capabilities)
    || value.capabilities.length < 1 || value.capabilities.length > 128) return null;
  const expires = value.valid_until;
  if (expires !== undefined && expires !== null
    && (typeof expires !== "string" || !Number.isFinite(Date.parse(expires)))) return null;
  if (typeof expires === "string" && Date.parse(expires) <= Date.now()) return null;
  const found: string[] = [];
  const seen = new Set<string>();
  for (const entry of value.capabilities) {
    if (!record(entry) || typeof entry.capability !== "string"
      || (entry.access_mode !== "read" && entry.access_mode !== "write")
      || seen.has(entry.capability)) return null;
    seen.add(entry.capability);
    if (entry.access_mode === "read" && allowed.has(entry.capability))
      found.push(entry.capability);
  }
  return found.sort();
}

/**
 * Resolve one unambiguous PROJECT scope, never silently fallback to a device
 * grant. The model cannot select a project or a PC from target discovery.
 */
export function selectCanonicalRelayProjectScope(
  catalog: unknown, trustedDeviceId?: string,
): ProductRelayProjectScope | null {
  const target = selectedCanonicalTarget(catalog, trustedDeviceId);
  if (!target) return null;
  const eligible: ProductRelayProjectScope[] = [];
  for (const group of target.grant_groups as unknown[]) {
    const allowed = readCapabilities(group, RELAY_PROJECT_READ_CAPABILITIES);
    if (allowed === null) return null;
    if (!record(group) || !isCanonicalUuid(group.project_id)
      || !isCanonicalUuid(group.space_id)) continue;
    if (allowed.length > 0) eligible.push(Object.freeze({
      deviceId: target.device_id as string,
      spaceId: group.space_id,
      projectId: group.project_id,
      allowedActions: Object.freeze(allowed),
    }));
  }
  return eligible.length === 1 ? eligible[0] : null;
}

/**
 * Resolve one device-scoped, NULL-Space/NULL-project read grant. A project
 * grant can never stand in for device authority (and vice versa).
 *
 * Read-only metadata, NOT new action enqueue permission. Revocation is
 * re-evaluated by the canonical PostgreSQL target RPC on each operation.
 */
export function selectCanonicalRelayDeviceScope(
  catalog: unknown, trustedDeviceId?: string,
): ProductRelayDeviceScope | null {
  const target = selectedCanonicalTarget(catalog, trustedDeviceId);
  if (!target) return null;
  const eligible: ProductRelayDeviceScope[] = [];
  for (const group of target.grant_groups as unknown[]) {
    const allowed = readCapabilities(group, RELAY_DEVICE_READ_CAPABILITIES);
    if (allowed === null) return null;
    if (!record(group) || group.scope_kind !== "device"
      || group.space_id !== null || group.project_id !== null) continue;
    if (allowed.length > 0) eligible.push(Object.freeze({
      deviceId: target.device_id as string,
      spaceId: null,
      projectId: null,
      allowedActions: Object.freeze(allowed),
    }));
  }
  return eligible.length === 1 ? eligible[0] : null;
}
