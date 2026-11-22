import { isCanonicalUuid } from "./product_remote_grant_contract.ts";

/**
 * An authenticated Runtime reports its ActionRegistry through canonical
 * PostgreSQL presence. This is availability ONLY, never authorization.
 *
 * Old/unreported registries remain "unverified" and retain the existing
 * grant + final PostgreSQL enqueue authority during component rollout.
 * A malformed report fails closed instead of silently becoming unverified.
 */
export function runtimeCapabilityAvailability(
  catalog: unknown, deviceId: string, action: string,
): "available" | "unavailable" | "unverified" {
  if (!isCanonicalUuid(deviceId) || typeof action !== "string"
      || !catalog || typeof catalog !== "object" || Array.isArray(catalog)) return "unavailable";
  const record = catalog as Record<string, unknown>;
  if (record.ok !== true || !Array.isArray(record.targets)) return "unavailable";
  const targets = record.targets.filter(value =>
    value !== null && typeof value === "object" && !Array.isArray(value)
    && (value as Record<string, unknown>).device_id === deviceId);
  if (targets.length !== 1) return "unavailable";
  const target = targets[0] as Record<string, unknown>;
  if (target.runtime_capabilities === null || target.runtime_capabilities === undefined)
    return "unverified";
  if (!Array.isArray(target.runtime_capabilities)
      || target.runtime_capabilities.length < 1
      || target.runtime_capabilities.length > 1024) return "unavailable";
  let previous = "";
  for (const name of target.runtime_capabilities) {
    if (typeof name !== "string" || !/^[a-z][a-z0-9._-]{0,159}$/.test(name)
        || (previous && previous >= name)) return "unavailable";
    previous = name;
  }
  return target.runtime_capabilities.includes(action) ? "available" : "unavailable";
}
