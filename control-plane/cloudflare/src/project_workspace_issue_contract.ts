/** Strict input shape for the existing Owner and enrolled Device transports.
 * Only PostgreSQL can issue a resource; these parsers never authorize one.
 * Owner subject and Device identity come from independently authenticated
 * canonical transports, never any caller JSON.
 */
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";

export type OwnerWorkspaceApproval = Readonly<{
  clientId: string;
  labProjectId: string;
  spaceId: string;
  projectId: string;
  deviceId: string;
  actorId: string;
  workspaceSessionId: string;
  resourceId: string;
  intentId: string;
}>;
export type DeviceWorkspaceConfirmation = Readonly<{
  intentId: string;
  actorId: string;
  clientId: string;
  workspaceSessionId: string;
  resourceId: string;
}>;

const OWNER_KEYS = new Set([
  "client_id", "lab_project_id", "space_id", "project_id", "device_id",
  "actor_id", "workspace_session_id", "resource_id", "intent_id",
]);
const DEVICE_KEYS = new Set([
  "intent_id", "actor_id", "client_id", "workspace_session_id", "resource_id",
]);
const localId = (v: unknown): v is string =>
  typeof v === "string" && /^[A-Za-z0-9_-]{1,180}$/.test(v);
const opaque = (v: unknown): v is string =>
  typeof v === "string" && /^resource_[A-Za-z0-9_-]{8,160}$/.test(v);
function exact(value: unknown, fields: Set<string>): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === fields.size
    && Object.keys(value).every(key => fields.has(key));
}

export function canonicalOwnerWorkspaceApproval(value: unknown): OwnerWorkspaceApproval | null {
  if (!exact(value, OWNER_KEYS)) return null;
  if (!isCanonicalUuid(value.client_id)
      || !isCanonicalUuid(value.space_id)
      || !isCanonicalUuid(value.project_id)
      || !isCanonicalUuid(value.device_id)
      || !isCanonicalUuid(value.actor_id)
      || !isCanonicalUuid(value.intent_id)
      || !localId(value.lab_project_id)
      || !localId(value.workspace_session_id)
      || !opaque(value.resource_id)) return null;
  return Object.freeze({
    clientId: value.client_id, labProjectId: value.lab_project_id,
    spaceId: value.space_id, projectId: value.project_id,
    deviceId: value.device_id, actorId: value.actor_id,
    workspaceSessionId: value.workspace_session_id,
    resourceId: value.resource_id, intentId: value.intent_id,
  });
}

export function canonicalDeviceWorkspaceConfirmation(
  value: unknown,
): DeviceWorkspaceConfirmation | null {
  if (!exact(value, DEVICE_KEYS)) return null;
  if (!isCanonicalUuid(value.intent_id)
      || !isCanonicalUuid(value.actor_id)
      || !isCanonicalUuid(value.client_id)
      || !localId(value.workspace_session_id)
      || !opaque(value.resource_id)) return null;
  return Object.freeze({
    intentId: value.intent_id, actorId: value.actor_id,
    clientId: value.client_id, workspaceSessionId: value.workspace_session_id,
    resourceId: value.resource_id,
  });
}
