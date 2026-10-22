/**
 * Project-First M1 resource-grant PROJECTION ONLY.
 *
 * This function may consume only a PostgreSQL-authenticated, server-owned grant
 * row and a server-owned canonical subject/project/device context. It does NOT
 * issue grants, resolve a local filesystem path, create an MCP action, or make
 * a UI-/LLM-supplied ID authoritative. A real SQL RPC and Runtime picker are
 * prerequisites before connecting this to any live Product endpoint.
 */
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";

export type WorkspaceGrantScope = Readonly<{
  ownerUserId: string;
  spaceId: string;
  projectId: string; // canonical Product project UUID, not the Lab project ID
  labProjectId: string; // untrusted local ID, bound by a server-side ownership record
  actorId: string;
  clientId: string; // registered exact Product client UUID
  workspaceSessionId: string;
  deviceId: string;
  resourceId: string;
}>;

export type WorkspaceGrantRow = Readonly<{
  grant_id: string;
  owner_user_id: string;
  space_id: string;
  project_id: string;
  lab_project_id: string;
  actor_id: string;
  client_id: string;
  workspace_session_id: string;
  device_id: string;
  resource_id: string;
  allowed_actions: readonly string[];
  issued_by: "trusted-runtime-picker";
  valid_until: string;
  revoked_at: string | null;
  active: boolean;
}>;

export type VerifiedWorkspaceGrant = Readonly<{
  authorized: true;
  projectId: string;
  actorId: string;
  clientId: string;
  workspaceSessionId: string;
  deviceId: string;
  resourceId: string;
  expiresAt: string;
}>;

const LAB_ID = /^[A-Za-z0-9_-]{1,180}$/;
const RESOURCE_ID = /^resource_[A-Za-z0-9_-]{8,160}$/;

const obj = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const time = (value: unknown): number | null => {
  if (typeof value !== "string" || value.length < 20 || value.length > 40
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
};
const same = (value: unknown, trusted: string): boolean =>
  typeof value === "string" && value === trusted;

/**
 * Returns null unless a preexisting trusted DB projection exactly matches an
 * independently attested caller scope. This is an additional shape/expiry
 * check, NOT authorization: the SQL owner must verify membership, device,
 * consent, actor/client, resource ownership and revocation on every read.
 */
export function projectWorkspaceGrantProjection(
  raw: unknown,
  trusted: WorkspaceGrantScope,
  nowMs: number,
): VerifiedWorkspaceGrant | null {
  if (!obj(raw) || !obj(trusted) || !Number.isFinite(nowMs)
    || !isCanonicalUuid(trusted.ownerUserId)
    || !isCanonicalUuid(trusted.spaceId)
    || !isCanonicalUuid(trusted.projectId)
    || !isCanonicalUuid(trusted.actorId)
    || !isCanonicalUuid(trusted.clientId)
    || !isCanonicalUuid(trusted.deviceId)
    || !LAB_ID.test(trusted.labProjectId)
    || !LAB_ID.test(trusted.workspaceSessionId)
    || !RESOURCE_ID.test(trusted.resourceId)) return null;

  const r = raw as Record<string, unknown>;
  if (!isCanonicalUuid(r.grant_id)
    || !same(r.owner_user_id, trusted.ownerUserId)
    || !same(r.space_id, trusted.spaceId)
    || !same(r.project_id, trusted.projectId)
    || !same(r.lab_project_id, trusted.labProjectId)
    || !same(r.actor_id, trusted.actorId)
    || !same(r.client_id, trusted.clientId)
    || !same(r.workspace_session_id, trusted.workspaceSessionId)
    || !same(r.device_id, trusted.deviceId)
    || !same(r.resource_id, trusted.resourceId)
    || r.active !== true
    || r.revoked_at !== null
    || r.issued_by !== "trusted-runtime-picker"
    || !Array.isArray(r.allowed_actions)
    || r.allowed_actions.length !== 1 || r.allowed_actions[0] !== "read"
  ) return null;

  const expiry = time(r.valid_until);
  // A local resource binding always expires; no infinite / null grants.
  // Limit exposure if an upstream query supplies a malformed lifetime.
  if (expiry === null || expiry <= nowMs || expiry > nowMs + 24 * 60 * 60 * 1000)
    return null;
  return Object.freeze({
    authorized: true as const,
    projectId: trusted.labProjectId,
    actorId: trusted.actorId,
    clientId: trusted.clientId,
    workspaceSessionId: trusted.workspaceSessionId,
    deviceId: trusted.deviceId,
    resourceId: trusted.resourceId,
    expiresAt: new Date(expiry).toISOString(),
  });
}
