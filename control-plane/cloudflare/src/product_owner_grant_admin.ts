import { authenticateProductRequest, type ProductAuthEnv } from "./product_auth.ts";
import {
  approveProjectWorkspaceResource,
  listOwnerMcpRemoteAuthority,
  replaceOwnerMcpGrantGroup,
  revokeOwnerMcpGrantGroup,
  revokeProjectWorkspaceResource,
  ProductPostgresError,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { ownerMcpGrantProfile } from "./product_owner_grant_profiles.ts";
import {
  inspectOwnerCentralSessionTargets,
  listOwnerCentralSelections,
  selectOwnerCentralDevice,
} from "./product_central_device_session_store.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { readBoundedJsonObject } from "./request_json.ts";
import { canonicalOwnerWorkspaceApproval } from "./project_workspace_issue_contract.ts";

type Env = ProductAuthEnv & ProductPostgresEnv & {
  CENTRAL_OWNER_TARGET_PREFLIGHT_ENABLED?: string;
  CENTRAL_OWNER_SELECTION_ENABLED?: string;
  PRODUCT_OWNER_OAUTH_CLIENT_ID?: string;
};
type Json = Record<string, unknown>;
const ROOT = "/v3/owner/remote-authority";
export const PRODUCT_OWNER_CENTRAL_SESSION_TARGETS_PATH = "/v3/owner/central-session-targets";
export const PRODUCT_OWNER_CENTRAL_SESSION_SELECTIONS_PATH = "/v3/owner/central-session-selections";
const GROUPS = "/v3/owner/remote-grant-groups";
const WORKSPACE_RESOURCES = "/v3/owner/workspace-resources/";
const WORKSPACE_APPROVALS = WORKSPACE_RESOURCES + "approvals";
const RESOURCE_ID_RE = /^resource_[A-Za-z0-9_-]{8,160}$/;
const CLIENT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PROFILE_KEY_RE = /^[a-z][a-z0-9._-]{1,79}$/;

const json = (body: unknown, status = 200) => Response.json(body, {
  status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
});

/** Strict shape parser only. Ownership comes from the already authenticated
 * Owner session and is checked by the canonical PostgreSQL RPC.
 */
export function parseOwnerWorkspaceResourceRevocation(
  url: URL,
): { clientId: string; resourceId: string } | null {
  if (!url.pathname.startsWith(WORKSPACE_RESOURCES)) return null;
  const resourceId = url.pathname.slice(WORKSPACE_RESOURCES.length);
  const clientId = url.searchParams.get("client_id") ?? "";
  if (!RESOURCE_ID_RE.test(resourceId) || !isCanonicalUuid(clientId)
      || [...url.searchParams.keys()].some(key => key !== "client_id")
      || url.searchParams.getAll("client_id").length !== 1)
    return null;
  return { clientId, resourceId };
}

async function owner(request: Request, env: Env): Promise<string | Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
  if (identity.role !== "authenticated" || !isCanonicalUuid(identity.subjectId))
    return json({ ok: false, error: "product_owner_identity_invalid" }, 403);
  // A delegated Product MCP JWT is NOT an Owner decision. The official
  // Owner CLI uses its own public PKCE client, so do not reject all client_id
  // claims: accept only a first-party account JWT or the explicitly pinned
  // first-party Owner OAuth client configured in canonical Platform metadata.
  if (new URL(request.url).pathname === PRODUCT_OWNER_CENTRAL_SESSION_SELECTIONS_PATH) {
    const pinned = (env.PRODUCT_OWNER_OAUTH_CLIENT_ID ?? "").trim().toLowerCase();
    if (identity.clientId !== null
        && (!isCanonicalUuid(pinned) || identity.clientId.toLowerCase() !== pinned))
      return json({ ok: false, error: "owner_primary_session_required" }, 403);
  }
  return identity.subjectId;
}

function failure(error: unknown): Response {
  if (error instanceof ProductPostgresError) return json({ ok: false, error: error.code }, error.status);
  return json({ ok: false, error: "product_postgres_unavailable" }, 503);
}

function optionalUuid(value: unknown): string | null | undefined {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string" || !isCanonicalUuid(value)) return undefined;
  return value;
}

function validUntil(value: unknown): string | null | undefined {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string" || value.length > 64) return undefined;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || timestamp <= Date.now()
      || timestamp > Date.now() + 365 * 24 * 60 * 60 * 1000) return undefined;
  return new Date(timestamp).toISOString();
}

export async function handleProductOwnerGrantAdmin(
  request: Request, env: Env,
  deps: {
    inspectCentralTargets?: typeof inspectOwnerCentralSessionTargets;
    listSelections?: typeof listOwnerCentralSelections;
    selectDevice?: typeof selectOwnerCentralDevice;
  } = {},
): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname !== ROOT && url.pathname !== PRODUCT_OWNER_CENTRAL_SESSION_TARGETS_PATH
      && url.pathname !== PRODUCT_OWNER_CENTRAL_SESSION_SELECTIONS_PATH
      && !url.pathname.startsWith(GROUPS) && !url.pathname.startsWith(WORKSPACE_RESOURCES))
    return json({ ok: false, error: "not_found" }, 404);

  const ownerId = await owner(request, env);
  if (ownerId instanceof Response) return ownerId;

  try {
    if (url.pathname === PRODUCT_OWNER_CENTRAL_SESSION_SELECTIONS_PATH) {
      // Owner action is separately feature-gated from advisory target reads.
      // The signed Owner session never conveys an implicit action grant.
      if (env.CENTRAL_OWNER_SELECTION_ENABLED !== "enabled")
        return json({ ok: false, error: "not_found" }, 404);
      if (request.method === "GET") {
        if ([...url.searchParams.keys()].some(key => key !== "client_id")
            || url.searchParams.getAll("client_id").length !== 1)
          return json({ ok: false, error: "owner_central_selection_invalid" }, 400);
        const clientId = (url.searchParams.get("client_id") ?? "").toLowerCase();
        if (!CLIENT_ID_RE.test(clientId))
          return json({ ok: false, error: "owner_central_selection_invalid" }, 400);
        const result = await (deps.listSelections ?? listOwnerCentralSelections)(env, {
          ownerUserId: ownerId, clientId,
        });
        return json(result, result.ok === true ? 200 : 403);
      }
      if (request.method !== "POST")
        return json({ ok: false, error: "method_not_allowed" }, 405);
      if (url.search !== "")
        return json({ ok: false, error: "owner_central_selection_invalid" }, 400);
      const mime = (request.headers.get("content-type") ?? "").split(";", 1)[0].trim().toLowerCase();
      if (mime !== "application/json")
        return json({ ok: false, error: "content_type_invalid" }, 415);
      const body = await readBoundedJsonObject(request, 1024);
      if (!body || Object.keys(body).length !== 3
          || Object.keys(body).some(key => !["client_id","challenge_id","device_id"].includes(key)))
        return json({ ok: false, error: "owner_central_selection_invalid" }, 400);
      const clientId = typeof body.client_id === "string" ? body.client_id.toLowerCase() : "";
      const challengeId = typeof body.challenge_id === "string" ? body.challenge_id.toLowerCase() : "";
      const deviceId = typeof body.device_id === "string" ? body.device_id.toLowerCase() : "";
      if (!CLIENT_ID_RE.test(clientId) || !isCanonicalUuid(challengeId) || !isCanonicalUuid(deviceId))
        return json({ ok: false, error: "owner_central_selection_invalid" }, 400);
      const result = await (deps.selectDevice ?? selectOwnerCentralDevice)(env, {
        ownerUserId: ownerId, clientId, challengeId, deviceId,
      });
      return json(result, result.ok === true ? 200 : 403);
    }
    if (url.pathname === PRODUCT_OWNER_CENTRAL_SESSION_TARGETS_PATH) {
      // Advisory-only Owner preflight: not a device selector, grant or dispatch.
      // Remain off until the read-only SQL authority is governed and deployed.
      if (env.CENTRAL_OWNER_TARGET_PREFLIGHT_ENABLED !== "enabled")
        return json({ ok: false, error: "not_found" }, 404);
      if (request.method !== "GET") return json({ ok: false, error: "method_not_allowed" }, 405);
      if ([...url.searchParams.keys()].some(key => key !== "client_id")
          || url.searchParams.getAll("client_id").length !== 1)
        return json({ ok: false, error: "owner_central_targets_invalid" }, 400);
      const clientId = (url.searchParams.get("client_id") ?? "").toLowerCase();
      if (!CLIENT_ID_RE.test(clientId)) return json({ ok: false, error: "owner_central_targets_invalid" }, 400);
      const result = await (deps.inspectCentralTargets ?? inspectOwnerCentralSessionTargets)(env, {
        ownerUserId: ownerId, clientId,
      });
      return json(result, result.ok === true ? 200 : 403);
    }
    if (url.pathname.startsWith(WORKSPACE_RESOURCES)) {
      // Owner consent cannot be issued just because the READ verifier gate is
      // enabled. This second gate remains OFF pending native picker E2E.
      if (url.pathname === WORKSPACE_APPROVALS) {
        if (env.WORKSPACE_RESOURCE_VERIFIER_ENABLED !== "enabled"
            || env.WORKSPACE_RESOURCE_ISSUANCE_ENABLED !== "enabled")
          return json({ ok: false, error: "not_found" }, 404);
        if (request.method !== "POST")
          return json({ ok: false, error: "method_not_allowed" }, 405);
        if (url.search.length !== 0)
          return json({ ok: false, error: "workspace_approval_invalid" }, 400);
        const body = await readBoundedJsonObject(request, 2048);
        const input = canonicalOwnerWorkspaceApproval(body);
        if (!input) return json({ ok: false, error: "workspace_approval_invalid" }, 400);
        // The Owner ID comes exclusively from the signed Product session
        // above; neither a body field nor opaque resourceId authenticates it.
        const approved = await approveProjectWorkspaceResource(env, {
          ownerUserId: ownerId, ...input,
        });
        return json({ ok: approved, approved }, approved ? 200 : 403);
      }
      // Disabled until governance-approved SQL migration and real picker
      // attestation. Explicitly signed Owner identity is already verified.
      if (env.WORKSPACE_RESOURCE_VERIFIER_ENABLED !== "enabled")
        return json({ ok: false, error: "not_found" }, 404);
      if (request.method !== "DELETE")
        return json({ ok: false, error: "method_not_allowed" }, 405);
      const input = parseOwnerWorkspaceResourceRevocation(url);
      if (!input)
        return json({ ok: false, error: "workspace_resource_invalid" }, 400);
      const revoked = await revokeProjectWorkspaceResource(env, {
        ownerUserId: ownerId, ...input,
      });
      return json({ ok: true, revoked });
    }

    if (request.method === "GET" && url.pathname === ROOT) {
      const deviceId = (url.searchParams.get("device_id") ?? "").toLowerCase();
      if (!isCanonicalUuid(deviceId)) return json({ ok: false, error: "device_id_invalid" }, 400);
      const result = await listOwnerMcpRemoteAuthority(env, ownerId, deviceId);
      return json(result, result.ok === false ? 403 : 200);
    }

    if (request.method === "POST" && url.pathname === GROUPS) {
      const body = await readBoundedJsonObject(request, 16 * 1024);
      const allowed = new Set(["client_id","device_id","profile_key","space_id","project_id","valid_until"]);
      if (!body || Object.keys(body).some((key) => !allowed.has(key)))
        return json({ ok: false, error: "owner_grant_invalid" }, 400);
      const clientId = typeof body.client_id === "string" ? body.client_id.toLowerCase() : "";
      const deviceId = typeof body.device_id === "string" ? body.device_id.toLowerCase() : "";
      const profileKey = typeof body.profile_key === "string" ? body.profile_key : "";
      const spaceId = optionalUuid(body.space_id);
      const projectId = optionalUuid(body.project_id);
      const until = validUntil(body.valid_until);
      const profile = ownerMcpGrantProfile(profileKey);
      if (!CLIENT_ID_RE.test(clientId) || !isCanonicalUuid(deviceId) || !PROFILE_KEY_RE.test(profileKey)
          || spaceId === undefined || projectId === undefined || until === undefined || !profile)
        return json({ ok: false, error: "owner_grant_invalid" }, 400);
      if (profile.scope === "device" && (spaceId !== null || projectId !== null))
        return json({ ok: false, error: "owner_grant_scope_invalid" }, 400);
      if (profile.scope === "project" && (spaceId === null || projectId === null))
        return json({ ok: false, error: "owner_grant_scope_invalid" }, 400);
      const result = await replaceOwnerMcpGrantGroup(env, {
        ownerUserId: ownerId, deviceId, clientId, profileKey,
        spaceId, projectId, capabilities: profile.capabilities, validUntil: until,
      });
      const status = result.ok === true ? 200
        : result.error === "product_mcp_oauth_consent_required" ? 403 : 400;
      return json(result, status);
    }

    if (request.method === "DELETE" && url.pathname.startsWith(GROUPS + "/")) {
      const groupId = url.pathname.slice((GROUPS + "/").length).toLowerCase();
      const clientId = (url.searchParams.get("client_id") ?? "").toLowerCase();
      if (!isCanonicalUuid(groupId) || !CLIENT_ID_RE.test(clientId))
        return json({ ok: false, error: "owner_grant_revoke_invalid" }, 400);
      const result = await revokeOwnerMcpGrantGroup(env, ownerId, clientId, groupId);
      return json(result, result.ok === true ? 200 : 404);
    }

    return json({ ok: false, error: "method_not_allowed" }, 405);
  } catch (error) {
    return failure(error);
  }
}

export const PRODUCT_OWNER_REMOTE_AUTHORITY_PATH = ROOT;
export const PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH = GROUPS;
