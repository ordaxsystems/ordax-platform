import { authenticateProductRequest, type ProductAuthEnv } from "./product_auth.ts";
import {
  listOwnerMcpRemoteAuthority,
  replaceOwnerMcpGrantGroup,
  revokeOwnerMcpGrantGroup,
  ProductPostgresError,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { ownerMcpGrantProfile } from "./product_owner_grant_profiles.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { readBoundedJsonObject } from "./request_json.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type Json = Record<string, unknown>;
const ROOT = "/v3/owner/remote-authority";
const GROUPS = "/v3/owner/remote-grant-groups";
const CLIENT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const PROFILE_KEY_RE = /^[a-z][a-z0-9._-]{1,79}$/;

const json = (body: unknown, status = 200) => Response.json(body, {
  status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
});

async function owner(request: Request, env: Env): Promise<string | Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
  if (identity.role !== "authenticated" || !isCanonicalUuid(identity.subjectId))
    return json({ ok: false, error: "product_owner_identity_invalid" }, 403);
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

export async function handleProductOwnerGrantAdmin(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname !== ROOT && !url.pathname.startsWith(GROUPS))
    return json({ ok: false, error: "not_found" }, 404);

  const ownerId = await owner(request, env);
  if (ownerId instanceof Response) return ownerId;

  try {
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
