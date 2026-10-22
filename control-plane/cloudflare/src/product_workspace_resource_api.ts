import { authenticateProductRequest, type ProductAuthEnv } from "./product_auth.ts";
import { authenticateProductDeviceRequest } from "./product_device_auth.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import {
  canonicalGithubRepositoryFullName,
  projectScopeResponse,
  resolveOwnerProjectScope,
} from "./product_owner_project_scope.ts";
import {
  registerProjectWorkspaceResource,
  revokeProjectWorkspaceResource,
  ProductPostgresError,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import {
  projectWorkspaceVerifierResponse,
  type DeviceWorkspaceProofQuery,
} from "./product_device_transport.ts";
import { readBoundedJsonObject } from "./request_json.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type Json = Record<string, unknown>;
type Dependencies = Readonly<{
  authenticateOwner?: typeof authenticateProductRequest;
  authenticateDevice?: typeof authenticateProductDeviceRequest;
  resolveScope?: typeof resolveOwnerProjectScope;
  register?: typeof registerProjectWorkspaceResource;
  revoke?: typeof revokeProjectWorkspaceResource;
}>;

export const PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH = "/v3/owner/project-workspace-resources";

const LAB_ID = /^[A-Za-z0-9_-]{1,180}$/;
const RESOURCE_ID = /^resource_[A-Za-z0-9_-]{8,160}$/;
const SESSION_ID = /^[A-Za-z0-9_-]{1,180}$/;
const REGISTRATION_ERRORS = new Set([
  "workspace_authorization_required",
  "workspace_resource_conflict",
  "workspace_project_binding_conflict",
  "workspace_resource_invalid",
]);

const json = (body: unknown, status = 200) => Response.json(body, {
  status,
  headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
});

function expectedKeys(body: Json, keys: readonly string[]): boolean {
  return Object.keys(body).length === keys.length
    && Object.keys(body).every(key => keys.includes(key));
}

async function ownerIdentity(
  request: Request,
  env: Env,
  authenticate: NonNullable<Dependencies["authenticateOwner"]>,
) {
  const identity = await authenticate(request, env);
  if (!identity.ok) return { response: json({ ok: false, error: identity.error }, identity.status) };
  if (identity.role !== "authenticated" || !isCanonicalUuid(identity.subjectId)) {
    return { response: json({ ok: false, error: "product_owner_identity_invalid" }, 403) };
  }
  // The OAuth client comes from the verified Owner JWT. A request body may
  // repeat it for SQL, but must never choose a different consented client.
  if (!isCanonicalUuid(identity.clientId)) {
    return { response: json({ ok: false, error: "product_owner_client_invalid" }, 403) };
  }
  return { ownerUserId: identity.subjectId, clientId: identity.clientId.toLowerCase() };
}

function projectScopeStatus(result: Json): number {
  switch (result.error) {
    case "owner_project_scope_not_found": return 404;
    case "owner_project_scope_ambiguous": return 409;
    case "product_owner_auth_ineligible":
    case "device_not_owned": return 403;
    default: return 400;
  }
}

function publicFailure(error: unknown): Response {
  if (error instanceof ProductPostgresError) return json({ ok: false, error: error.code }, error.status);
  return json({ ok: false, error: "product_postgres_unavailable" }, 503);
}

function registrationFailure(raw: unknown): Response {
  const candidate = raw && typeof raw === "object" && !Array.isArray(raw)
    && (raw as Json).ok === false && typeof (raw as Json).error === "string"
    ? (raw as Json).error as string : "workspace_resource_registration_failed";
  const error = REGISTRATION_ERRORS.has(candidate) ? candidate : "workspace_resource_registration_failed";
  const status = error === "workspace_authorization_required" ? 403
    : error === "workspace_resource_conflict" || error === "workspace_project_binding_conflict" ? 409
      : error === "workspace_resource_invalid" ? 400 : 502;
  return json({ ok: false, error }, status);
}

/**
 * Registers only a Runtime-selected opaque resource reference. The canonical
 * Owner and Device identities are verified here; Platform resolves the Product
 * project and attaches this reference to the existing read grant. Local paths
 * and permissions never cross this API boundary.
 */
export function createOwnerWorkspaceResourceHandler(env: Env, deps: Dependencies = {}) {
  const authenticateOwner = deps.authenticateOwner ?? authenticateProductRequest;
  const authenticateDevice = deps.authenticateDevice ?? authenticateProductDeviceRequest;
  const resolve = deps.resolveScope ?? resolveOwnerProjectScope;
  const register = deps.register ?? registerProjectWorkspaceResource;
  const revoke = deps.revoke ?? revokeProjectWorkspaceResource;

  return async function handleOwnerWorkspaceResource(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const resourceId = url.pathname.startsWith(PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH + "/")
      ? url.pathname.slice(PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH.length + 1) : "";
    if (url.pathname !== PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH && !RESOURCE_ID.test(resourceId)) {
      return json({ ok: false, error: "not_found" }, 404);
    }

    const owner = await ownerIdentity(request, env, authenticateOwner);
    if ("response" in owner) return owner.response;

    try {
      if (request.method === "POST" && url.pathname === PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH) {
        const body = await readBoundedJsonObject(request, 12 * 1024);
        const keys = ["actor_id", "client_id", "lab_project_id", "repository_full_name",
          "resource_id", "workspace_session_id"] as const;
        if (!body || !expectedKeys(body, keys)) {
          return json({ ok: false, error: "workspace_resource_invalid" }, 400);
        }
        const actorId = typeof body.actor_id === "string" ? body.actor_id.toLowerCase() : "";
        const clientId = typeof body.client_id === "string" ? body.client_id.toLowerCase() : "";
        const labProjectId = typeof body.lab_project_id === "string" ? body.lab_project_id : "";
        const workspaceSessionId = typeof body.workspace_session_id === "string"
          ? body.workspace_session_id : "";
        const resource = typeof body.resource_id === "string" ? body.resource_id : "";
        const repository = canonicalGithubRepositoryFullName(body.repository_full_name);
        if (!isCanonicalUuid(actorId) || clientId !== owner.clientId || !LAB_ID.test(labProjectId)
            || !SESSION_ID.test(workspaceSessionId) || !RESOURCE_ID.test(resource) || repository === null) {
          return json({ ok: false, error: "workspace_resource_invalid" }, 400);
        }

        const device = await authenticateDevice(request, env);
        if (!device.ok) return device.response;
        const rawScope = await resolve(env, owner.ownerUserId, device.deviceId, repository);
        const scope = projectScopeResponse(rawScope, repository);
        if (scope.ok !== true) return json(scope, projectScopeStatus(scope));

        const rawProof = await register(env, {
          ownerUserId: owner.ownerUserId,
          actorId,
          clientId,
          workspaceSessionId,
          labProjectId,
          deviceId: device.deviceId,
          resourceId: resource,
          spaceId: String(scope.space_id),
          projectId: String(scope.project_id),
        });
        if (!rawProof || typeof rawProof !== "object" || (rawProof as Json).ok !== true) {
          return registrationFailure(rawProof);
        }
        const query: DeviceWorkspaceProofQuery = {
          ownerUserId: owner.ownerUserId,
          actorId,
          clientId,
          labProjectId,
          workspaceSessionId,
          deviceId: device.deviceId,
          resourceId: resource,
        };
        const proof = projectWorkspaceVerifierResponse(rawProof, query);
        const grant = proof && proof.grant && typeof proof.grant === "object" && !Array.isArray(proof.grant)
          ? proof.grant as Json : null;
        if (!proof || !grant || typeof grant.space_id !== "string"
            || grant.space_id !== scope.space_id || grant.project_id !== scope.project_id) {
          return json({ ok: false, error: "workspace_authority_invalid" }, 502);
        }
        return json(proof);
      }

      if (request.method === "DELETE" && resourceId) {
        const clientId = (url.searchParams.get("client_id") ?? "").toLowerCase();
        if (clientId !== owner.clientId || [...url.searchParams.keys()].some(key => key !== "client_id")) {
          return json({ ok: false, error: "workspace_resource_revoke_invalid" }, 400);
        }
        const result = await revoke(env, owner.ownerUserId, clientId, resourceId);
        if (result.ok !== true) {
          const candidate = typeof result.error === "string" ? result.error : "";
          const error = candidate === "workspace_resource_not_found"
            || candidate === "workspace_resource_revoke_invalid"
            ? candidate : "workspace_resource_revoke_failed";
          return json({ ok: false, error }, error === "workspace_resource_not_found" ? 404 : 403);
        }
        return json({ ok: true, resource_id: resourceId, revoked: true });
      }
      return json({ ok: false, error: "method_not_allowed" }, 405);
    } catch (error) {
      return publicFailure(error);
    }
  };
}

export function handleProductOwnerWorkspaceResource(request: Request, env: Env): Promise<Response> {
  return createOwnerWorkspaceResourceHandler(env)(request);
}
