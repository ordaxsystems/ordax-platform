import { readBoundedJsonObject } from "./request_json.ts";
import {
  authenticateProductRequest,
  authorizeProductOwnerIdentity,
  type ProductAuthEnv,
  type ProductIdentity,
} from "./product_auth.ts";
import { canonicalGithubRepositoryFullName } from "./product_owner_project_scope.ts";
import {
  createOwnerProject,
  createOwnerProjectDeviceBindingIntent,
  ProductPostgresError,
  readOwnerProjectOnboardingState,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { hasExactQueryParameters } from "./request_query.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type Json = Record<string, unknown>;

type Dependencies = Readonly<{
  authenticate?: (request: Request, env: ProductAuthEnv) => Promise<ProductIdentity>;
  readState?: typeof readOwnerProjectOnboardingState;
  createProject?: typeof createOwnerProject;
  createBindingIntent?: typeof createOwnerProjectDeviceBindingIntent;
  randomUUID?: () => string;
  now?: () => number;
}>;

export const PRODUCT_OWNER_PROJECT_ONBOARDING_PATH = "/v3/owner/project-onboarding";
export const PRODUCT_OWNER_PROJECT_ONBOARDING_PROJECTS_PATH =
  PRODUCT_OWNER_PROJECT_ONBOARDING_PATH + "/projects";
export const PRODUCT_OWNER_PROJECT_DEVICE_BINDING_INTENTS_PATH =
  PRODUCT_OWNER_PROJECT_ONBOARDING_PATH + "/device-binding-intents";

const PROJECT_KINDS = new Set([
  "general", "development", "creative", "legal", "business", "research",
]);
const PROJECT_STATES = new Set([
  "needs_github_installation",
  "needs_repository_selection",
  "needs_device_binding",
  "ready_without_grants",
]);
const ROOT_STATES = new Set(["needs_space", "needs_project"]);
const PUBLIC_STATE_ERRORS = new Set([
  "owner_project_onboarding_invalid",
  "product_owner_auth_ineligible",
  "device_not_owned",
]);
const PUBLIC_PROJECT_ERRORS = new Set([
  "project_identity_invalid",
  "trusted_actor_auth_ineligible",
  "space_not_found",
  "space_inactive",
  "space_admin_required",
  "project_name_invalid",
  "project_kind_invalid",
  "project_metadata_invalid",
]);
const PUBLIC_BINDING_INTENT_ERRORS = new Set([
  "project_device_binding_intent_invalid",
  "product_owner_auth_ineligible",
  "device_not_owned",
  "project_not_found",
  "space_admin_required",
  "github_repository_required",
  "github_repository_ambiguous",
]);

const json = (body: unknown, status = 200) => Response.json(body, {
  status,
  headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
});

function exactObjectKeys(value: unknown, keys: readonly string[]): value is Json {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value as Json).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function safeLabel(value: unknown, max = 120): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim();
  if (normalized.length < 1 || normalized.length > max || /[\u0000-\u001f\u007f]/.test(normalized)) {
    return null;
  }
  return normalized;
}

function publicDatabaseError(error: unknown): Response {
  if (error instanceof ProductPostgresError) {
    return json({ ok: false, error: error.code }, error.status);
  }
  return json({ ok: false, error: "product_postgres_unavailable" }, 503);
}

export function onboardingStateResponse(raw: Json, requestedDeviceId: string): Json {
  if (raw.ok === false && typeof raw.error === "string" && PUBLIC_STATE_ERRORS.has(raw.error)) {
    return { ok: false, error: raw.error };
  }
  if (raw.ok !== true || raw.device_id !== requestedDeviceId
      || !Array.isArray(raw.spaces) || !Array.isArray(raw.projects)
      || raw.spaces.length > 64 || raw.projects.length > 512) {
    throw new Error("product_postgres_invalid_response");
  }

  const spaces = raw.spaces.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error("product_postgres_invalid_response");
    }
    const item = entry as Json;
    const name = safeLabel(item.name);
    const kind = safeLabel(item.kind, 80);
    if (!isCanonicalUuid(item.space_id) || name === null || kind === null || item.state !== "active") {
      throw new Error("product_postgres_invalid_response");
    }
    return { space_id: item.space_id, name, kind, state: "active" };
  });

  const projects = raw.projects.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error("product_postgres_invalid_response");
    }
    const item = entry as Json;
    const name = safeLabel(item.name);
    const count = item.github_connection_count;
    const nextState = item.next_state;
    const repository = item.repository_full_name === null
      ? null : canonicalGithubRepositoryFullName(item.repository_full_name);
    if (!isCanonicalUuid(item.project_id) || !isCanonicalUuid(item.space_id)
        || name === null || typeof item.kind !== "string" || !PROJECT_KINDS.has(item.kind)
        || item.state !== "active" || typeof count !== "number" || !Number.isSafeInteger(count) || count < 0
        || typeof item.space_device_execute !== "boolean"
        || typeof item.project_device_bound !== "boolean"
        || typeof nextState !== "string" || !PROJECT_STATES.has(nextState)
        || (count === 1 && repository === null)
        || (count !== 1 && item.repository_full_name !== null)) {
      throw new Error("product_postgres_invalid_response");
    }
    return {
      project_id: item.project_id,
      space_id: item.space_id,
      name,
      kind: item.kind,
      state: "active",
      github_connection_count: count,
      repository_full_name: repository,
      space_device_execute: item.space_device_execute,
      project_device_bound: item.project_device_bound,
      next_state: nextState,
    };
  });

  const rootState = raw.next_state;
  if (rootState !== null && (typeof rootState !== "string" || !ROOT_STATES.has(rootState))) {
    throw new Error("product_postgres_invalid_response");
  }
  if ((rootState === "needs_space" && spaces.length !== 0)
      || (rootState === "needs_project" && (spaces.length === 0 || projects.length !== 0))
      || (rootState === null && (spaces.length === 0 || projects.length === 0))) {
    throw new Error("product_postgres_invalid_response");
  }

  return {
    ok: true,
    device_id: requestedDeviceId,
    spaces,
    projects,
    next_state: rootState,
  };
}

export function ownerProjectCreationResponse(raw: Json, requestedSpaceId: string): Json {
  if (raw.ok === false && typeof raw.error === "string" && PUBLIC_PROJECT_ERRORS.has(raw.error)) {
    return { ok: false, error: raw.error };
  }
  if (raw.ok !== true || !isCanonicalUuid(raw.project_id)
      || raw.space_id !== requestedSpaceId || raw.state !== "active") {
    throw new Error("product_postgres_invalid_response");
  }
  return {
    ok: true,
    project_id: raw.project_id,
    space_id: requestedSpaceId,
    state: "active",
    next_state: "needs_github_installation",
  };
}

export function ownerProjectDeviceBindingIntentResponse(
  raw: Json,
  requestedProjectId: string,
  requestedDeviceId: string,
): Json {
  if (raw.ok === false && typeof raw.error === "string"
      && PUBLIC_BINDING_INTENT_ERRORS.has(raw.error)) {
    return { ok: false, error: raw.error };
  }
  if (raw.ok !== true || !isCanonicalUuid(raw.intent_id)
      || raw.project_id !== requestedProjectId || raw.device_id !== requestedDeviceId
      || raw.next_state !== "awaiting_device_confirmation"
      || typeof raw.expires_at !== "string"
      || !Number.isFinite(Date.parse(raw.expires_at))) {
    throw new Error("product_postgres_invalid_response");
  }
  return {
    ok: true,
    schema: "ordax.owner-project-device-binding-intent/1",
    intent_id: raw.intent_id,
    project_id: requestedProjectId,
    device_id: requestedDeviceId,
    expires_at: raw.expires_at,
    next_state: "awaiting_device_confirmation",
  };
}

function bindingIntentStatus(result: Json): number {
  if (result.ok === true) return 201;
  switch (result.error) {
    case "device_not_owned":
    case "product_owner_auth_ineligible":
    case "space_admin_required":
      return 403;
    case "project_not_found":
      return 404;
    case "github_repository_required":
    case "github_repository_ambiguous":
      return 409;
    default:
      return 400;
  }
}

function stateStatus(result: Json): number {
  if (result.ok === true) return 200;
  if (result.error === "device_not_owned" || result.error === "product_owner_auth_ineligible") return 403;
  return 400;
}

function projectStatus(result: Json): number {
  if (result.ok === true) return 201;
  switch (result.error) {
    case "space_not_found": return 404;
    case "space_inactive": return 409;
    case "trusted_actor_auth_ineligible":
    case "space_admin_required": return 403;
    default: return 400;
  }
}

export function createOwnerProjectOnboardingHandler(env: Env, deps: Dependencies = {}) {
  const authenticate = deps.authenticate ?? authenticateProductRequest;
  const readState = deps.readState ?? readOwnerProjectOnboardingState;
  const createProject = deps.createProject ?? createOwnerProject;
  const createBindingIntent = deps.createBindingIntent ?? createOwnerProjectDeviceBindingIntent;
  const randomUUID = deps.randomUUID ?? (() => crypto.randomUUID());
  const now = deps.now ?? Date.now;

  return async function handleOwnerProjectOnboarding(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== PRODUCT_OWNER_PROJECT_ONBOARDING_PATH
        && url.pathname !== PRODUCT_OWNER_PROJECT_ONBOARDING_PROJECTS_PATH
        && url.pathname !== PRODUCT_OWNER_PROJECT_DEVICE_BINDING_INTENTS_PATH) {
      return json({ ok: false, error: "not_found" }, 404);
    }

    const identity = authorizeProductOwnerIdentity(await authenticate(request, env), env);
    if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);

    if (url.pathname === PRODUCT_OWNER_PROJECT_ONBOARDING_PATH) {
      if (request.method !== "GET") return json({ ok: false, error: "method_not_allowed" }, 405);
      if (!hasExactQueryParameters(url, ["device_id"])) {
        return json({ ok: false, error: "owner_project_onboarding_invalid" }, 400);
      }
      const deviceId = (url.searchParams.get("device_id") ?? "").toLowerCase();
      if (!isCanonicalUuid(deviceId)) {
        return json({ ok: false, error: "owner_project_onboarding_invalid" }, 400);
      }
      try {
        const raw = await readState(env, { ownerUserId: identity.ownerUserId, deviceId });
        const result = onboardingStateResponse(raw, deviceId);
        return json(result, stateStatus(result));
      } catch (error) {
        if (error instanceof Error && error.message === "product_postgres_invalid_response") {
          return json({ ok: false, error: "product_postgres_invalid_response" }, 503);
        }
        return publicDatabaseError(error);
      }
    }

    if (url.pathname === PRODUCT_OWNER_PROJECT_DEVICE_BINDING_INTENTS_PATH) {
      // Authenticate first, then keep the staged boundary indistinguishable from
      // an absent route until the SQL + Runtime confirmation path are released.
      if (env.OWNER_PROJECT_DEVICE_BINDING_ENABLED !== "enabled") {
        return json({ ok: false, error: "not_found" }, 404);
      }
      if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
      if (url.search !== "") {
        return json({ ok: false, error: "project_device_binding_intent_invalid" }, 400);
      }
      let body: unknown;
      try {
        body = await readBoundedJsonObject(request, 4096);
      } catch {
        return json({ ok: false, error: "project_device_binding_intent_invalid" }, 400);
      }
      if (!exactObjectKeys(body, ["project_id", "device_id", "confirm"])) {
        return json({ ok: false, error: "project_device_binding_intent_invalid" }, 400);
      }
      const record = body as Json;
      const projectId = typeof record.project_id === "string" ? record.project_id.toLowerCase() : "";
      const deviceId = typeof record.device_id === "string" ? record.device_id.toLowerCase() : "";
      if (!isCanonicalUuid(projectId) || !isCanonicalUuid(deviceId)
          || record.confirm !== "bind_project_device") {
        return json({ ok: false, error: "project_device_binding_intent_invalid" }, 400);
      }
      const intentId = randomUUID().toLowerCase();
      const expiresAt = new Date(now() + 5 * 60 * 1000).toISOString();
      if (!isCanonicalUuid(intentId)) {
        return json({ ok: false, error: "project_device_binding_intent_invalid" }, 503);
      }
      try {
        const raw = await createBindingIntent(env, {
          ownerUserId: identity.ownerUserId,
          projectId,
          deviceId,
          intentId,
          expiresAt,
        });
        const result = ownerProjectDeviceBindingIntentResponse(raw, projectId, deviceId);
        return json(result, bindingIntentStatus(result));
      } catch (error) {
        if (error instanceof Error && error.message === "product_postgres_invalid_response") {
          return json({ ok: false, error: "product_postgres_invalid_response" }, 503);
        }
        return publicDatabaseError(error);
      }
    }

    if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
    if ([...url.searchParams].length !== 0) {
      return json({ ok: false, error: "owner_project_create_invalid" }, 400);
    }

    let body: unknown;
    try {
      body = await readBoundedJsonObject(request, 16_384);
    } catch {
      return json({ ok: false, error: "owner_project_create_invalid" }, 400);
    }
    if (!exactObjectKeys(body, ["space_id", "name", "kind", "confirm"])) {
      return json({ ok: false, error: "owner_project_create_invalid" }, 400);
    }
    const record = body as Json;
    const spaceId = typeof record.space_id === "string" ? record.space_id.toLowerCase() : "";
    const name = safeLabel(record.name);
    const kind = typeof record.kind === "string" ? record.kind : "";
    if (!isCanonicalUuid(spaceId) || name === null || !PROJECT_KINDS.has(kind)
        || record.confirm !== "create_project") {
      return json({ ok: false, error: "owner_project_create_invalid" }, 400);
    }

    try {
      const raw = await createProject(env, {
        ownerUserId: identity.ownerUserId,
        spaceId,
        name,
        kind: kind as "general" | "development" | "creative" | "legal" | "business" | "research",
      });
      const result = ownerProjectCreationResponse(raw, spaceId);
      return json(result, projectStatus(result));
    } catch (error) {
      if (error instanceof Error && error.message === "product_postgres_invalid_response") {
        return json({ ok: false, error: "product_postgres_invalid_response" }, 503);
      }
      return publicDatabaseError(error);
    }
  };
}

export function handleProductOwnerProjectOnboarding(request: Request, env: Env): Promise<Response> {
  return createOwnerProjectOnboardingHandler(env)(request);
}
