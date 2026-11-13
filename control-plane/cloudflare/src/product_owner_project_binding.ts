import {
  authenticateProductRequest,
  authorizeProductOwnerIdentity,
  type ProductAuthEnv,
  type ProductIdentity,
} from "./product_auth.ts";
import {
  createOwnerProjectBindingIntent,
  ProductPostgresError,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { scheduleProductDeviceWake } from "./product_device_wake.ts";
import { readBoundedJsonObject } from "./request_json.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type Json = Record<string, unknown>;

type Dependencies = Readonly<{
  authenticate?: (request: Request, env: ProductAuthEnv) => Promise<ProductIdentity>;
  createIntent?: typeof createOwnerProjectBindingIntent;
  wake?: typeof scheduleProductDeviceWake;
  now?: () => number;
  randomUuid?: () => string;
}>;

export const PRODUCT_OWNER_PROJECT_BINDING_INTENTS_PATH =
  "/v3/owner/project-bindings/intents";

const INTENT_TTL_MS = 5 * 60 * 1000;

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

const PUBLIC_ERRORS = new Set([
  "project_binding_intent_invalid",
  "product_owner_auth_ineligible",
  "project_not_found_or_inactive",
  "space_admin_required",
  "device_not_owned",
  "github_repository_required",
  "github_repository_ambiguous",
  "project_device_binding_exists",
  "project_binding_intent_pending",
]);

function errorStatus(error: string): number {
  if (error === "project_not_found_or_inactive") return 404;
  if (error === "space_admin_required" || error === "device_not_owned"
      || error === "product_owner_auth_ineligible") return 403;
  if (error === "project_device_binding_exists" || error === "project_binding_intent_pending"
      || error === "github_repository_ambiguous") return 409;
  return 400;
}

export function createOwnerProjectBindingHandler(env: Env, deps: Dependencies = {}) {
  const authenticate = deps.authenticate ?? authenticateProductRequest;
  const createIntent = deps.createIntent ?? createOwnerProjectBindingIntent;
  const wake = deps.wake ?? scheduleProductDeviceWake;
  const now = deps.now ?? Date.now;
  const randomUuid = deps.randomUuid ?? (() => crypto.randomUUID());

  return async function handleOwnerProjectBinding(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname !== PRODUCT_OWNER_PROJECT_BINDING_INTENTS_PATH) {
      return json({ ok: false, error: "not_found" }, 404);
    }

    const identity = authorizeProductOwnerIdentity(await authenticate(request, env), env);
    if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);

    // Authenticate first, then hide the disabled feature from valid Owners.
    if (env.OWNER_PROJECT_BINDING_ENABLED !== "enabled") {
      return json({ ok: false, error: "not_found" }, 404);
    }
    if (request.method !== "POST") {
      return json({ ok: false, error: "method_not_allowed" }, 405);
    }
    if (url.search !== "") {
      return json({ ok: false, error: "project_binding_request_invalid" }, 400);
    }

    const body = await readBoundedJsonObject(request, 4096);
    if (!exactObjectKeys(body, ["project_id", "device_id", "confirm"])
        || typeof body.project_id !== "string" || !isCanonicalUuid(body.project_id)
        || typeof body.device_id !== "string" || !isCanonicalUuid(body.device_id)
        || body.confirm !== "bind_device") {
      return json({ ok: false, error: "project_binding_request_invalid" }, 400);
    }

    const intentId = randomUuid().toLowerCase();
    if (!isCanonicalUuid(intentId)) {
      return json({ ok: false, error: "project_binding_entropy_invalid" }, 503);
    }
    const expiresAt = new Date(now() + INTENT_TTL_MS).toISOString();

    try {
      const result = await createIntent(env, {
        ownerUserId: identity.ownerUserId,
        projectId: body.project_id.toLowerCase(),
        deviceId: body.device_id.toLowerCase(),
        intentId,
        expiresAt,
      });
      if (result.ok === false && typeof result.error === "string"
          && PUBLIC_ERRORS.has(result.error)) {
        return json({ ok: false, error: result.error }, errorStatus(result.error));
      }
      if (result.ok !== true || result.intent_id !== intentId
          || result.project_id !== body.project_id.toLowerCase()
          || result.device_id !== body.device_id.toLowerCase()
          || !isCanonicalUuid(result.space_id)
          || result.next_state !== "awaiting_device_confirmation"
          || typeof result.expires_at !== "string"
          || Date.parse(result.expires_at) !== Date.parse(expiresAt)) {
        return json({ ok: false, error: "product_postgres_invalid_response" }, 503);
      }

      // Wake is advisory only. The Runtime must authenticate and read the
      // canonical pending intent; no binding authority travels in the signal.
      await wake(env, body.device_id.toLowerCase());
      return json({
        ok: true,
        schema: "ordax.owner-project-binding-intent/1",
        intent_id: intentId,
        project_id: result.project_id,
        space_id: result.space_id,
        device_id: result.device_id,
        expires_at: result.expires_at,
        next_state: "awaiting_device_confirmation",
      }, 201);
    } catch (error) {
      if (error instanceof ProductPostgresError) {
        return json({ ok: false, error: error.code }, error.status);
      }
      return json({ ok: false, error: "product_postgres_unavailable" }, 503);
    }
  };
}

export function handleProductOwnerProjectBinding(request: Request, env: Env): Promise<Response> {
  return createOwnerProjectBindingHandler(env)(request);
}
