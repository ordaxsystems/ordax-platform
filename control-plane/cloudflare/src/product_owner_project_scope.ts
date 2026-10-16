import postgres from "postgres";
import {
  authenticateProductRequest,
  type ProductAuthEnv,
  type ProductIdentity,
} from "./product_auth.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import type { ProductPostgresEnv } from "./product_postgres_store.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type Json = Record<string, unknown>;

type Dependencies = Readonly<{
  authenticate?: (request: Request, env: ProductAuthEnv) => Promise<ProductIdentity>;
  resolve?: (env: ProductPostgresEnv, ownerUserId: string, deviceId: string, repositoryFullName: string) => Promise<Json>;
}>;

export const PRODUCT_OWNER_PROJECT_SCOPE_PATH = "/v3/owner/project-scope";
const GITHUB_REPOSITORY_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/;

const json = (body: unknown, status = 200) => Response.json(body, {
  status,
  headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
});

export function canonicalGithubRepositoryFullName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim();
  if (normalized.length < 3 || normalized.length > 140 || !GITHUB_REPOSITORY_RE.test(normalized)) {
    return null;
  }
  return normalized;
}

function configuredConnectionString(env: ProductPostgresEnv): string | null {
  const raw = (env.POSTGRES?.connectionString ?? "").trim();
  if (!raw) return null;
  try {
    const parsed = new URL(raw);
    return parsed.protocol === "postgres:" || parsed.protocol === "postgresql:" ? raw : null;
  } catch {
    return null;
  }
}

export async function resolveOwnerProjectScope(
  env: ProductPostgresEnv,
  ownerUserId: string,
  deviceId: string,
  repositoryFullName: string,
): Promise<Json> {
  const connectionString = configuredConnectionString(env);
  const repository = canonicalGithubRepositoryFullName(repositoryFullName);
  if (!connectionString) throw new Error("product_postgres_unconfigured");
  if (!isCanonicalUuid(ownerUserId) || !isCanonicalUuid(deviceId) || repository === null) {
    throw new Error("owner_project_scope_invalid");
  }

  const sql = postgres(connectionString, {
    max: 1,
    connect_timeout: 5,
    idle_timeout: 1,
    prepare: true,
  });
  try {
    const rows = await sql`
      select public.ordax_resolve_owner_project_scope_v1(
        ${ownerUserId}::uuid,
        ${deviceId}::uuid,
        ${repository}::text
      ) as result
    `;
    const value = (rows[0] as { result?: unknown } | undefined)?.result;
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("product_postgres_invalid_response");
    }
    return value as Json;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("product_")) throw error;
    throw new Error("product_postgres_unavailable");
  } finally {
    try {
      await sql.end({ timeout: 1 });
    } catch {
      // Hyperdrive owns upstream pooling; cleanup must not mask the RPC result.
    }
  }
}

function resultStatus(result: Json): number {
  if (result.ok === true) return 200;
  switch (result.error) {
    case "owner_project_scope_not_found": return 404;
    case "owner_project_scope_ambiguous": return 409;
    case "product_owner_auth_ineligible":
    case "device_not_owned": return 403;
    default: return 400;
  }
}

export function createOwnerProjectScopeHandler(env: Env, deps: Dependencies = {}) {
  const authenticate = deps.authenticate ?? authenticateProductRequest;
  const resolve = deps.resolve ?? resolveOwnerProjectScope;

  return async function handleOwnerProjectScope(request: Request): Promise<Response> {
    if (request.method !== "GET") return json({ ok: false, error: "method_not_allowed" }, 405);
    const url = new URL(request.url);
    if (url.pathname !== PRODUCT_OWNER_PROJECT_SCOPE_PATH) {
      return json({ ok: false, error: "not_found" }, 404);
    }

    const identity = await authenticate(request, env);
    if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
    if (identity.role !== "authenticated" || !isCanonicalUuid(identity.subjectId)) {
      return json({ ok: false, error: "product_owner_identity_invalid" }, 403);
    }

    const deviceId = (url.searchParams.get("device_id") ?? "").toLowerCase();
    const repositoryFullName = canonicalGithubRepositoryFullName(
      url.searchParams.get("repository_full_name"),
    );
    if (!isCanonicalUuid(deviceId) || repositoryFullName === null) {
      return json({ ok: false, error: "owner_project_scope_invalid" }, 400);
    }

    try {
      const result = await resolve(env, identity.subjectId, deviceId, repositoryFullName);
      return json(result, resultStatus(result));
    } catch (error) {
      const code = error instanceof Error ? error.message : "product_postgres_unavailable";
      const status = code === "owner_project_scope_invalid" ? 400 : 503;
      return json({ ok: false, error: code }, status);
    }
  };
}

export function handleProductOwnerProjectScope(request: Request, env: Env): Promise<Response> {
  return createOwnerProjectScopeHandler(env)(request);
}
