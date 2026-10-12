import {
  authenticateProductRequest,
  type ProductAuthEnv,
} from "./product_auth.ts";
import { PROJECT_BROWSER_ACTIONS } from "./product_action_scope.ts";
import { readBoundedJsonObject } from "./request_json.ts";

type JsonObject = Record<string, unknown>;

export interface ProductProjectGrantEnv extends ProductAuthEnv {
  DB: D1Database;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PROJECT_SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const MAX_BODY_BYTES = 16 * 1024;
const MAX_PROJECTS = 20;

export const PROJECT_BROWSER_AUTOMATION_MODE = "project-browser-automation";

const OWNER_PROJECT_GRANT_PROFILES: Record<string, readonly string[]> = {
  [PROJECT_BROWSER_AUTOMATION_MODE]: [...PROJECT_BROWSER_ACTIONS].sort(),
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

async function parseSmallJson(request: Request): Promise<JsonObject | null> {
  return readBoundedJsonObject(request, MAX_BODY_BYTES);
}

function parseExpiry(value: unknown): string | null | undefined {
  if (value == null) return null;
  if (typeof value !== "string") return undefined;
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.getTime() <= Date.now()) {
    return undefined;
  }
  return parsed.toISOString();
}

function normalizedProjects(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_PROJECTS) {
    return null;
  }
  const projects = new Set<string>();
  for (const item of value) {
    if (typeof item !== "string" || !PROJECT_SLUG_RE.test(item)) return null;
    projects.add(item);
  }
  if (projects.size < 1) return null;
  return [...projects].sort();
}

function actionsForMode(mode: string): string[] | null {
  if (!Object.hasOwn(OWNER_PROJECT_GRANT_PROFILES, mode)) return null;
  const actions = OWNER_PROJECT_GRANT_PROFILES[mode];
  return actions?.length ? [...actions].sort() : null;
}

function modeForActions(actions: string[]): string {
  const normalized = [...actions].sort();
  for (const [mode, expectedActions] of Object.entries(OWNER_PROJECT_GRANT_PROFILES)) {
    if (JSON.stringify(normalized) === JSON.stringify([...expectedActions].sort())) {
      return mode;
    }
  }
  return "custom-project-grant";
}

function onlyAllowedCreateKeys(body: JsonObject): boolean {
  const allowed = new Set(["link_id", "mode", "projects", "expires_at"]);
  return Object.keys(body).every((key) => allowed.has(key));
}

type DeviceLinkRow = {
  id: string;
  subject_id: string;
  space_id: string;
  device_id: string;
};

type ProductGrantRow = {
  id: string;
  subject_id: string;
  space_id: string | null;
  device_id: string;
  actions_json: string;
  projects_json: string;
  expires_at: string | null;
  created_at: string;
  revoked_at: string | null;
};

function parsedGrant(row: ProductGrantRow): { actions: string[]; projects: string[] } | null {
  let actions: unknown;
  let projects: unknown;
  try { actions = JSON.parse(row.actions_json); } catch { return null; }
  try { projects = JSON.parse(row.projects_json); } catch { return null; }
  if (
    !Array.isArray(actions)
    || actions.length < 1
    || !actions.every((item) => typeof item === "string")
    || !Array.isArray(projects)
    || projects.length < 1
    || !projects.every((item) => typeof item === "string" && PROJECT_SLUG_RE.test(item))
  ) {
    return null;
  }
  return { actions, projects };
}

function rowIsOwnerProjectGrant(row: ProductGrantRow): boolean {
  const parsed = parsedGrant(row);
  return Boolean(parsed && modeForActions(parsed.actions) !== "custom-project-grant");
}

function publicGrant(row: ProductGrantRow): JsonObject {
  const parsed = parsedGrant(row) ?? { actions: [], projects: [] };
  return {
    id: row.id,
    subject_id: row.subject_id,
    space_id: row.space_id,
    device_id: row.device_id,
    mode: modeForActions(parsed.actions),
    actions: parsed.actions,
    projects: parsed.projects,
    expires_at: row.expires_at,
    created_at: row.created_at,
    revoked_at: row.revoked_at,
  };
}

async function linkedDeviceForOwner(
  env: ProductProjectGrantEnv,
  subjectId: string,
  linkId: string,
): Promise<DeviceLinkRow | null> {
  return env.DB.prepare(
    `SELECT l.id, l.subject_id, l.space_id, l.device_id
     FROM ordax_product_device_links l
     JOIN ordax_devices d ON d.id = l.device_id
     WHERE l.id = ?1
       AND l.subject_id = ?2
       AND l.revoked_at IS NULL
       AND d.revoked_at IS NULL`,
  ).bind(linkId, subjectId).first<DeviceLinkRow>();
}

/**
 * Owner-facing authorization for reviewed project-scoped capability profiles.
 *
 * The authenticated owner chooses only an active device link, a reviewed mode,
 * and bounded project slugs. The server derives the exact action set. This
 * endpoint is intentionally not exposed through MCP, so a model cannot mint or
 * widen its own grant.
 */
export async function createOwnerProjectGrant(
  request: Request,
  env: ProductProjectGrantEnv,
): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);

  const body = await parseSmallJson(request);
  if (!body || !onlyAllowedCreateKeys(body)) {
    return json({ ok: false, error: "owner_project_grant_invalid" }, 400);
  }

  const linkId = typeof body.link_id === "string" ? body.link_id : "";
  const mode = typeof body.mode === "string" ? body.mode : "";
  const actions = actionsForMode(mode);
  const projects = normalizedProjects(body.projects);
  const expiresAt = parseExpiry(body.expires_at);
  if (!UUID_RE.test(linkId) || actions === null || projects === null || expiresAt === undefined) {
    return json({ ok: false, error: "owner_project_grant_invalid" }, 400);
  }

  const link = await linkedDeviceForOwner(env, identity.subjectId, linkId);
  if (!link) {
    return json({ ok: false, error: "product_device_link_not_found" }, 404);
  }

  const actionsJson = JSON.stringify(actions);
  const projectsJson = JSON.stringify(projects);
  const existing = await env.DB.prepare(
    `SELECT id, subject_id, space_id, device_id, actions_json, projects_json,
            expires_at, created_at, revoked_at
     FROM ordax_product_grants
     WHERE subject_id = ?1
       AND device_id = ?2
       AND ((space_id IS NULL AND ?3 = '') OR space_id = ?3)
       AND actions_json = ?4
       AND projects_json = ?5
       AND revoked_at IS NULL
       AND ((expires_at IS NULL AND ?6 IS NULL) OR expires_at = ?6)
     ORDER BY created_at DESC
     LIMIT 1`,
  ).bind(
    identity.subjectId,
    link.device_id,
    link.space_id,
    actionsJson,
    projectsJson,
    expiresAt,
  ).first<ProductGrantRow>();

  if (existing) {
    return json({
      ok: true,
      replayed: true,
      mode,
      grant: publicGrant(existing),
      provenance: { link_id: link.id },
    });
  }

  const grantId = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO ordax_product_grants
      (id, subject_id, space_id, device_id, actions_json, projects_json,
       expires_at, created_at, revoked_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)`,
  ).bind(
    grantId,
    identity.subjectId,
    link.space_id || null,
    link.device_id,
    actionsJson,
    projectsJson,
    expiresAt,
    createdAt,
  ).run();

  const created: ProductGrantRow = {
    id: grantId,
    subject_id: identity.subjectId,
    space_id: link.space_id || null,
    device_id: link.device_id,
    actions_json: actionsJson,
    projects_json: projectsJson,
    expires_at: expiresAt,
    created_at: createdAt,
    revoked_at: null,
  };
  return json({
    ok: true,
    replayed: false,
    mode,
    grant: publicGrant(created),
    provenance: { link_id: link.id },
  }, 201);
}

export async function listOwnerProjectGrants(
  request: Request,
  env: ProductProjectGrantEnv,
): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);

  const url = new URL(request.url);
  const linkId = (url.searchParams.get("link_id") || "").trim();
  if (linkId && !UUID_RE.test(linkId)) {
    return json({ ok: false, error: "owner_project_grant_link_id_invalid" }, 400);
  }

  const query = linkId
    ? `SELECT DISTINCT g.id, g.subject_id, g.space_id, g.device_id, g.actions_json,
              g.projects_json, g.expires_at, g.created_at, g.revoked_at
       FROM ordax_product_grants g
       JOIN ordax_product_device_links l
         ON l.subject_id = g.subject_id
        AND l.device_id = g.device_id
        AND l.space_id = COALESCE(g.space_id, '')
       JOIN ordax_devices d ON d.id = l.device_id
       WHERE g.subject_id = ?1
         AND l.id = ?2
         AND l.revoked_at IS NULL
         AND d.revoked_at IS NULL
       ORDER BY g.created_at DESC`
    : `SELECT DISTINCT g.id, g.subject_id, g.space_id, g.device_id, g.actions_json,
              g.projects_json, g.expires_at, g.created_at, g.revoked_at
       FROM ordax_product_grants g
       JOIN ordax_product_device_links l
         ON l.subject_id = g.subject_id
        AND l.device_id = g.device_id
        AND l.space_id = COALESCE(g.space_id, '')
       JOIN ordax_devices d ON d.id = l.device_id
       WHERE g.subject_id = ?1
         AND l.revoked_at IS NULL
         AND d.revoked_at IS NULL
       ORDER BY g.created_at DESC`;
  const statement = env.DB.prepare(query);
  const result = linkId
    ? await statement.bind(identity.subjectId, linkId).all<ProductGrantRow>()
    : await statement.bind(identity.subjectId).all<ProductGrantRow>();

  return json({
    ok: true,
    grants: (result.results ?? []).filter(rowIsOwnerProjectGrant).map(publicGrant),
  });
}

export async function revokeOwnerProjectGrant(
  request: Request,
  env: ProductProjectGrantEnv,
  grantId: string,
): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
  if (!UUID_RE.test(grantId)) {
    return json({ ok: false, error: "owner_project_grant_id_invalid" }, 400);
  }

  const row = await env.DB.prepare(
    `SELECT g.id, g.subject_id, g.space_id, g.device_id, g.actions_json,
            g.projects_json, g.expires_at, g.created_at, g.revoked_at
     FROM ordax_product_grants g
     JOIN ordax_product_device_links l
       ON l.subject_id = g.subject_id
      AND l.device_id = g.device_id
      AND l.space_id = COALESCE(g.space_id, '')
     JOIN ordax_devices d ON d.id = l.device_id
     WHERE g.id = ?1
       AND g.subject_id = ?2
       AND l.revoked_at IS NULL
       AND d.revoked_at IS NULL
     LIMIT 1`,
  ).bind(grantId, identity.subjectId).first<ProductGrantRow>();

  if (!row || !rowIsOwnerProjectGrant(row)) {
    return json({ ok: false, error: "owner_project_grant_not_found" }, 404);
  }
  if (row.revoked_at) {
    return json({ ok: true, revoked: false, already_revoked: true, grant: publicGrant(row) });
  }

  const revokedAt = new Date().toISOString();
  const update = await env.DB.prepare(
    `UPDATE ordax_product_grants
     SET revoked_at = ?1
     WHERE id = ?2 AND subject_id = ?3 AND revoked_at IS NULL`,
  ).bind(revokedAt, grantId, identity.subjectId).run();
  if ((update.meta.changes ?? 0) !== 1) {
    return json({ ok: false, error: "owner_project_grant_revoke_conflict" }, 409);
  }

  return json({
    ok: true,
    revoked: true,
    grant: publicGrant({ ...row, revoked_at: revokedAt }),
  });
}
