import {
  authenticateProductRequest,
  type ProductAuthEnv,
} from "./product_auth.ts";
import { APP_INTELLIGENCE_DEVICE_ACTIONS } from "./product_action_scope.ts";
import { readBoundedJsonObject } from "./request_json.ts";

type JsonObject = Record<string, unknown>;

export interface ProductDeviceIntelligenceGrantEnv extends ProductAuthEnv {
  DB: D1Database;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const APP_INTELLIGENCE_READ_MODE = "app-intelligence-read";
const MAX_BODY_BYTES = 16 * 1024;

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
  if (!Number.isFinite(parsed.getTime()) || parsed.getTime() <= Date.now()) return undefined;
  return parsed.toISOString();
}

function stableActions(): string[] {
  return [...APP_INTELLIGENCE_DEVICE_ACTIONS].sort();
}

function publicGrant(row: ProductGrantRow): JsonObject {
  return {
    id: row.id,
    subject_id: row.subject_id,
    space_id: row.space_id,
    device_id: row.device_id,
    mode: APP_INTELLIGENCE_READ_MODE,
    actions: stableActions(),
    projects: [],
    expires_at: row.expires_at,
    created_at: row.created_at,
    revoked_at: row.revoked_at,
  };
}

function rowIsAppIntelligenceGrant(row: ProductGrantRow): boolean {
  try {
    const actions = JSON.parse(row.actions_json);
    const projects = JSON.parse(row.projects_json);
    return (
      Array.isArray(actions)
      && JSON.stringify([...actions].sort()) === JSON.stringify(stableActions())
      && Array.isArray(projects)
      && projects.length === 0
    );
  } catch {
    return false;
  }
}

async function linkedDeviceForOwner(
  env: ProductDeviceIntelligenceGrantEnv,
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

export async function createOwnerDeviceIntelligenceGrant(
  request: Request,
  env: ProductDeviceIntelligenceGrantEnv,
): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);

  const body = await parseSmallJson(request);
  if (!body || Object.keys(body).some((key) => !["link_id", "mode", "expires_at"].includes(key))) {
    return json({ ok: false, error: "owner_app_intelligence_grant_invalid" }, 400);
  }
  const linkId = typeof body.link_id === "string" ? body.link_id : "";
  const mode = typeof body.mode === "string" ? body.mode : "";
  const expiresAt = parseExpiry(body.expires_at);
  if (!UUID_RE.test(linkId) || mode !== APP_INTELLIGENCE_READ_MODE || expiresAt === undefined) {
    return json({ ok: false, error: "owner_app_intelligence_grant_invalid" }, 400);
  }

  const link = await linkedDeviceForOwner(env, identity.subjectId, linkId);
  if (!link) return json({ ok: false, error: "product_device_link_not_found" }, 404);

  const actionsJson = JSON.stringify(stableActions());
  const projectsJson = "[]";
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

export async function listOwnerDeviceIntelligenceGrants(
  request: Request,
  env: ProductDeviceIntelligenceGrantEnv,
): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);

  const url = new URL(request.url);
  const linkId = (url.searchParams.get("link_id") || "").trim();
  if (linkId && !UUID_RE.test(linkId)) {
    return json({ ok: false, error: "owner_app_intelligence_grant_link_id_invalid" }, 400);
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
    grants: (result.results ?? []).filter(rowIsAppIntelligenceGrant).map(publicGrant),
  });
}

export async function revokeOwnerDeviceIntelligenceGrant(
  request: Request,
  env: ProductDeviceIntelligenceGrantEnv,
  grantId: string,
): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
  if (!UUID_RE.test(grantId)) {
    return json({ ok: false, error: "owner_app_intelligence_grant_id_invalid" }, 400);
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

  if (!row || !rowIsAppIntelligenceGrant(row)) {
    return json({ ok: false, error: "owner_app_intelligence_grant_not_found" }, 404);
  }
  if (row.revoked_at) {
    return json({ ok: true, revoked: false, already_revoked: true, grant: publicGrant(row) });
  }
  const revokedAt = new Date().toISOString();
  const update = await env.DB.prepare(
    "UPDATE ordax_product_grants SET revoked_at = ?1 WHERE id = ?2 AND subject_id = ?3 AND revoked_at IS NULL",
  ).bind(revokedAt, grantId, identity.subjectId).run();
  if ((update.meta.changes ?? 0) !== 1) {
    return json({ ok: false, error: "owner_app_intelligence_grant_revoke_conflict" }, 409);
  }
  return json({
    ok: true,
    revoked: true,
    grant: publicGrant({ ...row, revoked_at: revokedAt }),
  });
}
