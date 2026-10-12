import {
  authenticateProductRequest,
  type ProductAuthEnv,
} from "./product_auth.ts";
import { COMPUTER_DEVICE_ACTIONS } from "./product_action_scope.ts";
import { readBoundedJsonObject } from "./request_json.ts";

type JsonObject = Record<string, unknown>;

export interface ProductDeviceGrantEnv extends ProductAuthEnv {
  DB: D1Database;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const FULL_COMPUTER_CONTROL_MODE = "full-computer-control";
export const INTERACTIVE_COMPUTER_CONTROL_MODE = "interactive-computer-control";
export const FILESYSTEM_COMPUTER_CONTROL_MODE = "computer-filesystem";
export const CLIPBOARD_COMPUTER_CONTROL_MODE = "computer-clipboard";
export const PROCESS_COMPUTER_CONTROL_MODE = "computer-process-control";
const MAX_BODY_BYTES = 16 * 1024;

export const OWNER_DEVICE_COMPUTER_GRANT_PROFILES: Readonly<Record<string, readonly string[]>> = {
  [INTERACTIVE_COMPUTER_CONTROL_MODE]: [
    "computer.access_status",
    "computer.active_window",
    "computer.click",
    "computer.drag",
    "computer.focus_window",
    "computer.hotkey",
    "computer.launch_app",
    "computer.mouse_move",
    "computer.processes",
    "computer.screen_info",
    "computer.screenshot",
    "computer.scroll",
    "computer.type",
    "computer.windows",
  ],
  [FILESYSTEM_COMPUTER_CONTROL_MODE]: [
    "computer.access_status",
    "computer.directory_create",
    "computer.directory_list",
    "computer.file_stat",
    "computer.path_move",
    "computer.path_remove",
    "computer.search",
    "computer.text_patch",
    "computer.text_read",
    "computer.text_write",
  ],
  [CLIPBOARD_COMPUTER_CONTROL_MODE]: [
    "computer.clipboard_read",
    "computer.clipboard_write",
  ],
  [PROCESS_COMPUTER_CONTROL_MODE]: [
    "computer.processes",
    "computer.terminate_process",
  ],
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

function stableComputerActions(): string[] {
  return [...COMPUTER_DEVICE_ACTIONS].sort();
}

function actionsForOwnerDeviceMode(mode: string): string[] | null {
  if (mode === FULL_COMPUTER_CONTROL_MODE) return stableComputerActions();
  if (!Object.hasOwn(OWNER_DEVICE_COMPUTER_GRANT_PROFILES, mode)) return null;
  const profile = OWNER_DEVICE_COMPUTER_GRANT_PROFILES[mode];
  if (!profile || profile.length === 0) return null;
  if (profile.some((action) => !COMPUTER_DEVICE_ACTIONS.has(action))) return null;
  return [...profile].sort();
}

function ownerDeviceModeForActions(actions: string[]): string {
  const normalized = [...actions].sort();
  const full = stableComputerActions();
  if (JSON.stringify(normalized) === JSON.stringify(full)) return FULL_COMPUTER_CONTROL_MODE;
  for (const [mode, profile] of Object.entries(OWNER_DEVICE_COMPUTER_GRANT_PROFILES)) {
    const expected = [...profile].sort();
    if (JSON.stringify(normalized) === JSON.stringify(expected)) return mode;
  }
  return "custom-device-grant";
}

function onlyAllowedCreateKeys(body: JsonObject): boolean {
  const allowed = new Set(["link_id", "mode", "expires_at"]);
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

function publicGrant(row: ProductGrantRow): JsonObject {
  let actions: unknown = [];
  let projects: unknown = [];
  try { actions = JSON.parse(row.actions_json); } catch { actions = []; }
  try { projects = JSON.parse(row.projects_json); } catch { projects = []; }
  const safeActions = Array.isArray(actions)
    ? actions.filter((action): action is string => typeof action === "string")
    : [];
  return {
    id: row.id,
    subject_id: row.subject_id,
    space_id: row.space_id,
    device_id: row.device_id,
    mode: ownerDeviceModeForActions(safeActions),
    actions: safeActions,
    projects: Array.isArray(projects) ? projects : [],
    expires_at: row.expires_at,
    created_at: row.created_at,
    revoked_at: row.revoked_at,
  };
}

async function linkedDeviceForOwner(
  env: ProductDeviceGrantEnv,
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

function rowIsDeviceComputerGrant(row: ProductGrantRow): boolean {
  let actions: unknown;
  let projects: unknown;
  try { actions = JSON.parse(row.actions_json); } catch { return false; }
  try { projects = JSON.parse(row.projects_json); } catch { return false; }
  return (
    Array.isArray(actions)
    && actions.length > 0
    && actions.every(
      (action) => typeof action === "string" && COMPUTER_DEVICE_ACTIONS.has(action),
    )
    && Array.isArray(projects)
    && projects.length === 0
  );
}

/**
 * Owner-facing authorization handler for device-scoped Computer Control.
 *
 * Authority is derived from the authenticated ORDAX subject plus an active
 * device link owned by that subject. The request cannot name subject_id,
 * device_id, space_id, projects, actions, or an operator role.
 *
 * This handler is intentionally not an MCP tool. A remote model cannot mint or
 * widen this grant for itself.
 */
export async function createOwnerDeviceComputerGrant(
  request: Request,
  env: ProductDeviceGrantEnv,
): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);

  const body = await parseSmallJson(request);
  if (!body || !onlyAllowedCreateKeys(body)) {
    return json({ ok: false, error: "owner_device_grant_invalid" }, 400);
  }

  const linkId = typeof body.link_id === "string" ? body.link_id : "";
  const mode = typeof body.mode === "string" ? body.mode : "";
  const actions = actionsForOwnerDeviceMode(mode);
  const expiresAt = parseExpiry(body.expires_at);
  if (
    !UUID_RE.test(linkId)
    || actions === null
    || expiresAt === undefined
  ) {
    return json({ ok: false, error: "owner_device_grant_invalid" }, 400);
  }

  const link = await linkedDeviceForOwner(env, identity.subjectId, linkId);
  if (!link) {
    return json({ ok: false, error: "product_device_link_not_found" }, 404);
  }

  const actionsJson = JSON.stringify(actions);
  const projectsJson = "[]";
  const now = new Date().toISOString();

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
    now,
  ).run();

  const created: ProductGrantRow = {
    id: grantId,
    subject_id: identity.subjectId,
    space_id: link.space_id || null,
    device_id: link.device_id,
    actions_json: actionsJson,
    projects_json: projectsJson,
    expires_at: expiresAt,
    created_at: now,
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

/** List active/revoked device Computer grants owned by the authenticated subject. */
export async function listOwnerDeviceComputerGrants(
  request: Request,
  env: ProductDeviceGrantEnv,
): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);

  const url = new URL(request.url);
  const linkId = (url.searchParams.get("link_id") || "").trim();
  if (linkId && !UUID_RE.test(linkId)) {
    return json({ ok: false, error: "owner_device_grant_link_id_invalid" }, 400);
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
  const grants = (result.results ?? [])
    .filter(rowIsDeviceComputerGrant)
    .map(publicGrant);
  return json({ ok: true, grants });
}

/**
 * Revoke one owner-created device Computer grant. The authenticated subject
 * must own both the grant and its still-active device link provenance.
 */
export async function revokeOwnerDeviceComputerGrant(
  request: Request,
  env: ProductDeviceGrantEnv,
  grantId: string,
): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
  if (!UUID_RE.test(grantId)) {
    return json({ ok: false, error: "owner_device_grant_id_invalid" }, 400);
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

  if (!row || !rowIsDeviceComputerGrant(row)) {
    return json({ ok: false, error: "owner_device_grant_not_found" }, 404);
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
    return json({ ok: false, error: "owner_device_grant_revoke_conflict" }, 409);
  }

  return json({
    ok: true,
    revoked: true,
    grant: publicGrant({ ...row, revoked_at: revokedAt }),
  });
}

export const OWNER_DEVICE_COMPUTER_GRANT_MODE = FULL_COMPUTER_CONTROL_MODE;
