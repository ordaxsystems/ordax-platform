import { DurableObject } from "cloudflare:workers";
import {
  authenticateProductRequest,
  productAuthConfigured,
  type ProductAuthEnv,
} from "./product_auth";
import {
  APP_INTELLIGENCE_DEVICE_ACTIONS,
  DEVICE_SCOPED_ACTIONS,
  PROJECT_BROWSER_ACTIONS,
  projectBindingMatchesScope,
} from "./product_action_scope";
import {
  createOwnerDeviceComputerGrant,
  listOwnerDeviceComputerGrants,
  revokeOwnerDeviceComputerGrant,
} from "./product_device_grants";
import {
  createOwnerProjectGrant,
  listOwnerProjectGrants,
  revokeOwnerProjectGrant,
} from "./product_project_grants";
import {
  createOwnerDeviceIntelligenceGrant,
  listOwnerDeviceIntelligenceGrants,
  revokeOwnerDeviceIntelligenceGrant,
} from "./product_intelligence_grants";
import { handleOrdaxMcp } from "./mcp_http";
import { scopeProductResult } from "./product_results";
import { oauthConsentResponse } from "./oauth_consent";
import { openAiAppsChallenge, publicProductPage } from "./public_pages";
import { readBoundedJsonObject } from "./request_json";
import { handleProductDevicePresence, PRODUCT_DEVICE_PRESENCE_PATH } from "./product_device_presence";
import {
  enrollProductDevice,
  identifyProductDevice,
  ProductPostgresError,
  productPostgresConfigured,
  type ProductPostgresEnv,
} from "./product_postgres_store";

interface Env extends ProductAuthEnv, ProductPostgresEnv {
  SUPABASE_PUBLISHABLE_KEY?: string;
  DB: D1Database;
  ARTIFACTS: R2Bucket;
  DEVICE_SESSIONS: DurableObjectNamespace<DeviceSession>;
  ORDAX_OPERATOR_TOKEN: string;
  OPENAI_APPS_CHALLENGE?: string;
}

type JsonObject = Record<string, unknown>;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX64_RE = /^[0-9a-f]{64}$/i;
const DIRECT_ARTIFACT_MAX_BYTES = 90 * 1024 * 1024;
const MULTIPART_ARTIFACT_MAX_BYTES = DIRECT_ARTIFACT_MAX_BYTES * 10_000;
const MULTIPART_MAX_PARTS = 10_000;
const CONTROL_PLANE_CAPABILITIES = [
  "artifact_multipart_v1",
  "terminal_report_recovery_v1",
  "product_grant_store_v1",
  "product_grant_resolution_v1",
  "product_subject_auth_jwks_v1",
  "product_readonly_actions_v1",
  "product_typed_actions_v2",
];

const ACTION_PREFIXES = [
  "blender.", "unity.", "git.", "project.", "projects.", "workspace.", "artifact.",
  "observation.", "game_assets.", "geo.", "visual.", "agent.", "terminal.", "handoff.", "continuity.",
  "browser.", "computer.", "process.", "intelligence.",
];

const PRODUCT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$/;
const PROJECT_SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const PRODUCT_READ_ONLY_ACTIONS = new Set([
  ...APP_INTELLIGENCE_DEVICE_ACTIONS,
  "projects.list",
  "workspace.repository_catalog",
  "project.inventory",
  "project.text_read",
  "workspace.file_stat",
  "workspace.directory_list",
  "workspace.text_read",
  "project.search_text",
  "project.text_read_batch",
  "project.preview_status",
  "agent.project_health",
  "agent.project_briefing",
  "continuity.get",
  "artifacts.list",
  "git.status",
  "git.diff",
  "artifact.preview",
  "handoff.get",
  "browser.status",
  "browser.list",
  "browser.snapshot",
  "browser.screenshot",
  "computer.windows",
  "computer.active_window",
  "computer.screenshot",
  "computer.screen_info",
  "computer.clipboard_read",
  "computer.access_status",
  "computer.file_stat",
  "computer.directory_list",
  "computer.text_read",
  "computer.search",
  "computer.processes",
  "process.status",
  "process.list",
  "process.logs",
]);
const PRODUCT_TYPED_ACTIONS_V2 = new Set([
  "continuity.update",
  "workspace.project_create",
  "workspace.bind_project",
  "handoff.create",
  "workspace.text_write",
  "workspace.text_patch",
  "workspace.directory_create",
  "workspace.path_remove",
  "workspace.path_move",
  "git.command",
  "terminal.exec",
  "process.start",
  "process.write_stdin",
  "process.stop",
  "browser.start",
  "browser.navigate",
  "browser.click",
  "browser.type",
  "browser.stop",
  "computer.focus_window",
  "computer.click",
  "computer.mouse_move",
  "computer.drag",
  "computer.scroll",
  "computer.clipboard_write",
  "computer.launch_app",
  "computer.type",
  "computer.hotkey",
  "computer.text_write",
  "computer.text_patch",
  "computer.directory_create",
  "computer.path_move",
  "computer.path_remove",
  "computer.terminate_process",
  "project.text_write",
  "project.text_patch",
  "blender.live_status",
  "blender.live_scene_snapshot",
  "blender.live_object_inspect",
  "blender.live_modeling_schema",
  "blender.live_start",
  "blender.live_object_transform",
  "blender.live_create_primitive",
  "blender.live_material_apply",
  "blender.live_save",
]);
const PRODUCT_ACTIONS = new Set([
  ...PRODUCT_READ_ONLY_ACTIONS,
  ...PRODUCT_TYPED_ACTIONS_V2,
]);
const PRODUCT_PROJECT_ACTIONS = new Set([
  "project.inventory",
  "project.text_read",
  "project.search_text",
  "project.text_read_batch",
  "project.preview_status",
  "project.text_write",
  "project.text_patch",
  "agent.project_health",
  "agent.project_briefing",
  "continuity.get",
  "continuity.update",
  "artifacts.list",
  "git.status",
  "git.diff",
  "artifact.preview",
  "handoff.create",
  "workspace.text_write",
  "workspace.text_patch",
  "workspace.directory_create",
  "workspace.path_remove",
  "workspace.path_move",
  "git.command",
  "terminal.exec",
  "process.status",
  "process.list",
  "process.logs",
  "process.start",
  "process.write_stdin",
  "process.stop",
  ...PROJECT_BROWSER_ACTIONS,
  "project.text_write",
  "project.text_patch",
  "blender.live_status",
  "blender.live_scene_snapshot",
  "blender.live_object_inspect",
  "blender.live_modeling_schema",
  "blender.live_start",
  "blender.live_object_transform",
  "blender.live_create_primitive",
  "blender.live_material_apply",
  "blender.live_save",
]);

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function nowIso(): string {
  return new Date().toISOString();
}

function randomHex(bytes = 32): string {
  const value = crypto.getRandomValues(new Uint8Array(bytes));
  return [...value].map((item) => item.toString(16).padStart(2, "0")).join("");
}

async function sha256Text(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)]
    .map((item) => item.toString(16).padStart(2, "0"))
    .join("");
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function hexToArrayBuffer(value: string): ArrayBuffer {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes.buffer;
}

function arrayBufferToHex(value: ArrayBuffer): string {
  return [...new Uint8Array(value)]
    .map((item) => item.toString(16).padStart(2, "0"))
    .join("");
}

function isRecord(value: unknown): value is JsonObject {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function canonicalJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((item) => canonicalJsonValue(item));
  if (isRecord(value)) {
    const normalized: JsonObject = {};
    for (const key of Object.keys(value).sort()) {
      normalized[key] = canonicalJsonValue(value[key]);
    }
    return normalized;
  }
  return value;
}

function stableJson(value: unknown): string {
  return JSON.stringify(canonicalJsonValue(value));
}

function canonicalStoredJson(value: string | null): string | null {
  if (!value) return null;
  try {
    return stableJson(JSON.parse(value));
  } catch {
    return null;
  }
}

function actionAllowed(value: string): boolean {
  return value === "ordax.dev.adapter.invoke"
    || ACTION_PREFIXES.some((prefix) => value.startsWith(prefix));
}

async function operatorAuthorized(request: Request, env: Env): Promise<boolean> {
  const auth = request.headers.get("authorization") ?? "";
  if (!env.ORDAX_OPERATOR_TOKEN || !auth.startsWith("Bearer ")) return false;
  const supplied = auth.slice(7);
  if (supplied.length !== env.ORDAX_OPERATOR_TOKEN.length) return false;
  const [a, b] = await Promise.all([
    sha256Text(supplied),
    sha256Text(env.ORDAX_OPERATOR_TOKEN),
  ]);
  return a === b;
}

async function authenticateDevice(
  env: Env,
  deviceId: string,
  rawToken: string,
): Promise<{ ok: true } | { ok: false; error: string }> {
  if (!UUID_RE.test(deviceId) || rawToken.length < 32 || rawToken.length > 512) {
    return { ok: false, error: "device_auth_required" };
  }
  const digest = await sha256Text(rawToken);
  const row = await env.DB.prepare(
    "SELECT id, revoked_at FROM ordax_devices WHERE id = ?1 AND token_sha256 = ?2",
  ).bind(deviceId, digest).first<{ id: string; revoked_at: string | null }>();
  if (!row) return { ok: false, error: "invalid_device_token" };
  if (row.revoked_at) return { ok: false, error: "device_revoked" };
  return { ok: true };
}

function parseRuntimeIdentityHeaders(request: Request): {
  agentInstanceId: string;
  bootId: string;
} | null {
  const agentInstanceId = request.headers.get("X-Ordax-Agent-Instance") ?? "";
  const bootId = request.headers.get("X-Ordax-Boot-Id") ?? "";
  if (!UUID_RE.test(agentInstanceId) || !UUID_RE.test(bootId)) return null;
  return { agentInstanceId, bootId };
}

async function wakeDeviceSession(
  env: Env,
  deviceId: string,
  targetAgentInstanceId?: string,
  targetBootId?: string,
): Promise<void> {
  const id = env.DEVICE_SESSIONS.idFromName(deviceId);
  const headers = new Headers({ "X-Ordax-Device-Id": deviceId });
  if (targetAgentInstanceId && targetBootId) {
    headers.set("X-Ordax-Target-Agent-Instance", targetAgentInstanceId);
    headers.set("X-Ordax-Target-Boot-Id", targetBootId);
  }
  await env.DEVICE_SESSIONS.get(id).fetch("https://device.internal/wake", {
    method: "POST",
    headers,
  });
}

async function parseSmallJson(request: Request, maxBytes = 128 * 1024): Promise<JsonObject | null> {
  return readBoundedJsonObject(request, maxBytes);
}

async function deviceSetup(request: Request, env: Env): Promise<Response> {
  const body = await parseSmallJson(request, 16 * 1024);
  if (!body) return json({ ok: false, error: "request_invalid" }, 400);

  const operation = typeof body.operation === "string" ? body.operation : "";
  const binding = typeof body.machine_binding_sha256 === "string"
    ? body.machine_binding_sha256.toLowerCase()
    : "";
  if (!HEX64_RE.test(binding)) {
    return json({ ok: false, error: "request_invalid" }, 400);
  }

  if (operation === "identify") {
    const rawToken = request.headers.get("X-Ordax-Device-Token") ?? "";
    if (rawToken.length < 32 || rawToken.length > 512) {
      return json({ ok: false, error: "device_auth_required" }, 401);
    }
    const digest = await sha256Text(rawToken);
    try {
      // Product identity is owned by PostgreSQL; never consult engineering D1.
      const identified = await identifyProductDevice(env, {
        tokenSha256: digest,
        machineBindingSha256: binding,
      });
      if (identified.ok !== true || typeof identified.device_id !== "string"
          || !UUID_RE.test(identified.device_id)) {
        return json({ ok: false, error: "device_token_invalid" }, 401);
      }
      return json({
        ok: true,
        protocol: "cloudflare-v3",
        device_id: identified.device_id,
      });
    } catch (error) {
      if (error instanceof ProductPostgresError) {
        return json({ ok: false, error: error.code }, error.status);
      }
      return json({ ok: false, error: "product_postgres_unavailable" }, 503);
    }
  }

  if (operation !== "enroll") {
    return json({ ok: false, error: "operation_not_allowed" }, 400);
  }

  const tokenSha256 = typeof body.token_sha256 === "string"
    ? body.token_sha256.toLowerCase()
    : "";
  const deviceName = typeof body.device_name === "string"
    ? body.device_name.trim()
    : "";
  const deviceKind = body.device_kind;
  const channel = body.channel;
  if (
    !HEX64_RE.test(tokenSha256)
    || deviceName.length < 1
    || deviceName.length > 120
    || /[\x00-\x1f\x7f]/.test(deviceName)
    || (deviceKind !== "desktop" && deviceKind !== "laptop"
      && deviceKind !== "mobile" && deviceKind !== "server"
      && deviceKind !== "other")
    || (channel !== "stable" && channel !== "development")
  ) {
    return json({ ok: false, error: "request_invalid" }, 400);
  }

  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) {
    return json({ ok: false, error: identity.error }, identity.status);
  }

  if (!UUID_RE.test(identity.subjectId)) {
    return json({ ok: false, error: "device_owner_invalid" }, 403);
  }
  try {
    // The canonical RPC atomically enforces owner binding, credential uniqueness,
    // and the 10-per-hour re-enrollment limit; no DO business persistence.
    const enrolled = await enrollProductDevice(env, {
      ownerUserId: identity.subjectId,
      deviceName,
      deviceKind,
      channel,
      tokenSha256,
      machineBindingSha256: binding,
    });
    if (enrolled.ok !== true || typeof enrolled.device_id !== "string"
        || !UUID_RE.test(enrolled.device_id)) {
      const code = typeof enrolled.error === "string"
        ? enrolled.error : "device_enrollment_invalid";
      const statuses: Record<string, number> = {
        device_enrollment_invalid: 400,
        device_owner_not_found: 403,
        device_owner_mismatch: 403,
        device_credential_conflict: 409,
        device_credential_missing: 409,
        enrollment_rate_limited: 429,
      };
      return json({ ok: false, error: code }, statuses[code] ?? 502);
    }
    return json({
      ok: true,
      protocol: "cloudflare-v3",
      device_id: enrolled.device_id,
    });
  } catch (error) {
    if (error instanceof ProductPostgresError) {
      return json({ ok: false, error: error.code }, error.status);
    }
    return json({ ok: false, error: "product_postgres_unavailable" }, 503);
  }
}


type ProductGrantRow = {
  id: string;
  subject_id: string;
  space_id: string | null;
  device_id: string | null;
  actions_json: string;
  projects_json: string;
  expires_at: string | null;
  created_at: string;
  revoked_at: string | null;
};

function normalizedStringArray(
  value: unknown,
  options: {
    maxItems: number;
    validator: (item: string) => boolean;
    allowed?: Set<string>;
  },
): string[] | null {
  const { maxItems, validator, allowed } = options;
  if (!Array.isArray(value) || value.length > maxItems) return null;
  const result = new Set<string>();
  for (const item of value) {
    if (
      typeof item !== "string"
      || !validator(item)
      || (allowed && !allowed.has(item))
    ) {
      return null;
    }
    result.add(item);
  }
  return [...result].sort();
}

function publicProductGrant(row: ProductGrantRow): JsonObject {
  let actions: unknown = [];
  let projects: unknown = [];
  try { actions = JSON.parse(row.actions_json); } catch { actions = []; }
  try { projects = JSON.parse(row.projects_json); } catch { projects = []; }
  return {
    id: row.id,
    subject_id: row.subject_id,
    space_id: row.space_id,
    device_id: row.device_id,
    actions: Array.isArray(actions) ? actions : [],
    projects: Array.isArray(projects) ? projects : [],
    expires_at: row.expires_at,
    created_at: row.created_at,
    revoked_at: row.revoked_at,
  };
}

type ProductGrantInput = {
  actions: string[];
  projects: string[];
  expiresAt: string | null;
};

function parseProductGrantInput(body: JsonObject): ProductGrantInput | null {
  const actions = normalizedStringArray(body.actions, {
    maxItems: 128,
    validator: (item) => PRODUCT_ID_RE.test(item),
    allowed: PRODUCT_ACTIONS,
  });
  const projects = normalizedStringArray(body.projects ?? [], {
    maxItems: 100,
    validator: (item) => PROJECT_SLUG_RE.test(item),
  });

  if (
    !actions
    || actions.length === 0
    || !projects
    || (actions.some((item) => PRODUCT_PROJECT_ACTIONS.has(item)) && projects.length === 0)
  ) {
    return null;
  }

  let expiresAt: string | null = null;
  if (body.expires_at != null) {
    if (typeof body.expires_at !== "string") return null;
    const parsed = new Date(body.expires_at);
    if (!Number.isFinite(parsed.getTime()) || parsed.getTime() <= Date.now()) {
      return null;
    }
    expiresAt = parsed.toISOString();
  }

  return { actions, projects, expiresAt };
}

async function persistProductGrant(
  env: Env,
  input: {
    subjectId: string;
    spaceId: string | null;
    deviceId: string;
    grant: ProductGrantInput;
  },
): Promise<JsonObject> {
  const grantId = crypto.randomUUID();
  const createdAt = nowIso();
  await env.DB.prepare(
    `INSERT INTO ordax_product_grants
      (id, subject_id, space_id, device_id, actions_json, projects_json,
       expires_at, created_at, revoked_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)`,
  ).bind(
    grantId,
    input.subjectId,
    input.spaceId,
    input.deviceId,
    stableJson(input.grant.actions),
    stableJson(input.grant.projects),
    input.grant.expiresAt,
    createdAt,
  ).run();

  return {
    id: grantId,
    subject_id: input.subjectId,
    space_id: input.spaceId,
    device_id: input.deviceId,
    actions: input.grant.actions,
    projects: input.grant.projects,
    expires_at: input.grant.expiresAt,
    created_at: createdAt,
    revoked_at: null,
  };
}

async function createProductGrant(request: Request, env: Env): Promise<Response> {
  if (!await operatorAuthorized(request, env)) {
    return json({ ok: false, error: "operator_unauthorized" }, 401);
  }
  const body = await parseSmallJson(request, 32 * 1024);
  if (!body) return json({ ok: false, error: "invalid_json" }, 400);

  const subjectId = typeof body.subject_id === "string" ? body.subject_id : "";
  const spaceId = body.space_id == null
    ? null
    : typeof body.space_id === "string" ? body.space_id : "";
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  const grantInput = parseProductGrantInput(body);

  if (
    !PRODUCT_ID_RE.test(subjectId)
    || (spaceId !== null && !PRODUCT_ID_RE.test(spaceId))
    || !UUID_RE.test(deviceId)
    || !grantInput
  ) {
    return json({ ok: false, error: "product_grant_invalid" }, 400);
  }

  const device = await env.DB.prepare(
    "SELECT id FROM ordax_devices WHERE id = ?1 AND revoked_at IS NULL",
  ).bind(deviceId).first();
  if (!device) return json({ ok: false, error: "device_not_found" }, 404);

  const grant = await persistProductGrant(env, {
    subjectId,
    spaceId,
    deviceId,
    grant: grantInput,
  });
  return json({ ok: true, grant }, 201);
}

async function createProductGrantFromLink(
  request: Request,
  env: Env,
): Promise<Response> {
  if (!await operatorAuthorized(request, env)) {
    return json({ ok: false, error: "operator_unauthorized" }, 401);
  }
  const body = await parseSmallJson(request, 32 * 1024);
  if (!body) return json({ ok: false, error: "invalid_json" }, 400);

  const linkId = typeof body.link_id === "string" ? body.link_id : "";
  const grantInput = parseProductGrantInput(body);
  if (
    !UUID_RE.test(linkId)
    || !grantInput
    || body.subject_id != null
    || body.device_id != null
    || body.space_id != null
  ) {
    return json({ ok: false, error: "product_grant_invalid" }, 400);
  }

  const link = await env.DB.prepare(
    `SELECT l.subject_id, l.space_id, l.device_id
     FROM ordax_product_device_links l
     JOIN ordax_devices d ON d.id = l.device_id
     WHERE l.id = ?1
       AND l.revoked_at IS NULL
       AND d.revoked_at IS NULL`,
  ).bind(linkId).first<{
    subject_id: string;
    space_id: string;
    device_id: string;
  }>();
  if (!link) {
    return json({ ok: false, error: "product_device_link_not_found" }, 404);
  }

  const grant = await persistProductGrant(env, {
    subjectId: link.subject_id,
    spaceId: link.space_id || null,
    deviceId: link.device_id,
    grant: grantInput,
  });
  return json({
    ok: true,
    grant,
    provenance: {
      link_id: linkId,
      subject_id: link.subject_id,
      space_id: link.space_id || null,
      device_id: link.device_id,
    },
  }, 201);
}

async function listProductGrants(request: Request, env: Env): Promise<Response> {
  if (!await operatorAuthorized(request, env)) {
    return json({ ok: false, error: "operator_unauthorized" }, 401);
  }

  const url = new URL(request.url);
  const subjectId = url.searchParams.get("subject_id");
  const deviceId = url.searchParams.get("device_id");
  if (subjectId !== null && !PRODUCT_ID_RE.test(subjectId)) {
    return json({ ok: false, error: "subject_id_invalid" }, 400);
  }
  if (deviceId !== null && !UUID_RE.test(deviceId)) {
    return json({ ok: false, error: "device_id_invalid" }, 400);
  }

  const where: string[] = [];
  const values: string[] = [];
  if (subjectId !== null) {
    values.push(subjectId);
    where.push(`subject_id = ?${values.length}`);
  }
  if (deviceId !== null) {
    values.push(deviceId);
    where.push(`device_id = ?${values.length}`);
  }
  const condition = where.length ? " WHERE " + where.join(" AND ") : "";
  const query =
    `SELECT id, subject_id, space_id, device_id, actions_json, projects_json,
            expires_at, created_at, revoked_at
     FROM ordax_product_grants${condition}
     ORDER BY created_at DESC LIMIT 200`;

  const rows = await env.DB.prepare(query).bind(...values).all<ProductGrantRow>();
  return json({
    ok: true,
    grants: (rows.results ?? []).map((row) => publicProductGrant(row)),
  });
}

async function resolveProductGrantForContext(
  env: Env,
  context: {
    subjectId: string;
    spaceId: string | null;
    deviceId: string;
    action: string;
    project: string | null;
  },
): Promise<ProductGrantRow | null> {
  if (!projectBindingMatchesScope(
    context.action,
    context.project,
    PRODUCT_PROJECT_ACTIONS,
  )) {
    return null;
  }

  const now = nowIso();
  const rows = await env.DB.prepare(
    `SELECT id, subject_id, space_id, device_id, actions_json, projects_json,
            expires_at, created_at, revoked_at
     FROM ordax_product_grants
     WHERE subject_id = ?1
       AND revoked_at IS NULL
       AND (expires_at IS NULL OR expires_at > ?2)
       AND device_id = ?3
       AND ((space_id IS NULL AND ?4 IS NULL) OR space_id = ?4)
     ORDER BY
       CASE WHEN space_id IS NULL THEN 0 ELSE 1 END DESC,
       created_at DESC
     LIMIT 100`,
  ).bind(
    context.subjectId,
    now,
    context.deviceId,
    context.spaceId,
  ).all<ProductGrantRow>();

  for (const row of rows.results ?? []) {
    let actions: unknown = [];
    let projects: unknown = [];
    try { actions = JSON.parse(row.actions_json); } catch { continue; }
    try { projects = JSON.parse(row.projects_json); } catch { continue; }
    if (
      !Array.isArray(actions)
      || !actions.every((item) => typeof item === "string")
      || !actions.includes(context.action)
      || !Array.isArray(projects)
      || !projects.every((item) => typeof item === "string")
    ) {
      continue;
    }
    if (DEVICE_SCOPED_ACTIONS.has(context.action)) {
      if (projects.length !== 0 || context.project !== null) continue;
    } else if (PRODUCT_PROJECT_ACTIONS.has(context.action)) {
      if (context.project === null || !projects.includes(context.project)) continue;
    }
    return row;
  }
  return null;
}

async function resolveProductGrantAdmin(
  request: Request,
  env: Env,
): Promise<Response> {
  if (!await operatorAuthorized(request, env)) {
    return json({ ok: false, error: "operator_unauthorized" }, 401);
  }
  const body = await parseSmallJson(request, 16 * 1024);
  if (!body) return json({ ok: false, error: "invalid_json" }, 400);

  const subjectId = typeof body.subject_id === "string" ? body.subject_id : "";
  const spaceId = body.space_id == null
    ? null
    : typeof body.space_id === "string" ? body.space_id : "";
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  const action = typeof body.action === "string" ? body.action : "";
  const project = body.project == null
    ? null
    : typeof body.project === "string" ? body.project : "";

  if (
    !PRODUCT_ID_RE.test(subjectId)
    || (spaceId !== null && !PRODUCT_ID_RE.test(spaceId))
    || !UUID_RE.test(deviceId)
    || !PRODUCT_ACTIONS.has(action)
    || (project !== null && !PROJECT_SLUG_RE.test(project))
    || !projectBindingMatchesScope(action, project, PRODUCT_PROJECT_ACTIONS)
  ) {
    return json({ ok: false, error: "product_grant_resolution_invalid" }, 400);
  }

  const device = await env.DB.prepare(
    "SELECT id FROM ordax_devices WHERE id = ?1 AND revoked_at IS NULL",
  ).bind(deviceId).first();
  if (!device) return json({ ok: false, error: "device_not_found" }, 404);

  const grant = await resolveProductGrantForContext(env, {
    subjectId,
    spaceId,
    deviceId,
    action,
    project,
  });
  if (!grant) {
    return json({ ok: false, error: "product_grant_not_resolved" }, 404);
  }

  return json({
    ok: true,
    grant: publicProductGrant(grant),
    resolved_for: {
      subject_id: subjectId,
      space_id: spaceId,
      device_id: deviceId,
      action,
      project,
    },
  });
}

async function revokeProductGrant(
  request: Request,
  env: Env,
  grantId: string,
): Promise<Response> {
  if (!await operatorAuthorized(request, env)) {
    return json({ ok: false, error: "operator_unauthorized" }, 401);
  }
  if (!UUID_RE.test(grantId)) {
    return json({ ok: false, error: "product_grant_id_invalid" }, 400);
  }

  const existing = await env.DB.prepare(
    `SELECT id, subject_id, space_id, device_id, actions_json, projects_json,
            expires_at, created_at, revoked_at
     FROM ordax_product_grants WHERE id = ?1`,
  ).bind(grantId).first<ProductGrantRow>();
  if (!existing) return json({ ok: false, error: "product_grant_not_found" }, 404);

  if (existing.revoked_at) {
    return json({
      ok: true,
      revoked: false,
      already_revoked: true,
      grant: publicProductGrant(existing),
    });
  }

  const revokedAt = nowIso();
  await env.DB.prepare(
    "UPDATE ordax_product_grants SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
  ).bind(revokedAt, grantId).run();
  return json({
    ok: true,
    revoked: true,
    grant: publicProductGrant({ ...existing, revoked_at: revokedAt }),
  });
}

async function listProductTargets(request: Request, env: Env): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);

  const url = new URL(request.url);
  const spaceId = url.searchParams.get("space_id");
  if (spaceId !== null && !PRODUCT_ID_RE.test(spaceId)) {
    return json({ ok: false, error: "space_id_invalid" }, 400);
  }

  const now = nowIso();
  const rows = await env.DB.prepare(
    `SELECT
       g.id AS grant_id, g.space_id, g.device_id, g.actions_json, g.projects_json,
       g.expires_at, g.created_at,
       d.name AS device_name, d.last_seen_at,
       (
         SELECT l.id
         FROM ordax_product_device_links l
         WHERE l.subject_id = g.subject_id
           AND l.device_id = g.device_id
           AND l.revoked_at IS NULL
           AND COALESCE(l.space_id, '') = COALESCE(g.space_id, '')
         ORDER BY l.created_at DESC
         LIMIT 1
       ) AS link_id
     FROM ordax_product_grants g
     JOIN ordax_devices d ON d.id = g.device_id
     WHERE g.subject_id = ?1
       AND g.device_id IS NOT NULL
       AND g.revoked_at IS NULL
       AND d.revoked_at IS NULL
       AND (g.expires_at IS NULL OR g.expires_at > ?2)
       AND (?3 IS NULL OR g.space_id = ?3)
     ORDER BY d.name ASC, g.created_at DESC
     LIMIT 200`,
  ).bind(identity.subjectId, now, spaceId).all<{
    grant_id: string;
    space_id: string | null;
    device_id: string;
    actions_json: string;
    projects_json: string;
    expires_at: string | null;
    created_at: string;
    device_name: string;
    last_seen_at: string | null;
    link_id: string | null;
  }>();

  const devices = new Map<string, JsonObject>();
  for (const row of rows.results ?? []) {
    let actions: unknown = [];
    let projects: unknown = [];
    try { actions = JSON.parse(row.actions_json); } catch { continue; }
    try { projects = JSON.parse(row.projects_json); } catch { continue; }
    if (
      !Array.isArray(actions)
      || !actions.every((item) => typeof item === "string")
      || !Array.isArray(projects)
      || !projects.every((item) => typeof item === "string")
    ) {
      continue;
    }
    let entry = devices.get(row.device_id) as (JsonObject & { grants?: unknown[] }) | undefined;
    if (!entry) {
      entry = {
        device_id: row.device_id,
        name: row.device_name,
        last_seen_at: row.last_seen_at,
        link_id: row.link_id,
        grants: [],
      };
      devices.set(row.device_id, entry);
    }
    (entry.grants as unknown[]).push({
      grant_id: row.grant_id,
      space_id: row.space_id,
      actions,
      projects,
      expires_at: row.expires_at,
      created_at: row.created_at,
    });
  }

  return json({ ok: true, targets: [...devices.values()] });
}

async function createProductDevicePairing(
  request: Request,
  env: Env,
): Promise<Response> {
  const deviceId = request.headers.get("X-Ordax-Device-Id") ?? "";
  const token = request.headers.get("X-Ordax-Device-Token") ?? "";
  const auth = await authenticateDevice(env, deviceId, token);
  if (!auth.ok) return json({ ok: false, error: auth.error }, 401);

  const now = new Date();
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + 10 * 60 * 1000).toISOString();
  const pairingId = crypto.randomUUID();
  const secret = randomHex(32);
  const secretSha256 = await sha256Text(secret);

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE ordax_product_device_pairings
       SET expires_at = ?1
       WHERE device_id = ?2 AND claimed_at IS NULL AND expires_at > ?1`,
    ).bind(createdAt, deviceId),
    env.DB.prepare(
      `INSERT INTO ordax_product_device_pairings
        (id, device_id, secret_sha256, created_at, expires_at,
         claimed_at, claimed_subject_id, claimed_space_id)
       VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, NULL)`,
    ).bind(pairingId, deviceId, secretSha256, createdAt, expiresAt),
  ]);

  return json({
    ok: true,
    pairing: {
      pairing_id: pairingId,
      pairing_secret: secret,
      expires_at: expiresAt,
    },
  }, 201);
}

async function claimProductDevicePairing(
  request: Request,
  env: Env,
): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);

  const body = await parseSmallJson(request, 16 * 1024);
  if (!body) return json({ ok: false, error: "product_pairing_invalid" }, 400);

  const pairingId = typeof body.pairing_id === "string" ? body.pairing_id : "";
  const pairingSecret = typeof body.pairing_secret === "string"
    ? body.pairing_secret.toLowerCase()
    : "";
  const spaceId = body.space_id == null
    ? ""
    : typeof body.space_id === "string" ? body.space_id : "";

  if (
    !UUID_RE.test(pairingId)
    || !HEX64_RE.test(pairingSecret)
    || (spaceId !== "" && !PRODUCT_ID_RE.test(spaceId))
  ) {
    return json({ ok: false, error: "product_pairing_invalid" }, 400);
  }

  const secretSha256 = await sha256Text(pairingSecret);
  const now = nowIso();
  const row = await env.DB.prepare(
    `SELECT p.device_id, p.secret_sha256, p.expires_at, p.claimed_at,
            p.claimed_subject_id, p.claimed_space_id
     FROM ordax_product_device_pairings p
     JOIN ordax_devices d ON d.id = p.device_id
     WHERE p.id = ?1 AND d.revoked_at IS NULL`,
  ).bind(pairingId).first<{
    device_id: string;
    secret_sha256: string;
    expires_at: string;
    claimed_at: string | null;
    claimed_subject_id: string | null;
    claimed_space_id: string | null;
  }>();

  if (!row || row.secret_sha256 !== secretSha256) {
    return json({ ok: false, error: "product_pairing_not_found" }, 404);
  }
  if (row.expires_at <= now) {
    return json({ ok: false, error: "product_pairing_expired" }, 410);
  }
  if (row.claimed_at) {
    if (
      row.claimed_subject_id !== identity.subjectId
      || (row.claimed_space_id ?? "") !== spaceId
    ) {
      return json({ ok: false, error: "product_pairing_already_claimed" }, 409);
    }

    const existingLink = await env.DB.prepare(
      `SELECT l.id, l.space_id, l.device_id, l.created_at,
              d.name AS device_name, d.last_seen_at
       FROM ordax_product_device_links l
       JOIN ordax_devices d ON d.id = l.device_id
       WHERE l.subject_id = ?1 AND l.device_id = ?2 AND l.space_id = ?3
         AND l.revoked_at IS NULL AND d.revoked_at IS NULL`,
    ).bind(identity.subjectId, row.device_id, spaceId).first<{
      id: string;
      space_id: string;
      device_id: string;
      created_at: string;
      device_name: string;
      last_seen_at: string | null;
    }>();

    if (!existingLink) {
      return json({ ok: false, error: "product_pairing_already_claimed" }, 409);
    }
    return json({
      ok: true,
      link: {
        link_id: existingLink.id,
        space_id: existingLink.space_id || null,
        device_id: existingLink.device_id,
        device_name: existingLink.device_name,
        last_seen_at: existingLink.last_seen_at,
        created_at: existingLink.created_at,
      },
      replayed: true,
    });
  }

  if (!row.claimed_at) {
    const claim = await env.DB.prepare(
      `UPDATE ordax_product_device_pairings
       SET claimed_at = ?1, claimed_subject_id = ?2, claimed_space_id = ?3
       WHERE id = ?4
         AND secret_sha256 = ?5
         AND claimed_at IS NULL
         AND expires_at > ?1`,
    ).bind(
      now,
      identity.subjectId,
      spaceId,
      pairingId,
      secretSha256,
    ).run();

    if ((claim.meta.changes ?? 0) !== 1) {
      return json({ ok: false, error: "product_pairing_claim_conflict" }, 409);
    }
  }

  const proposedLinkId = crypto.randomUUID();
  await env.DB.prepare(
    `INSERT INTO ordax_product_device_links
      (id, subject_id, space_id, device_id, created_at, revoked_at)
     VALUES (?1, ?2, ?3, ?4, ?5, NULL)
     ON CONFLICT(subject_id, device_id, space_id)
     DO UPDATE SET revoked_at = NULL`,
  ).bind(
    proposedLinkId,
    identity.subjectId,
    spaceId,
    row.device_id,
    now,
  ).run();

  const link = await env.DB.prepare(
    `SELECT l.id, l.space_id, l.device_id, l.created_at,
            d.name AS device_name, d.last_seen_at
     FROM ordax_product_device_links l
     JOIN ordax_devices d ON d.id = l.device_id
     WHERE l.subject_id = ?1 AND l.device_id = ?2 AND l.space_id = ?3
       AND l.revoked_at IS NULL`,
  ).bind(identity.subjectId, row.device_id, spaceId).first<{
    id: string;
    space_id: string;
    device_id: string;
    created_at: string;
    device_name: string;
    last_seen_at: string | null;
  }>();

  if (!link) return json({ ok: false, error: "product_device_link_failed" }, 500);
  return json({
    ok: true,
    link: {
      link_id: link.id,
      space_id: link.space_id || null,
      device_id: link.device_id,
      device_name: link.device_name,
      last_seen_at: link.last_seen_at,
      created_at: link.created_at,
    },
  }, 201);
}

async function listProductDeviceLinks(
  request: Request,
  env: Env,
): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);

  const url = new URL(request.url);
  const spaceId = url.searchParams.get("space_id");
  if (spaceId !== null && !PRODUCT_ID_RE.test(spaceId)) {
    return json({ ok: false, error: "space_id_invalid" }, 400);
  }

  const rows = await env.DB.prepare(
    `SELECT l.id, l.space_id, l.device_id, l.created_at,
            d.name AS device_name, d.last_seen_at
     FROM ordax_product_device_links l
     JOIN ordax_devices d ON d.id = l.device_id
     WHERE l.subject_id = ?1
       AND l.revoked_at IS NULL
       AND d.revoked_at IS NULL
       AND (?2 IS NULL OR l.space_id = ?2)
     ORDER BY d.name ASC, l.created_at DESC
     LIMIT 200`,
  ).bind(identity.subjectId, spaceId).all<{
    id: string;
    space_id: string;
    device_id: string;
    created_at: string;
    device_name: string;
    last_seen_at: string | null;
  }>();

  return json({
    ok: true,
    links: (rows.results ?? []).map((row) => ({
      link_id: row.id,
      space_id: row.space_id || null,
      device_id: row.device_id,
      device_name: row.device_name,
      last_seen_at: row.last_seen_at,
      created_at: row.created_at,
    })),
  });
}

async function revokeProductDeviceLink(
  request: Request,
  env: Env,
  linkId: string,
): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
  if (!UUID_RE.test(linkId)) {
    return json({ ok: false, error: "product_device_link_id_invalid" }, 400);
  }

  const revokedAt = nowIso();
  const update = await env.DB.prepare(
    `UPDATE ordax_product_device_links
     SET revoked_at = ?1
     WHERE id = ?2 AND subject_id = ?3 AND revoked_at IS NULL`,
  ).bind(revokedAt, linkId, identity.subjectId).run();

  if ((update.meta.changes ?? 0) !== 1) {
    return json({ ok: false, error: "product_device_link_not_found" }, 404);
  }
  return json({ ok: true, link_id: linkId, revoked_at: revokedAt });
}

async function productSession(request: Request, env: Env): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) {
    return json({ ok: false, error: identity.error }, identity.status);
  }
  return json({
    ok: true,
    session: {
      subject_id: identity.subjectId,
      issuer: identity.issuer,
      audience: identity.audience,
      expires_at_unix: identity.expiresAt,
    },
  });
}

async function createProductAction(request: Request, env: Env): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
  const body = await parseSmallJson(request, 64 * 1024);
  if (!body) return json({ ok: false, error: "invalid_json" }, 400);
  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  const spaceId = body.space_id == null ? null : typeof body.space_id === "string" ? body.space_id : "";
  const action = typeof body.action === "string" ? body.action : "";
  const project = body.project == null ? null : typeof body.project === "string" ? body.project : "";
  const argumentsValue = isRecord(body.arguments) ? { ...body.arguments } : {};
  if (!UUID_RE.test(deviceId) || (spaceId !== null && !PRODUCT_ID_RE.test(spaceId)) || !PRODUCT_ACTIONS.has(action) || (project !== null && !PROJECT_SLUG_RE.test(project)) || !projectBindingMatchesScope(action, project, PRODUCT_PROJECT_ACTIONS)) {
    return json({ ok: false, error: "product_action_invalid" }, 400);
  }
  if (project !== null) {
    if (argumentsValue.project != null && argumentsValue.project !== project) return json({ ok: false, error: "product_project_conflict" }, 400);
    argumentsValue.project = project;
  } else if ("project" in argumentsValue) {
    return json({ ok: false, error: "product_action_invalid" }, 400);
  }
  const device = await env.DB.prepare("SELECT id FROM ordax_devices WHERE id = ?1 AND revoked_at IS NULL").bind(deviceId).first();
  if (!device) return json({ ok: false, error: "device_not_found" }, 404);
  const grant = await resolveProductGrantForContext(env, { subjectId: identity.subjectId, spaceId, deviceId, action, project });
  if (!grant) return json({ ok: false, error: "product_grant_not_resolved" }, 403);
  let actions: string[] = [];
  let projects: string[] = [];
  try {
    const rawActions = JSON.parse(grant.actions_json);
    const rawProjects = JSON.parse(grant.projects_json);
    if (!Array.isArray(rawActions) || !rawActions.every((item) => typeof item === "string") || !Array.isArray(rawProjects) || !rawProjects.every((item) => typeof item === "string")) throw new Error("invalid grant");
    actions = rawActions; projects = rawProjects;
  } catch { return json({ ok: false, error: "product_grant_corrupt" }, 500); }
  const requestId = crypto.randomUUID();
  const jobId = crypto.randomUUID();
  const effectId = crypto.randomUUID();
  const createdAt = nowIso();
  const expiresAtUnix = grant.expires_at == null ? null : Math.floor(new Date(grant.expires_at).getTime() / 1000);
  const invocation = {
    action, arguments: argumentsValue,
    context: { request_id: requestId, subject_id: identity.subjectId, device_id: deviceId, space_id: spaceId },
    grant: { grant_id: grant.id, subject_id: grant.subject_id, actions, projects, space_id: grant.space_id, device_id: grant.device_id, expires_at_unix: Number.isFinite(expiresAtUnix) ? expiresAtUnix : null },
  };
  const payloadBytes = new TextEncoder().encode(JSON.stringify(invocation));
  if (payloadBytes.byteLength > 64 * 1024) return json({ ok: false, error: "product_payload_too_large" }, 413);
  const payloadText = new TextDecoder().decode(payloadBytes);
  const payloadB64 = bytesToBase64(payloadBytes);
  const payloadSha256 = await sha256Text(payloadText);
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO ordax_jobs (id, device_id, capability, payload_canonical_b64, payload_sha256, status, effect_id, execution_epoch, created_at) VALUES (?1, ?2, 'ordax.product.invoke', ?3, ?4, 'queued', ?5, 0, ?6)`).bind(jobId, deviceId, payloadB64, payloadSha256, effectId, createdAt),
    env.DB.prepare(`INSERT INTO ordax_product_action_requests (request_id, job_id, subject_id, space_id, device_id, grant_id, action, project, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`).bind(requestId, jobId, identity.subjectId, spaceId, deviceId, grant.id, action, project, createdAt),
  ]);
  await wakeDeviceSession(env, deviceId);
  return json({ ok: true, request_id: requestId, status: "queued" }, 202);
}

async function getProductAction(request: Request, env: Env, requestId: string): Promise<Response> {
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);
  if (!UUID_RE.test(requestId)) return json({ ok: false, error: "product_request_id_invalid" }, 400);
  const row = await env.DB.prepare(`SELECT r.request_id, r.device_id, r.action, r.project, r.created_at, j.status, j.result_json, j.error_code, j.started_at, j.finished_at, g.projects_json FROM ordax_product_action_requests r JOIN ordax_jobs j ON j.id = r.job_id LEFT JOIN ordax_product_grants g ON g.id = r.grant_id WHERE r.request_id = ?1 AND r.subject_id = ?2`).bind(requestId, identity.subjectId).first<Record<string, unknown>>();
  if (!row) return json({ ok: false, error: "product_action_not_found" }, 404);
  let result: unknown = null;
  if (typeof row.result_json === "string" && row.result_json) { try { result = JSON.parse(row.result_json); } catch { result = null; } }
  result = scopeProductResult(row.action, result, row.projects_json);
  return json({ ok: true, action: { request_id: row.request_id, device_id: row.device_id, action: row.action, project: row.project, status: row.status, result, error_code: row.error_code, created_at: row.created_at, started_at: row.started_at, finished_at: row.finished_at } });
}

async function recordProductAudit(request: Request, env: Env): Promise<Response> {
  const deviceId = request.headers.get("X-Ordax-Device-Id") ?? "";
  const token = request.headers.get("X-Ordax-Device-Token") ?? "";
  const auth = await authenticateDevice(env, deviceId, token);
  if (!auth.ok) return json({ ok: false, error: auth.error }, 401);
  const body = await parseSmallJson(request, 32 * 1024);
  if (!body) return json({ ok: false, error: "product_audit_invalid" }, 400);
  const requestId = typeof body.request_id === "string" ? body.request_id : "";
  const subjectId = typeof body.subject_id === "string" ? body.subject_id : "";
  const grantId = body.grant_id == null ? null : typeof body.grant_id === "string" ? body.grant_id : "";
  const action = typeof body.action === "string" ? body.action : "";
  const project = body.project == null ? null : typeof body.project === "string" ? body.project : "";
  const phase = typeof body.phase === "string" ? body.phase : "";
  const decision = typeof body.decision === "string" ? body.decision : "";
  const reason = typeof body.reason === "string" ? body.reason : "";
  const fields = normalizedStringArray(body.payload_fields ?? [], { maxItems: 32, validator: (item) => PRODUCT_ID_RE.test(item) });
  const resultOk = body.result_ok == null ? null : typeof body.result_ok === "boolean" ? body.result_ok : undefined;
  if (!UUID_RE.test(requestId) || !PRODUCT_ID_RE.test(subjectId) || (grantId !== null && !UUID_RE.test(grantId)) || !PRODUCT_ACTIONS.has(action) || (project !== null && !PROJECT_SLUG_RE.test(project)) || !["decision","result"].includes(phase) || !["allow","deny"].includes(decision) || !reason || reason.length > 200 || !fields || resultOk === undefined) return json({ ok: false, error: "product_audit_invalid" }, 400);
  const owner = await env.DB.prepare(`SELECT subject_id, space_id, device_id, grant_id, action, project FROM ordax_product_action_requests WHERE request_id = ?1`).bind(requestId).first<{ subject_id: string; space_id: string | null; device_id: string; grant_id: string; action: string; project: string | null }>();
  if (!owner || owner.device_id !== deviceId || owner.subject_id !== subjectId || owner.grant_id !== grantId || owner.action !== action || owner.project !== project) return json({ ok: false, error: "product_audit_context_mismatch" }, 403);
  await env.DB.prepare(`INSERT INTO ordax_product_audit (request_id, subject_id, grant_id, device_id, space_id, action, project, phase, decision, reason, payload_fields_json, result_ok, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)`).bind(requestId, subjectId, grantId, deviceId, owner.space_id, action, project, phase, decision, reason, stableJson(fields), resultOk === null ? null : resultOk ? 1 : 0, nowIso()).run();
  return json({ ok: true });
}
async function provisionDevice(request: Request, env: Env): Promise<Response> {
  if (!await operatorAuthorized(request, env)) return json({ ok: false, error: "operator_unauthorized" }, 401);
  const body = await parseSmallJson(request, 16 * 1024);
  if (!body) return json({ ok: false, error: "invalid_json" }, 400);

  const deviceId = typeof body.device_id === "string" && UUID_RE.test(body.device_id)
    ? body.device_id
    : crypto.randomUUID();
  const name = typeof body.name === "string" ? body.name.trim().slice(0, 120) : "OrdaX Device";
  if (!name) return json({ ok: false, error: "device_name_required" }, 400);

  const token = randomHex(32);
  const tokenSha256 = await sha256Text(token);
  const createdAt = nowIso();
  await env.DB.prepare(
    `INSERT INTO ordax_devices (id, name, token_sha256, created_at, revoked_at)
     VALUES (?1, ?2, ?3, ?4, NULL)
     ON CONFLICT(id) DO UPDATE SET
       name = excluded.name,
       token_sha256 = excluded.token_sha256,
       revoked_at = NULL`,
  ).bind(deviceId, name, tokenSha256, createdAt).run();

  return json({
    ok: true,
    device_id: deviceId,
    device_token: token,
    protocol: "cloudflare-v3",
  }, 201);
}

async function enqueueJob(request: Request, env: Env): Promise<Response> {
  if (!await operatorAuthorized(request, env)) return json({ ok: false, error: "operator_unauthorized" }, 401);
  const body = await parseSmallJson(request);
  if (!body) return json({ ok: false, error: "invalid_json" }, 400);

  const deviceId = typeof body.device_id === "string" ? body.device_id : "";
  const action = typeof body.action === "string" ? body.action : "";
  const project = body.project == null ? null : typeof body.project === "string" ? body.project : "";
  if (!UUID_RE.test(deviceId) || !actionAllowed(action) || project === "") {
    return json({ ok: false, error: "job_invalid" }, 400);
  }
  const device = await env.DB.prepare(
    "SELECT id FROM ordax_devices WHERE id = ?1 AND revoked_at IS NULL",
  ).bind(deviceId).first();
  if (!device) return json({ ok: false, error: "device_not_found" }, 404);

  const payload = isRecord(body.payload) ? { ...body.payload } : {};
  if (project) {
    if (payload.project != null && payload.project !== project) {
      return json({ ok: false, error: "project_conflict" }, 400);
    }
    payload.project = project;
  }

  const payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  if (payloadBytes.byteLength > 64 * 1024) {
    return json({ ok: false, error: "payload_too_large" }, 413);
  }
  const payloadB64 = bytesToBase64(payloadBytes);
  const payloadSha256 = await sha256Text(new TextDecoder().decode(payloadBytes));
  const jobId = crypto.randomUUID();
  const effectId = crypto.randomUUID();
  const createdAt = nowIso();

  await env.DB.prepare(
    `INSERT INTO ordax_jobs
      (id, device_id, capability, payload_canonical_b64, payload_sha256, status,
       effect_id, execution_epoch, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, 'queued', ?6, 0, ?7)`,
  ).bind(jobId, deviceId, action, payloadB64, payloadSha256, effectId, createdAt).run();

  await wakeDeviceSession(env, deviceId);

  return json({ ok: true, job_id: jobId, effect_id: effectId, status: "queued" }, 201);
}

async function getJob(request: Request, env: Env, jobId: string): Promise<Response> {
  if (!await operatorAuthorized(request, env)) {
    return json({ ok: false, error: "operator_unauthorized" }, 401);
  }
  if (!UUID_RE.test(jobId)) return json({ ok: false, error: "job_id_invalid" }, 400);

  const row = await env.DB.prepare(
    `SELECT id, device_id, capability, status, effect_id, attempt_id, lease_id,
            execution_epoch, agent_instance_id, boot_id, lease_expires_at,
            report_id, result_json, result_sha256, error_code,
            created_at, started_at, finished_at
     FROM ordax_jobs WHERE id = ?1`,
  ).bind(jobId).first<Record<string, unknown>>();
  if (!row) return json({ ok: false, error: "job_not_found" }, 404);

  const events = await env.DB.prepare(
    `SELECT stage, message, progress_percent, created_at
     FROM ordax_job_events WHERE job_id = ?1 ORDER BY id ASC LIMIT 200`,
  ).bind(jobId).all();
  const artifacts = await env.DB.prepare(
    `SELECT id, file_name, kind, content_type, sha256, size_bytes, created_at
     FROM ordax_artifacts WHERE job_id = ?1 ORDER BY created_at ASC`,
  ).bind(jobId).all();

  let result: unknown = null;
  if (typeof row.result_json === "string" && row.result_json) {
    try { result = JSON.parse(row.result_json); } catch { result = null; }
  }
  const { result_json: _ignored, ...publicRow } = row;
  return json({
    ok: true,
    job: { ...publicRow, result },
    events: events.results ?? [],
    artifacts: artifacts.results ?? [],
  });
}

async function recoverTerminalReport(request: Request, env: Env): Promise<Response> {
  const deviceId = request.headers.get("X-Ordax-Device-Id") ?? "";
  const token = request.headers.get("X-Ordax-Device-Token") ?? "";
  const auth = await authenticateDevice(env, deviceId, token);
  if (!auth.ok) return json({ ok: false, error: auth.error }, 401);

  const body = await parseSmallJson(request, 640 * 1024);
  if (!body) return json({ ok: false, error: "report_invalid" }, 400);

  const recoveryAgentInstanceId = request.headers.get(
    "X-Ordax-Recovery-Agent-Instance",
  ) ?? "";
  const recoveryBootId = request.headers.get("X-Ordax-Recovery-Boot-Id") ?? "";
  if (!UUID_RE.test(recoveryAgentInstanceId) || !UUID_RE.test(recoveryBootId)) {
    return json({ ok: false, error: "recovery_runtime_identity_required" }, 400);
  }

  const jobId = typeof body.job_id === "string" ? body.job_id : "";
  const effectId = typeof body.effect_id === "string" ? body.effect_id : "";
  const attemptId = typeof body.attempt_id === "string" ? body.attempt_id : "";
  const leaseId = typeof body.lease_id === "string" ? body.lease_id : "";
  const agentInstanceId = typeof body.agent_instance_id === "string"
    ? body.agent_instance_id
    : "";
  const bootId = typeof body.boot_id === "string" ? body.boot_id : "";
  const reportId = typeof body.report_id === "string" ? body.report_id : "";
  const executionEpoch = Number.isSafeInteger(body.execution_epoch)
    ? Number(body.execution_epoch)
    : 0;
  const status = typeof body.status === "string" ? body.status : "";
  const resultSha256 = typeof body.result_sha256 === "string"
    ? body.result_sha256.toLowerCase()
    : "";
  const errorCode = typeof body.error_code === "string" ? body.error_code : null;
  const resultValue = isRecord(body.result) ? body.result : {};
  const resultJson = stableJson(resultValue);

  if (
    !UUID_RE.test(jobId)
    || !UUID_RE.test(effectId)
    || !UUID_RE.test(attemptId)
    || !UUID_RE.test(leaseId)
    || !UUID_RE.test(agentInstanceId)
    || !UUID_RE.test(bootId)
    || !UUID_RE.test(reportId)
    || executionEpoch < 1
    || !["succeeded", "failed", "cancelled"].includes(status)
    || !HEX64_RE.test(resultSha256)
    || new TextEncoder().encode(resultJson).byteLength > 512 * 1024
  ) {
    return json({ ok: false, error: "report_invalid" }, 400);
  }

  const row = await env.DB.prepare(
    `SELECT status, effect_id, attempt_id, lease_id, execution_epoch,
            agent_instance_id, boot_id, report_id, result_json,
            result_sha256, error_code
     FROM ordax_jobs WHERE id = ?1 AND device_id = ?2`,
  ).bind(jobId, deviceId).first<{
    status: string;
    effect_id: string;
    attempt_id: string | null;
    lease_id: string | null;
    execution_epoch: number;
    agent_instance_id: string | null;
    boot_id: string | null;
    report_id: string | null;
    result_json: string | null;
    result_sha256: string | null;
    error_code: string | null;
  }>();
  if (!row) return json({ ok: false, error: "job_not_found" }, 404);

  const contextMatches = (
    row.effect_id === effectId
    && row.attempt_id === attemptId
    && row.lease_id === leaseId
    && Number(row.execution_epoch) === executionEpoch
    && row.agent_instance_id === agentInstanceId
    && row.boot_id === bootId
  );

  if (["succeeded", "failed", "cancelled"].includes(row.status)) {
    const replayMatches = (
      contextMatches
      && row.report_id === reportId
      && row.status === status
      && canonicalStoredJson(row.result_json) === resultJson
      && (row.result_sha256 ?? "").toLowerCase() === resultSha256
      && row.error_code === errorCode
    );
    if (!replayMatches) {
      return json({ ok: false, error: "terminal_report_conflict" }, 409);
    }
    await wakeDeviceSession(
      env, deviceId, recoveryAgentInstanceId, recoveryBootId,
    );
    return json({ ok: true, status, replayed: true });
  }

  if (!contextMatches) {
    return json({ ok: false, error: "execution_context_superseded" }, 409);
  }
  if (!["leased", "running"].includes(row.status)) {
    return json({ ok: false, error: "job_not_recoverable" }, 409);
  }

  const finishedAt = nowIso();
  const update = await env.DB.prepare(
    `UPDATE ordax_jobs SET
       status = ?1, report_id = ?2, result_json = ?3, result_sha256 = ?4,
       error_code = ?5, finished_at = ?6, lease_expires_at = NULL
     WHERE id = ?7 AND device_id = ?8
       AND effect_id = ?9 AND attempt_id = ?10 AND lease_id = ?11
       AND execution_epoch = ?12 AND agent_instance_id = ?13 AND boot_id = ?14
       AND status IN ('leased','running') AND report_id IS NULL`,
  ).bind(
    status, reportId, resultJson, resultSha256, errorCode, finishedAt,
    jobId, deviceId, effectId, attemptId, leaseId, executionEpoch,
    agentInstanceId, bootId,
  ).run();
  if ((update.meta.changes ?? 0) !== 1) {
    return json({ ok: false, error: "terminal_recovery_race" }, 409);
  }
  await wakeDeviceSession(
    env, deviceId, recoveryAgentInstanceId, recoveryBootId,
  );
  return json({ ok: true, status, recovered: true, replayed: false });
}

type ArtifactDescriptor = {
  artifactId: string;
  jobId: string;
  deviceId: string;
  storagePath: string;
  fileName: string;
  kind: string;
  contentType: string;
  sha256: string;
  sizeBytes: number;
  metadataRaw: string;
};

type MultipartUploadRow = {
  artifact_id: string;
  job_id: string;
  device_id: string;
  upload_id: string;
  storage_path: string;
  file_name: string;
  kind: string;
  content_type: string;
  sha256: string;
  size_bytes: number;
  metadata_json: string;
  created_at: string;
};

function parseArtifactDescriptor(
  request: Request,
  deviceId: string,
  jobId: string,
  artifactId: string,
  maxBytes: number,
): ArtifactDescriptor | null {
  const fileName = (request.headers.get("X-Ordax-Artifact-Name") ?? "artifact.bin")
    .replace(/[^a-zA-Z0-9._-]+/g, "-").slice(0, 180) || "artifact.bin";
  const kind = (request.headers.get("X-Ordax-Artifact-Kind") ?? "artifact").slice(0, 80);
  const sha256 = (request.headers.get("X-Ordax-Artifact-Sha256") ?? "").toLowerCase();
  const sizeBytes = Number(
    request.headers.get("X-Ordax-Artifact-Size")
      ?? request.headers.get("content-length")
      ?? "0",
  );
  const metadataRaw = request.headers.get("X-Ordax-Artifact-Metadata") ?? "{}";
  const contentType = (
    request.headers.get("content-type") ?? "application/octet-stream"
  ).slice(0, 255);

  if (
    !HEX64_RE.test(sha256)
    || !Number.isSafeInteger(sizeBytes)
    || sizeBytes < 0
    || sizeBytes > maxBytes
    || metadataRaw.length > 4000
  ) {
    return null;
  }
  try {
    const parsed = JSON.parse(metadataRaw);
    if (!isRecord(parsed)) return null;
  } catch {
    return null;
  }

  return {
    artifactId,
    jobId,
    deviceId,
    storagePath: deviceId + "/" + jobId + "/" + artifactId + "-" + fileName,
    fileName,
    kind,
    contentType,
    sha256,
    sizeBytes,
    metadataRaw,
  };
}

async function existingArtifactGrant(
  request: Request,
  env: Env,
  artifactId: string,
  jobId: string,
  deviceId: string,
  expected?: ArtifactDescriptor,
): Promise<Response | null> {
  const row = await env.DB.prepare(
    `SELECT job_id, device_id, storage_path, file_name, kind, content_type,
            sha256, size_bytes, metadata_json
     FROM ordax_artifacts WHERE id = ?1`,
  ).bind(artifactId).first<{
    job_id: string;
    device_id: string;
    storage_path: string;
    file_name: string;
    kind: string;
    content_type: string;
    sha256: string;
    size_bytes: number;
    metadata_json: string;
  }>();
  if (!row) return null;

  const matches = (
    row.job_id === jobId
    && row.device_id === deviceId
    && (!expected || (
      row.storage_path === expected.storagePath
      && row.file_name === expected.fileName
      && row.kind === expected.kind
      && row.content_type === expected.contentType
      && row.sha256.toLowerCase() === expected.sha256
      && Number(row.size_bytes) === expected.sizeBytes
      && row.metadata_json === expected.metadataRaw
    ))
  );
  if (!matches) {
    return json({ ok: false, error: "artifact_replay_conflict" }, 409);
  }

  const readToken = randomHex(32);
  const readTokenSha256 = await sha256Text(readToken);
  const readExpiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const tokenUpdate = await env.DB.prepare(
    `UPDATE ordax_artifacts
     SET read_token_sha256 = ?1, read_expires_at = ?2
     WHERE id = ?3 AND job_id = ?4 AND device_id = ?5`,
  ).bind(
    readTokenSha256, readExpiresAt, artifactId, jobId, deviceId,
  ).run();
  if ((tokenUpdate.meta.changes ?? 0) !== 1) {
    return json({ ok: false, error: "artifact_replay_conflict" }, 409);
  }

  const origin = new URL(request.url).origin;
  return json({
    ok: true,
    complete: true,
    replayed: true,
    artifact_id: artifactId,
    storage_path: row.storage_path,
    signed_url: origin + "/v3/artifacts/" + artifactId
      + "?token=" + encodeURIComponent(readToken),
    expires_at: readExpiresAt,
  });
}

async function artifactJobAuthorized(
  request: Request,
  env: Env,
  parts: string[],
): Promise<
  | { ok: true; deviceId: string; jobId: string; artifactId: string }
  | { ok: false; response: Response }
> {
  const jobId = parts[2] ?? "";
  const artifactId = parts[3] ?? "";
  const deviceId = request.headers.get("X-Ordax-Device-Id") ?? "";
  const token = request.headers.get("X-Ordax-Device-Token") ?? "";
  if (!UUID_RE.test(jobId) || !UUID_RE.test(artifactId)) {
    return { ok: false, response: json({ ok: false, error: "artifact_path_invalid" }, 400) };
  }
  const auth = await authenticateDevice(env, deviceId, token);
  if (!auth.ok) {
    return { ok: false, response: json({ ok: false, error: auth.error }, 401) };
  }
  const job = await env.DB.prepare(
    "SELECT id FROM ordax_jobs WHERE id = ?1 AND device_id = ?2",
  ).bind(jobId, deviceId).first();
  if (!job) {
    return { ok: false, response: json({ ok: false, error: "job_not_found" }, 404) };
  }
  return { ok: true, deviceId, jobId, artifactId };
}

async function uploadArtifact(request: Request, env: Env, parts: string[]): Promise<Response> {
  const access = await artifactJobAuthorized(request, env, parts);
  if (!access.ok) return access.response;
  const descriptor = parseArtifactDescriptor(
    request, access.deviceId, access.jobId, access.artifactId,
    DIRECT_ARTIFACT_MAX_BYTES,
  );
  if (!descriptor) {
    return json({ ok: false, error: "artifact_metadata_invalid" }, 400);
  }

  const replay = await existingArtifactGrant(
    request, env, access.artifactId, access.jobId, access.deviceId, descriptor,
  );
  if (replay) return replay;

  let stored: R2Object | null;
  try {
    stored = await env.ARTIFACTS.put(descriptor.storagePath, request.body, {
      sha256: hexToArrayBuffer(descriptor.sha256),
      httpMetadata: { contentType: descriptor.contentType },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (/\((10014|10037)\)\s*$/.test(message)) {
      return json({ ok: false, error: "artifact_checksum_rejected" }, 422);
    }
    throw error;
  }

  if (!stored) {
    return json({ ok: false, error: "artifact_storage_write_failed" }, 503);
  }
  const storedSha256 = stored.checksums.sha256;
  if (
    stored.size !== descriptor.sizeBytes
    || !storedSha256
    || arrayBufferToHex(storedSha256).toLowerCase() !== descriptor.sha256
  ) {
    await env.ARTIFACTS.delete(descriptor.storagePath);
    return json({ ok: false, error: "artifact_integrity_mismatch" }, 422);
  }

  const readToken = randomHex(32);
  const readTokenSha256 = await sha256Text(readToken);
  const createdAt = nowIso();
  const readExpiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  await env.DB.prepare(
    `INSERT INTO ordax_artifacts
      (id, job_id, device_id, storage_path, file_name, kind, content_type, sha256,
       size_bytes, metadata_json, read_token_sha256, read_expires_at, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)`,
  ).bind(
    descriptor.artifactId, descriptor.jobId, descriptor.deviceId,
    descriptor.storagePath, descriptor.fileName, descriptor.kind,
    descriptor.contentType, descriptor.sha256, descriptor.sizeBytes,
    descriptor.metadataRaw, readTokenSha256, readExpiresAt, createdAt,
  ).run();

  const origin = new URL(request.url).origin;
  return json({
    ok: true,
    artifact_id: descriptor.artifactId,
    storage_path: descriptor.storagePath,
    signed_url: origin + "/v3/artifacts/" + descriptor.artifactId
      + "?token=" + encodeURIComponent(readToken),
    expires_at: readExpiresAt,
  }, 201);
}

async function loadMultipartUpload(
  env: Env,
  artifactId: string,
  jobId: string,
  deviceId: string,
): Promise<MultipartUploadRow | null> {
  return env.DB.prepare(
    `SELECT artifact_id, job_id, device_id, upload_id, storage_path, file_name,
            kind, content_type, sha256, size_bytes, metadata_json, created_at
     FROM ordax_artifact_uploads
     WHERE artifact_id = ?1 AND job_id = ?2 AND device_id = ?3`,
  ).bind(artifactId, jobId, deviceId).first<MultipartUploadRow>();
}

async function createMultipartArtifact(
  request: Request,
  env: Env,
  parts: string[],
): Promise<Response> {
  const access = await artifactJobAuthorized(request, env, parts);
  if (!access.ok) return access.response;
  const descriptor = parseArtifactDescriptor(
    request, access.deviceId, access.jobId, access.artifactId,
    MULTIPART_ARTIFACT_MAX_BYTES,
  );
  if (!descriptor || descriptor.sizeBytes < 1) {
    return json({ ok: false, error: "artifact_metadata_invalid" }, 400);
  }

  const replay = await existingArtifactGrant(
    request, env, access.artifactId, access.jobId, access.deviceId, descriptor,
  );
  if (replay) return replay;

  const staleBefore = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
  await env.DB.prepare(
    "DELETE FROM ordax_artifact_uploads WHERE device_id = ?1 AND created_at < ?2",
  ).bind(access.deviceId, staleBefore).run();

  const existing = await loadMultipartUpload(
    env, access.artifactId, access.jobId, access.deviceId,
  );
  if (existing) {
    const matches = (
      existing.storage_path === descriptor.storagePath
      && existing.file_name === descriptor.fileName
      && existing.kind === descriptor.kind
      && existing.content_type === descriptor.contentType
      && existing.sha256.toLowerCase() === descriptor.sha256
      && Number(existing.size_bytes) === descriptor.sizeBytes
      && existing.metadata_json === descriptor.metadataRaw
    );
    if (!matches) {
      return json({ ok: false, error: "multipart_upload_conflict" }, 409);
    }
    return json({
      ok: true,
      upload_id: existing.upload_id,
      storage_path: existing.storage_path,
      resumed: true,
    });
  }

  const multipart = await env.ARTIFACTS.createMultipartUpload(
    descriptor.storagePath,
    { httpMetadata: { contentType: descriptor.contentType } },
  );
  try {
    await env.DB.prepare(
      `INSERT INTO ordax_artifact_uploads
        (artifact_id, job_id, device_id, upload_id, storage_path, file_name, kind,
         content_type, sha256, size_bytes, metadata_json, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`,
    ).bind(
      descriptor.artifactId, descriptor.jobId, descriptor.deviceId,
      multipart.uploadId, descriptor.storagePath, descriptor.fileName,
      descriptor.kind, descriptor.contentType, descriptor.sha256,
      descriptor.sizeBytes, descriptor.metadataRaw, nowIso(),
    ).run();
  } catch (error) {
    try { await multipart.abort(); } catch {}
    throw error;
  }

  return json({
    ok: true,
    upload_id: multipart.uploadId,
    storage_path: descriptor.storagePath,
    resumed: false,
  }, 201);
}

async function uploadMultipartPart(
  request: Request,
  env: Env,
  parts: string[],
): Promise<Response> {
  const access = await artifactJobAuthorized(request, env, parts);
  if (!access.ok) return access.response;
  const url = new URL(request.url);
  const uploadId = url.searchParams.get("uploadId") ?? "";
  const partNumber = Number(url.searchParams.get("partNumber") ?? "0");
  const partSha256 = (request.headers.get("X-Ordax-Part-Sha256") ?? "").toLowerCase();
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (
    !uploadId
    || uploadId.length > 512
    || !Number.isSafeInteger(partNumber)
    || partNumber < 1
    || partNumber > MULTIPART_MAX_PARTS
    || !HEX64_RE.test(partSha256)
    || !Number.isSafeInteger(contentLength)
    || contentLength < 1
    || contentLength > DIRECT_ARTIFACT_MAX_BYTES
    || !request.body
  ) {
    return json({ ok: false, error: "multipart_part_invalid" }, 400);
  }

  const session = await loadMultipartUpload(
    env, access.artifactId, access.jobId, access.deviceId,
  );
  if (!session) return json({ ok: false, error: "multipart_upload_not_found" }, 404);
  if (session.upload_id !== uploadId) {
    return json({ ok: false, error: "multipart_upload_conflict" }, 409);
  }

  const [r2Body, digestBody] = request.body.tee();
  const digestStream = new crypto.DigestStream("SHA-256");
  const digestPromise = (async () => {
    await digestBody.pipeTo(digestStream);
    return arrayBufferToHex(await digestStream.digest).toLowerCase();
  })();
  const uploadPromise = env.ARTIFACTS
    .resumeMultipartUpload(session.storage_path, uploadId)
    .uploadPart(partNumber, r2Body);

  const [uploaded, observedSha256] = await Promise.all([uploadPromise, digestPromise]);
  if (observedSha256 !== partSha256) {
    return json({ ok: false, error: "multipart_part_checksum_mismatch" }, 422);
  }

  return json({
    ok: true,
    part_number: uploaded.partNumber,
    etag: uploaded.etag,
    sha256: observedSha256,
  }, 201);
}

async function completeMultipartArtifact(
  request: Request,
  env: Env,
  parts: string[],
): Promise<Response> {
  const access = await artifactJobAuthorized(request, env, parts);
  if (!access.ok) return access.response;

  const alreadyComplete = await existingArtifactGrant(
    request, env, access.artifactId, access.jobId, access.deviceId,
  );
  if (alreadyComplete) return alreadyComplete;

  const session = await loadMultipartUpload(
    env, access.artifactId, access.jobId, access.deviceId,
  );
  if (!session) return json({ ok: false, error: "multipart_upload_not_found" }, 404);

  const body = await parseSmallJson(request, 1024 * 1024);
  const uploadId = body && typeof body.upload_id === "string" ? body.upload_id : "";
  const rawParts = body && Array.isArray(body.parts) ? body.parts : [];
  if (
    uploadId !== session.upload_id
    || rawParts.length < 1
    || rawParts.length > MULTIPART_MAX_PARTS
  ) {
    return json({ ok: false, error: "multipart_complete_invalid" }, 400);
  }

  const uploadedParts: Array<{ partNumber: number; etag: string }> = [];
  for (const value of rawParts) {
    if (!isRecord(value)) {
      return json({ ok: false, error: "multipart_complete_invalid" }, 400);
    }
    const partNumber = Number(value.part_number);
    const etag = typeof value.etag === "string" ? value.etag : "";
    if (
      !Number.isSafeInteger(partNumber)
      || partNumber < 1
      || partNumber > MULTIPART_MAX_PARTS
      || etag.length < 1
      || etag.length > 256
    ) {
      return json({ ok: false, error: "multipart_complete_invalid" }, 400);
    }
    uploadedParts.push({ partNumber, etag });
  }
  uploadedParts.sort((a, b) => a.partNumber - b.partNumber);
  if (uploadedParts.some((item, index) => item.partNumber !== index + 1)) {
    return json({ ok: false, error: "multipart_parts_not_contiguous" }, 400);
  }

  let stored = await env.ARTIFACTS.head(session.storage_path);
  if (!stored) {
    stored = await env.ARTIFACTS
      .resumeMultipartUpload(session.storage_path, session.upload_id)
      .complete(uploadedParts);
  }
  if (!stored || stored.size !== Number(session.size_bytes)) {
    await env.ARTIFACTS.delete(session.storage_path);
    await env.DB.prepare(
      "DELETE FROM ordax_artifact_uploads WHERE artifact_id = ?1",
    ).bind(access.artifactId).run();
    return json({ ok: false, error: "artifact_integrity_mismatch" }, 422);
  }

  const object = await env.ARTIFACTS.get(session.storage_path);
  if (!object || !object.body) {
    return json({ ok: false, error: "artifact_storage_read_failed" }, 503);
  }
  const digestStream = new crypto.DigestStream("SHA-256");
  await object.body.pipeTo(digestStream);
  const observedSha256 = arrayBufferToHex(await digestStream.digest).toLowerCase();
  if (observedSha256 !== session.sha256.toLowerCase()) {
    await env.ARTIFACTS.delete(session.storage_path);
    await env.DB.prepare(
      "DELETE FROM ordax_artifact_uploads WHERE artifact_id = ?1",
    ).bind(access.artifactId).run();
    return json({ ok: false, error: "artifact_integrity_mismatch" }, 422);
  }

  const readToken = randomHex(32);
  const readTokenSha256 = await sha256Text(readToken);
  const createdAt = nowIso();
  const readExpiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const publishInsert = await env.DB.prepare(
    `INSERT INTO ordax_artifacts
      (id, job_id, device_id, storage_path, file_name, kind, content_type, sha256,
       size_bytes, metadata_json, read_token_sha256, read_expires_at, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
     ON CONFLICT(id) DO NOTHING`,
  ).bind(
    session.artifact_id, session.job_id, session.device_id, session.storage_path,
    session.file_name, session.kind, session.content_type, session.sha256,
    session.size_bytes, session.metadata_json, readTokenSha256,
    readExpiresAt, createdAt,
  ).run();
  // A concurrent complete may have won the unique artifact ID. Never
  // issue a signed URL for our token unless this write persisted it.
  if ((publishInsert.meta.changes ?? 0) !== 1) {
    return json({ ok: false, error: "artifact_publish_conflict" }, 409);
  }

  const persisted = await env.DB.prepare(
    `SELECT job_id, device_id, storage_path, sha256, size_bytes
     FROM ordax_artifacts WHERE id = ?1`,
  ).bind(access.artifactId).first<{
    job_id: string;
    device_id: string;
    storage_path: string;
    sha256: string;
    size_bytes: number;
  }>();
  if (
    !persisted
    || persisted.job_id !== session.job_id
    || persisted.device_id !== session.device_id
    || persisted.storage_path !== session.storage_path
    || persisted.sha256.toLowerCase() !== session.sha256.toLowerCase()
    || Number(persisted.size_bytes) !== Number(session.size_bytes)
  ) {
    return json({ ok: false, error: "artifact_publish_conflict" }, 409);
  }

  await env.DB.prepare(
    "DELETE FROM ordax_artifact_uploads WHERE artifact_id = ?1",
  ).bind(access.artifactId).run();

  const origin = new URL(request.url).origin;
  return json({
    ok: true,
    complete: true,
    multipart: true,
    artifact_id: session.artifact_id,
    storage_path: session.storage_path,
    sha256: observedSha256,
    size_bytes: Number(session.size_bytes),
    signed_url: origin + "/v3/artifacts/" + session.artifact_id
      + "?token=" + encodeURIComponent(readToken),
    expires_at: readExpiresAt,
  }, 201);
}

async function abortMultipartArtifact(
  request: Request,
  env: Env,
  parts: string[],
): Promise<Response> {
  const access = await artifactJobAuthorized(request, env, parts);
  if (!access.ok) return access.response;
  const url = new URL(request.url);
  const uploadId = url.searchParams.get("uploadId") ?? "";
  const session = await loadMultipartUpload(
    env, access.artifactId, access.jobId, access.deviceId,
  );
  if (!session) return json({ ok: true, aborted: false, missing: true });
  if (uploadId !== session.upload_id) {
    return json({ ok: false, error: "multipart_upload_conflict" }, 409);
  }

  try {
    await env.ARTIFACTS
      .resumeMultipartUpload(session.storage_path, session.upload_id)
      .abort();
  } catch {
    // R2 automatically aborts incomplete multipart uploads after its lifecycle.
  }
  await env.DB.prepare(
    "DELETE FROM ordax_artifact_uploads WHERE artifact_id = ?1",
  ).bind(access.artifactId).run();
  return json({ ok: true, aborted: true });
}

async function downloadArtifact(request: Request, env: Env, artifactId: string): Promise<Response> {
  if (!UUID_RE.test(artifactId)) return json({ ok: false, error: "artifact_id_invalid" }, 400);
  const token = new URL(request.url).searchParams.get("token") ?? "";
  if (token.length < 32 || token.length > 512) return json({ ok: false, error: "artifact_token_required" }, 401);
  const digest = await sha256Text(token);
  const row = await env.DB.prepare(
    `SELECT storage_path, file_name, content_type, read_expires_at
     FROM ordax_artifacts WHERE id = ?1 AND read_token_sha256 = ?2`,
  ).bind(artifactId, digest).first<{
    storage_path: string;
    file_name: string;
    content_type: string | null;
    read_expires_at: string;
  }>();
  if (!row || new Date(row.read_expires_at).getTime() <= Date.now()) {
    return json({ ok: false, error: "artifact_token_invalid_or_expired" }, 403);
  }
  const object = await env.ARTIFACTS.get(row.storage_path);
  if (!object) return json({ ok: false, error: "artifact_not_found" }, 404);

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("content-type", row.content_type ?? headers.get("content-type") ?? "application/octet-stream");
  headers.set("content-disposition", `inline; filename="${row.file_name.replace(/"/g, "")}"`);
  headers.set("cache-control", "private, no-store");
  return new Response(object.body, { headers });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);

    if (request.method === "GET" && url.pathname === "/health") {
      return json({
        ok: true,
        service: "ordax-control-plane-v3",
        capabilities: CONTROL_PLANE_CAPABILITIES,
        product_auth_configured: productAuthConfigured(env),
        product_postgres_configured: productPostgresConfigured(env),
      });
    }

    if (request.method === "GET" && url.pathname === "/.well-known/openai-apps-challenge") {
      return openAiAppsChallenge(env);
    }

    if (request.method === "GET") {
      const publicPage = publicProductPage(url.pathname);
      if (publicPage) return publicPage;
    }

    if (request.method === "GET" && url.pathname === "/v3/device/ws") {
      if ((request.headers.get("Upgrade") ?? "").toLowerCase() !== "websocket") {
        return json({ ok: false, error: "websocket_required" }, 426);
      }
      // Reject malformed runtime IDs before activating the Durable Object.
      const runtimeIdentity = parseRuntimeIdentityHeaders(request);
      if (!runtimeIdentity) return json({ ok: false, error: "runtime_identity_invalid" }, 400);
      const deviceId = url.searchParams.get("device_id") ?? "";
      const token = request.headers.get("X-Ordax-Device-Token") ?? "";
      const auth = await authenticateDevice(env, deviceId, token);
      if (!auth.ok) return json({ ok: false, error: auth.error }, 401);

      const id = env.DEVICE_SESSIONS.idFromName(deviceId);
      const headers = new Headers(request.headers);
      headers.set("X-Ordax-Device-Id", deviceId);
      headers.delete("X-Ordax-Device-Token");
      return env.DEVICE_SESSIONS.get(id).fetch("https://device.internal/ws", {
        method: "GET",
        headers,
      });
    }

    if (url.pathname === PRODUCT_DEVICE_PRESENCE_PATH) {
      return handleProductDevicePresence(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/device/setup") {
      return deviceSetup(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/device/recover-report") {
      return recoverTerminalReport(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/device/product-pairings") {
      return createProductDevicePairing(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/devices") {
      return provisionDevice(request, env);
    }
    if (request.method === "GET" && url.pathname === "/oauth/consent") {
      return oauthConsentResponse(request, env);
    }
    if (request.method === "GET" && url.pathname === "/.well-known/oauth-protected-resource") {
      const authorizationServers = env.PRODUCT_AUTH_ISSUER ? [env.PRODUCT_AUTH_ISSUER] : [];
      return json({
        resource: `${url.origin}/mcp`,
        authorization_servers: authorizationServers,
        bearer_methods_supported: ["header"],
        scopes_supported: ["openid", "email", "offline_access"],
      });
    }
    if (url.pathname === "/mcp") {
      return handleOrdaxMcp(request, {
        session: (inner) => productSession(inner, env),
        targets: (inner) => listProductTargets(inner, env),
        createAction: (inner) => createProductAction(inner, env),
        getAction: (inner, requestId) => getProductAction(inner, env, requestId),
      });
    }
    if (request.method === "GET" && url.pathname === "/v3/product/session") {
      return productSession(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/product/device-intelligence-grants") {
      return createOwnerDeviceIntelligenceGrant(request, env);
    }
    if (request.method === "GET" && url.pathname === "/v3/product/device-intelligence-grants") {
      return listOwnerDeviceIntelligenceGrants(request, env);
    }
    if (
      request.method === "DELETE"
      && parts[0] === "v3"
      && parts[1] === "product"
      && parts[2] === "device-intelligence-grants"
      && parts.length === 4
    ) {
      return revokeOwnerDeviceIntelligenceGrant(request, env, parts[3]);
    }
    if (request.method === "POST" && url.pathname === "/v3/product/device-computer-grants") {
      return createOwnerDeviceComputerGrant(request, env);
    }
    if (request.method === "GET" && url.pathname === "/v3/product/device-computer-grants") {
      return listOwnerDeviceComputerGrants(request, env);
    }
    if (
      request.method === "DELETE"
      && parts[0] === "v3"
      && parts[1] === "product"
      && parts[2] === "device-computer-grants"
      && parts.length === 4
    ) {
      return revokeOwnerDeviceComputerGrant(request, env, parts[3]);
    }
    if (request.method === "POST" && url.pathname === "/v3/product/project-capability-grants") {
      return createOwnerProjectGrant(request, env);
    }
    if (request.method === "GET" && url.pathname === "/v3/product/project-capability-grants") {
      return listOwnerProjectGrants(request, env);
    }
    if (
      request.method === "DELETE"
      && parts[0] === "v3"
      && parts[1] === "product"
      && parts[2] === "project-capability-grants"
      && parts.length === 4
    ) {
      return revokeOwnerProjectGrant(request, env, parts[3]);
    }
    if (request.method === "POST" && url.pathname === "/v3/product/device-links") {
      return claimProductDevicePairing(request, env);
    }
    if (request.method === "GET" && url.pathname === "/v3/product/device-links") {
      return listProductDeviceLinks(request, env);
    }
    if (
      request.method === "DELETE"
      && parts[0] === "v3"
      && parts[1] === "product"
      && parts[2] === "device-links"
      && parts.length === 4
    ) {
      return revokeProductDeviceLink(request, env, parts[3]);
    }
    if (request.method === "GET" && url.pathname === "/v3/product/targets") {
      return listProductTargets(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/product/actions") {
      return createProductAction(request, env);
    }
    if (request.method === "GET" && parts[0] === "v3" && parts[1] === "product" && parts[2] === "actions" && parts.length === 4) {
      return getProductAction(request, env, parts[3]);
    }
    if (request.method === "POST" && url.pathname === "/v3/product/audit") {
      return recordProductAudit(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/product-grants") {
      return createProductGrant(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/product-grants/from-link") {
      return createProductGrantFromLink(request, env);
    }
    if (request.method === "GET" && url.pathname === "/v3/product-grants") {
      return listProductGrants(request, env);
    }
    if (request.method === "POST" && url.pathname === "/v3/product-grants/resolve") {
      return resolveProductGrantAdmin(request, env);
    }
    if (
      request.method === "DELETE"
      && parts[0] === "v3"
      && parts[1] === "product-grants"
      && parts.length === 3
    ) {
      return revokeProductGrant(request, env, parts[2]);
    }
    if (request.method === "POST" && url.pathname === "/v3/jobs") {
      return enqueueJob(request, env);
    }
    if (request.method === "GET" && parts[0] === "v3" && parts[1] === "jobs" && parts.length === 3) {
      return getJob(request, env, parts[2]);
    }
    if (parts[0] === "v3" && parts[1] === "artifacts" && parts.length === 4) {
      const action = url.searchParams.get("action") ?? "";
      if (request.method === "POST" && action === "mpu-create") {
        return createMultipartArtifact(request, env, parts);
      }
      if (request.method === "PUT" && action === "mpu-uploadpart") {
        return uploadMultipartPart(request, env, parts);
      }
      if (request.method === "POST" && action === "mpu-complete") {
        return completeMultipartArtifact(request, env, parts);
      }
      if (request.method === "DELETE" && action === "mpu-abort") {
        return abortMultipartArtifact(request, env, parts);
      }
      if (request.method === "PUT" && action === "") {
        return uploadArtifact(request, env, parts);
      }
    }
    if (request.method === "GET" && parts[0] === "v3" && parts[1] === "artifacts" && parts.length === 3) {
      return downloadArtifact(request, env, parts[2]);
    }

    return json({ ok: false, error: "not_found" }, 404);
  },
};

type SocketAttachment = {
  deviceId: string;
  agentInstanceId: string;
  bootId: string;
};

export class DeviceSession extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  private ack(ws: WebSocket, requestId: unknown, ok: boolean, extra: JsonObject = {}): void {
    ws.send(JSON.stringify({
      type: "ack",
      request_id: typeof requestId === "string" ? requestId : null,
      ok,
      ...extra,
    }));
  }

  private attachment(ws: WebSocket): SocketAttachment | null {
    const value = ws.deserializeAttachment();
    return isRecord(value)
      && typeof value.deviceId === "string"
      && typeof value.agentInstanceId === "string"
      && typeof value.bootId === "string"
      ? value as unknown as SocketAttachment
      : null;
  }

  private async fenceExpiredForeignRunningJobs(
    deviceId: string,
    agentInstanceId: string,
    bootId: string,
  ): Promise<void> {
    const now = nowIso();
    await this.env.DB.prepare(
      `UPDATE ordax_jobs SET
         status = 'failed',
         error_code = 'execution_context_lost',
         finished_at = COALESCE(finished_at, ?1)
       WHERE device_id = ?2
         AND status = 'running'
         AND report_id IS NULL
         AND lease_expires_at < ?1
         AND (
           agent_instance_id IS NULL OR boot_id IS NULL
           OR agent_instance_id != ?3 OR boot_id != ?4
         )`,
    ).bind(now, deviceId, agentInstanceId, bootId).run();
  }

  private async deliverNextJob(ws: WebSocket, deviceId: string): Promise<void> {
    const now = nowIso();

    // One device executes one remote job at a time. A running action may already
    // have mutated local state, and an unexpired lease belongs to another active
    // delivery attempt. Either condition fences every later queued job.
    const activeExecution = await this.env.DB.prepare(
      `SELECT id FROM ordax_jobs
       WHERE device_id = ?1
         AND (status = 'running' OR (status = 'leased' AND lease_expires_at >= ?2))
       LIMIT 1`,
    ).bind(deviceId, now).first();
    if (activeExecution) return;

    const candidate = await this.env.DB.prepare(
      `SELECT id, capability, payload_canonical_b64, payload_sha256, effect_id, execution_epoch
       FROM ordax_jobs
       WHERE device_id = ?1
         AND (status = 'queued' OR (status = 'leased' AND lease_expires_at < ?2))
       ORDER BY created_at ASC
       LIMIT 1`,
    ).bind(deviceId, now).first<{
      id: string;
      capability: string;
      payload_canonical_b64: string;
      payload_sha256: string;
      effect_id: string;
      execution_epoch: number;
    }>();
    if (!candidate) return;

    const attachment = this.attachment(ws);
    if (!attachment) return;
    const attemptId = crypto.randomUUID();
    const leaseId = crypto.randomUUID();
    const nextEpoch = Number(candidate.execution_epoch ?? 0) + 1;
    const leaseExpiresAt = new Date(Date.now() + 120_000).toISOString();

    const update = await this.env.DB.prepare(
      `UPDATE ordax_jobs SET
         status = 'leased',
         attempt_id = ?1,
         lease_id = ?2,
         execution_epoch = ?3,
         agent_instance_id = ?4,
         boot_id = ?5,
         lease_expires_at = ?6
       WHERE id = ?7 AND device_id = ?8
         AND (status = 'queued' OR (status = 'leased' AND lease_expires_at < ?9))`,
    ).bind(
      attemptId, leaseId, nextEpoch, attachment.agentInstanceId,
      attachment.bootId, leaseExpiresAt, candidate.id, deviceId, now,
    ).run();
    if ((update.meta.changes ?? 0) !== 1) return;

    ws.send(JSON.stringify({
      type: "job",
      job: {
        job_id: candidate.id,
        capability: candidate.capability,
        payload_canonical_b64: candidate.payload_canonical_b64,
        payload_sha256: candidate.payload_sha256,
        effect_id: candidate.effect_id,
        attempt_id: attemptId,
        lease_id: leaseId,
        execution_epoch: nextEpoch,
        agent_instance_id: attachment.agentInstanceId,
        boot_id: attachment.bootId,
        expires_at: leaseExpiresAt,
      },
    }));
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const deviceId = request.headers.get("X-Ordax-Device-Id") ?? "";
    if (!UUID_RE.test(deviceId)) return json({ ok: false, error: "device_id_invalid" }, 400);

    if (url.pathname === "/ws") {
      if (request.method !== "GET") {
        return json({ ok: false, error: "method_not_allowed" }, 405);
      }
      if ((request.headers.get("Upgrade") ?? "").toLowerCase() !== "websocket") {
        return json({ ok: false, error: "websocket_required" }, 426);
      }
      // Do not accept or allocate a WebSocket for invalid execution identities.
      const runtimeIdentity = parseRuntimeIdentityHeaders(request);
      if (!runtimeIdentity) return json({ ok: false, error: "runtime_identity_invalid" }, 400);
      const { agentInstanceId, bootId } = runtimeIdentity;

      // A device may be revoked after the outer Worker authenticates it.
      // Recheck the canonical legacy registry at the DO handshake boundary.
      const presence = await this.env.DB.prepare(
        "UPDATE ordax_devices SET last_seen_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
      ).bind(nowIso(), deviceId).run();
      if ((presence.meta.changes ?? 0) !== 1) {
        return json({ ok: false, error: "device_revoked_or_missing" }, 401);
      }

      const pair = new WebSocketPair();
      const client = pair[0];
      const server = pair[1];
      this.ctx.acceptWebSocket(server);
      server.serializeAttachment({ deviceId, agentInstanceId, bootId });
      server.send(JSON.stringify({
        type: "hello",
        device_id: deviceId,
        protocol: "cloudflare-v3",
      }));
      await this.fenceExpiredForeignRunningJobs(deviceId, agentInstanceId, bootId);
      await this.deliverNextJob(server, deviceId);
      return new Response(null, { status: 101, webSocket: client });
    }

    if (url.pathname === "/wake" && request.method === "POST") {
      const targetAgentInstanceId =
        request.headers.get("X-Ordax-Target-Agent-Instance") ?? "";
      const targetBootId = request.headers.get("X-Ordax-Target-Boot-Id") ?? "";
      const targeted = Boolean(targetAgentInstanceId || targetBootId);
      if (
        targeted
        && (!UUID_RE.test(targetAgentInstanceId) || !UUID_RE.test(targetBootId))
      ) {
        return json({ ok: false, error: "wake_target_invalid" }, 400);
      }

      for (const ws of this.ctx.getWebSockets()) {
        const attachment = this.attachment(ws);
        if (!attachment || attachment.deviceId !== deviceId) continue;
        if (
          targeted
          && (
            attachment.agentInstanceId !== targetAgentInstanceId
            || attachment.bootId !== targetBootId
          )
        ) {
          continue;
        }
        await this.deliverNextJob(ws, deviceId);
      }
      return json({ ok: true });
    }

    return json({ ok: false, error: "not_found" }, 404);
  }

  async webSocketMessage(ws: WebSocket, raw: string | ArrayBuffer): Promise<void> {
    let message: JsonObject;
    try {
      const text = typeof raw === "string" ? raw : new TextDecoder().decode(raw);
      const parsed = JSON.parse(text);
      if (!isRecord(parsed)) throw new Error("not object");
      message = parsed;
    } catch {
      this.ack(ws, null, false, { error: "invalid_json" });
      return;
    }

    const attachment = this.attachment(ws);
    if (!attachment) {
      ws.close(1008, "missing identity");
      return;
    }
    const requestId = message.request_id;
    const type = typeof message.type === "string" ? message.type : "";
    const deviceId = attachment.deviceId;

    if (type === "heartbeat") {
      const presence = await this.env.DB.prepare(
        "UPDATE ordax_devices SET last_seen_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
      ).bind(nowIso(), deviceId).run();
      if ((presence.meta.changes ?? 0) !== 1) {
        this.ack(ws, requestId, false, { error: "device_revoked_or_missing" });
        ws.close(1008, "device revoked or missing");
        return;
      }
      this.ack(ws, requestId, true, { server_time: nowIso() });
      return;
    }

    const jobId = typeof message.job_id === "string" ? message.job_id : "";
    const effectId = typeof message.effect_id === "string" ? message.effect_id : "";
    const attemptId = typeof message.attempt_id === "string" ? message.attempt_id : "";
    const leaseId = typeof message.lease_id === "string" ? message.lease_id : "";
    const executionEpoch = Number.isSafeInteger(message.execution_epoch)
      ? Number(message.execution_epoch) : 0;
    if (
      !UUID_RE.test(jobId)
      || !UUID_RE.test(effectId)
      || !UUID_RE.test(attemptId)
      || !UUID_RE.test(leaseId)
      || executionEpoch < 1
    ) {
      this.ack(ws, requestId, false, { error: "execution_context_invalid" });
      return;
    }

    if (type === "report") {
      const reportId = typeof message.report_id === "string" ? message.report_id : "";
      const status = typeof message.status === "string" ? message.status : "";
      const resultSha256 = typeof message.result_sha256 === "string"
        ? message.result_sha256.toLowerCase()
        : "";
      const resultValue = isRecord(message.result) ? message.result : {};
      const resultJson = stableJson(resultValue);
      const errorCode = typeof message.error_code === "string" ? message.error_code : null;

      if (
        !UUID_RE.test(reportId)
        || !["succeeded", "failed", "cancelled"].includes(status)
        || !HEX64_RE.test(resultSha256)
      ) {
        this.ack(ws, requestId, false, { error: "report_invalid" });
        return;
      }
      if (new TextEncoder().encode(resultJson).byteLength > 512 * 1024) {
        this.ack(ws, requestId, false, { error: "result_too_large" });
        return;
      }

      const terminal = await this.env.DB.prepare(
        `SELECT status, effect_id, attempt_id, report_id, result_json,
                result_sha256, error_code, lease_id, execution_epoch,
                agent_instance_id, boot_id
         FROM ordax_jobs
         WHERE id = ?1 AND device_id = ?2
           AND status IN ('succeeded','failed','cancelled')`,
      ).bind(jobId, deviceId).first<{
        status: string;
        effect_id: string;
        attempt_id: string | null;
        report_id: string | null;
        result_json: string | null;
        result_sha256: string | null;
        error_code: string | null;
        lease_id: string | null;
        execution_epoch: number;
        agent_instance_id: string | null;
        boot_id: string | null;
      }>();

      if (terminal) {
        const replayMatches = (
          terminal.effect_id === effectId
          && terminal.attempt_id === attemptId
          && terminal.report_id === reportId
          && terminal.status === status
          && canonicalStoredJson(terminal.result_json) === resultJson
          && (terminal.result_sha256 ?? "").toLowerCase() === resultSha256
          && terminal.error_code === errorCode
          && terminal.lease_id === leaseId
          && Number(terminal.execution_epoch) === executionEpoch
          && terminal.agent_instance_id === attachment.agentInstanceId
          && terminal.boot_id === attachment.bootId
        );
        this.ack(
          ws,
          requestId,
          replayMatches,
          replayMatches
            ? { status, replayed: true }
            : { error: "terminal_report_conflict" },
        );
        return;
      }
    }

    const active = await this.env.DB.prepare(
      `SELECT id FROM ordax_jobs
       WHERE id = ?1 AND device_id = ?2 AND effect_id = ?3 AND attempt_id = ?4
         AND lease_id = ?5 AND execution_epoch = ?6
         AND agent_instance_id = ?7 AND boot_id = ?8
         AND status IN ('leased','running')`,
    ).bind(
      jobId, deviceId, effectId, attemptId, leaseId, executionEpoch,
      attachment.agentInstanceId, attachment.bootId,
    ).first();
    if (!active) {
      this.ack(ws, requestId, false, { error: "lease_not_active" });
      return;
    }

    if (type === "start") {
      const startedAt = nowIso();
      const result = await this.env.DB.prepare(
        `UPDATE ordax_jobs SET status = 'running', started_at = COALESCE(started_at, ?1)
         WHERE id = ?2 AND device_id = ?3 AND effect_id = ?4 AND attempt_id = ?5
           AND lease_id = ?6 AND execution_epoch = ?7
           AND agent_instance_id = ?8 AND boot_id = ?9
           AND status IN ('leased','running') AND report_id IS NULL`,
      ).bind(
        startedAt, jobId, deviceId, effectId, attemptId, leaseId, executionEpoch,
        attachment.agentInstanceId, attachment.bootId,
      ).run();
      const ok = (result.meta.changes ?? 0) === 1;
      this.ack(ws, requestId, ok, ok ? { started: true } : { error: "start_rejected" });
      return;
    }

    if (type === "lease_heartbeat") {
      const leasedUntil = new Date(Date.now() + 120_000).toISOString();
      const result = await this.env.DB.prepare(
        `UPDATE ordax_jobs SET lease_expires_at = ?1
         WHERE id = ?2 AND device_id = ?3 AND effect_id = ?4 AND attempt_id = ?5
           AND lease_id = ?6 AND execution_epoch = ?7
           AND agent_instance_id = ?8 AND boot_id = ?9
           AND status IN ('leased','running') AND report_id IS NULL`,
      ).bind(
        leasedUntil, jobId, deviceId, effectId, attemptId, leaseId, executionEpoch,
        attachment.agentInstanceId, attachment.bootId,
      ).run();
      const ok = (result.meta.changes ?? 0) === 1;
      this.ack(
        ws,
        requestId,
        ok,
        ok ? { leased_until: leasedUntil } : { error: "lease_not_active" },
      );
      return;
    }

    if (type === "progress") {
      const percent = message.progress_percent == null ? null
        : Number.isInteger(message.progress_percent)
          ? Math.max(0, Math.min(100, Number(message.progress_percent)))
          : null;
      const stage = typeof message.stage === "string" ? message.stage.slice(0, 96) : "info";
      const text = typeof message.message === "string" ? message.message.slice(0, 512) : null;
      await this.env.DB.prepare(
        `INSERT INTO ordax_job_events (job_id, stage, message, progress_percent, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)`,
      ).bind(jobId, stage, text, percent, nowIso()).run();
      this.ack(ws, requestId, true);
      return;
    }

    if (type === "report") {
      const reportId = String(message.report_id);
      const status = String(message.status);
      const resultSha256 = String(message.result_sha256).toLowerCase();
      const resultValue = isRecord(message.result) ? message.result : {};
      const resultJson = stableJson(resultValue);
      const errorCode = typeof message.error_code === "string" ? message.error_code : null;
      const finishedAt = nowIso();

      const update = await this.env.DB.prepare(
        `UPDATE ordax_jobs SET
           status = ?1, report_id = ?2, result_json = ?3, result_sha256 = ?4,
           error_code = ?5, finished_at = ?6, lease_expires_at = NULL
         WHERE id = ?7 AND device_id = ?8 AND effect_id = ?9 AND attempt_id = ?10
           AND lease_id = ?11 AND execution_epoch = ?12
           AND agent_instance_id = ?13 AND boot_id = ?14
           AND status IN ('leased','running') AND report_id IS NULL`,
      ).bind(
        status, reportId, resultJson, resultSha256, errorCode,
        finishedAt, jobId, deviceId, effectId, attemptId, leaseId,
        executionEpoch, attachment.agentInstanceId, attachment.bootId,
      ).run();
      const ok = (update.meta.changes ?? 0) === 1;
      this.ack(ws, requestId, ok, ok ? { status, replayed: false } : { error: "report_rejected" });
      if (ok) await this.deliverNextJob(ws, deviceId);
      return;
    }

    this.ack(ws, requestId, false, { error: "operation_not_allowed" });
  }

  async webSocketClose(
    _ws: WebSocket,
    _code: number,
    _reason: string,
    _wasClean: boolean,
  ): Promise<void> {
    // Presence is freshness-based in D1; disconnect doesn't revoke the device.
  }

  async webSocketError(_ws: WebSocket, _error: unknown): Promise<void> {
    // The next device reconnect reuses the same Durable Object identity.
  }
}
