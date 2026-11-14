import {
  applyGithubAuthorityRevocation,
  ProductPostgresError,
  type GithubAuthorityRevocationResult,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";

type Json = Record<string, unknown>;
type Revocation = Readonly<{
  event: "installation" | "installation_repositories" | "repository";
  action: string;
  installationId: string;
  repositoryIds: readonly string[];
}>;

export interface ProductGithubWebhookEnv extends ProductPostgresEnv {
  PRODUCT_GITHUB_APP_WEBHOOK_ENABLED?: string;
  PRODUCT_GITHUB_APP_WEBHOOK_SECRET?: string;
}

type Dependencies = Readonly<{
  applyRevocation?: typeof applyGithubAuthorityRevocation;
}>;

export const PRODUCT_GITHUB_WEBHOOK_PATH = "/v3/github/webhook";

const MAX_BODY_BYTES = 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SIGNATURE = /^sha256=([0-9a-f]{64})$/;
const SECRET = /^[^\s\u0000-\u001f\u007f]{32,512}$/;
const DESTRUCTIVE_REPOSITORY_ACTIONS = new Set([
  "archived", "deleted", "renamed", "transferred",
]);

const json = (body: unknown, status = 200) => Response.json(body, {
  status,
  headers: {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  },
});

function record(value: unknown): Json | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Json : null;
}

function providerId(value: unknown): string | null {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) return null;
  return String(value);
}

function installationId(payload: Json): string | null {
  const installation = record(payload.installation);
  return installation ? providerId(installation.id) : null;
}

function repositoryIds(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length > 500) return null;
  const ids = new Set<string>();
  for (const item of value) {
    const row = record(item);
    const id = row ? providerId(row.id) : null;
    if (!id) return null;
    ids.add(id);
  }
  return [...ids].sort((a, b) => {
    const left = BigInt(a), right = BigInt(b);
    return left < right ? -1 : left > right ? 1 : 0;
  });
}

export function githubAuthorityRevocation(
  event: string,
  payload: unknown,
): Revocation | null {
  const body = record(payload);
  if (!body || typeof body.action !== "string") return null;
  const action = body.action;
  const installation = installationId(body);

  if (event === "installation") {
    if (!installation || !["deleted", "suspend"].includes(action)) return null;
    return { event, action, installationId: installation, repositoryIds: [] };
  }

  if (event === "installation_repositories") {
    if (!installation || !["added", "removed"].includes(action)) return null;
    const removed = repositoryIds(body.repositories_removed);
    if (!removed || removed.length === 0) return null;
    return { event, action, installationId: installation, repositoryIds: removed };
  }

  if (event === "repository") {
    if (!installation || !DESTRUCTIVE_REPOSITORY_ACTIONS.has(action)) return null;
    const repository = record(body.repository);
    const id = repository ? providerId(repository.id) : null;
    if (!id) return null;
    return { event, action, installationId: installation, repositoryIds: [id] };
  }

  return null;
}

function bytesFromHex(value: string): Uint8Array | null {
  if (value.length % 2 !== 0) return null;
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < value.length; i += 2) {
    const byte = Number.parseInt(value.slice(i, i + 2), 16);
    if (!Number.isFinite(byte)) return null;
    out[i / 2] = byte;
  }
  return out;
}

export async function verifyGithubWebhookSignature(
  secret: string,
  rawBody: Uint8Array,
  header: string,
): Promise<boolean> {
  if (!SECRET.test(secret)) return false;
  const match = SIGNATURE.exec(header);
  if (!match) return false;
  const signature = bytesFromHex(match[1]);
  if (!signature) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    "HMAC",
    key,
    signature,
    rawBody,
  );
}

async function sha256(rawBody: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", rawBody));
  return [...digest].map(value => value.toString(16).padStart(2, "0")).join("");
}

function validResult(
  value: GithubAuthorityRevocationResult,
  deliveryId: string,
): value is GithubAuthorityRevocationResult & { ok: true } {
  if (!value || value.ok !== true || value.delivery_id !== deliveryId
      || typeof value.replayed !== "boolean") return false;
  for (const key of [
    "connection_count", "binding_count", "grant_count", "action_count", "intent_count",
  ] as const) {
    const count = value[key];
    if (!Number.isSafeInteger(count) || Number(count) < 0) return false;
  }
  return true;
}

export function createProductGithubWebhookHandler(
  env: ProductGithubWebhookEnv,
  deps: Dependencies = {},
) {
  const applyRevocation = deps.applyRevocation ?? applyGithubAuthorityRevocation;

  return async function handleGithubWebhook(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const secret = env.PRODUCT_GITHUB_APP_WEBHOOK_SECRET ?? "";
    if (url.pathname !== PRODUCT_GITHUB_WEBHOOK_PATH
        || env.PRODUCT_GITHUB_APP_WEBHOOK_ENABLED !== "enabled"
        || !SECRET.test(secret)) {
      return json({ ok: false, error: "not_found" }, 404);
    }
    if (request.method !== "POST") {
      return json({ ok: false, error: "method_not_allowed" }, 405);
    }
    if (url.search !== ""
        || (request.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase()
          !== "application/json") {
      return json({ ok: false, error: "github_webhook_invalid" }, 400);
    }

    const rawLength = request.headers.get("content-length");
    if (rawLength && /^\d+$/.test(rawLength) && Number(rawLength) > MAX_BODY_BYTES) {
      return json({ ok: false, error: "github_webhook_too_large" }, 413);
    }

    const deliveryId = (request.headers.get("x-github-delivery") ?? "").toLowerCase();
    const event = request.headers.get("x-github-event") ?? "";
    const signature = (request.headers.get("x-hub-signature-256") ?? "").toLowerCase();
    if (!UUID.test(deliveryId) || !/^[a-z_]{1,80}$/.test(event) || !SIGNATURE.test(signature)) {
      return json({ ok: false, error: "github_webhook_invalid" }, 400);
    }

    const rawBody = new Uint8Array(await request.arrayBuffer());
    if (rawBody.length === 0 || rawBody.length > MAX_BODY_BYTES) {
      return json({ ok: false, error: "github_webhook_too_large" }, 413);
    }
    if (!await verifyGithubWebhookSignature(secret, rawBody, signature)) {
      return json({ ok: false, error: "github_webhook_signature_invalid" }, 401);
    }

    let payload: unknown;
    try {
      payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(rawBody));
    } catch {
      return json({ ok: false, error: "github_webhook_invalid" }, 400);
    }

    if (event === "ping") return json({ ok: true, accepted: true });

    // User access tokens are deliberately never persisted. This event therefore
    // has no credential to revoke locally. Installation/repository authority is
    // revoked by the provider-scope events below.
    if (event === "github_app_authorization") {
      return json({ ok: true, accepted: true, ignored: true }, 202);
    }

    const revocation = githubAuthorityRevocation(event, payload);
    if (!revocation) {
      return json({ ok: true, accepted: true, ignored: true }, 202);
    }

    try {
      const result = await applyRevocation(env, {
        deliveryId,
        event: revocation.event,
        action: revocation.action,
        installationId: revocation.installationId,
        repositoryIds: revocation.repositoryIds,
        payloadSha256: await sha256(rawBody),
      });
      if (result.ok === false) {
        return json({ ok: false, error: "github_webhook_revocation_rejected" }, 409);
      }
      if (!validResult(result, deliveryId)) {
        return json({ ok: false, error: "product_postgres_invalid_response" }, 503);
      }
      return json({ ok: true, accepted: true, replayed: result.replayed });
    } catch (error) {
      if (error instanceof ProductPostgresError) {
        return json({ ok: false, error: "github_webhook_unavailable" }, 503);
      }
      return json({ ok: false, error: "github_webhook_unavailable" }, 503);
    }
  };
}

export function handleProductGithubWebhook(
  request: Request,
  env: ProductGithubWebhookEnv,
): Promise<Response> {
  return createProductGithubWebhookHandler(env)(request);
}
