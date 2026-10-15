import {
  authenticateProductRequest,
  type ProductAuthEnv,
} from "./product_auth.ts";
import {
  enrollProductDevice,
  identifyProductDevice,
  ProductPostgresError,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { readBoundedJsonObject } from "./request_json.ts";

export const PRODUCT_DEVICE_SETUP_PATH = "/v3/device/setup";

type Env = ProductAuthEnv & ProductPostgresEnv;
type JsonObject = Record<string, unknown>;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX64_RE = /^[0-9a-f]{64}$/i;
const DEVICE_KINDS = new Set(["desktop", "laptop", "mobile", "server", "other"]);
const CHANNELS = new Set(["stable", "development"]);

function respond(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

async function sha256Text(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)]
    .map((item) => item.toString(16).padStart(2, "0"))
    .join("");
}

function postgresFailure(error: unknown): Response {
  if (error instanceof ProductPostgresError) {
    return respond({ ok: false, error: error.code }, error.status);
  }
  return respond({ ok: false, error: "product_postgres_unavailable" }, 503);
}

/**
 * Product-device bootstrap on the same canonical PostgreSQL/Auth boundary as
 * the public MCP. This route deliberately has no D1, legacy Worker or global
 * operator-token fallback.
 */
export async function handleProductDeviceSetup(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return respond({ ok: false, error: "method_not_allowed" }, 405);
  }

  let body: JsonObject | null = null;
  try {
    body = await readBoundedJsonObject(request, 16 * 1024);
  } catch {
    return respond({ ok: false, error: "request_invalid" }, 400);
  }
  if (!body) return respond({ ok: false, error: "request_invalid" }, 400);

  const operation = typeof body.operation === "string" ? body.operation : "";
  const machineBindingSha256 = typeof body.machine_binding_sha256 === "string"
    ? body.machine_binding_sha256.toLowerCase()
    : "";
  if (!HEX64_RE.test(machineBindingSha256)) {
    return respond({ ok: false, error: "request_invalid" }, 400);
  }

  if (operation === "identify") {
    const rawToken = request.headers.get("X-Ordax-Device-Token") ?? "";
    if (rawToken.length < 32 || rawToken.length > 512) {
      return respond({ ok: false, error: "device_auth_required" }, 401);
    }
    try {
      const identified = await identifyProductDevice(env, {
        tokenSha256: await sha256Text(rawToken),
        machineBindingSha256,
      });
      if (identified.ok !== true || typeof identified.device_id !== "string"
          || !UUID_RE.test(identified.device_id)) {
        return respond({ ok: false, error: "device_token_invalid" }, 401);
      }
      return respond({
        ok: true,
        protocol: "cloudflare-v3",
        device_id: identified.device_id,
      });
    } catch (error) {
      return postgresFailure(error);
    }
  }

  if (operation !== "enroll") {
    return respond({ ok: false, error: "operation_not_allowed" }, 400);
  }

  const tokenSha256 = typeof body.token_sha256 === "string"
    ? body.token_sha256.toLowerCase()
    : "";
  const deviceName = typeof body.device_name === "string" ? body.device_name.trim() : "";
  const deviceKind = typeof body.device_kind === "string" ? body.device_kind : "";
  const channel = typeof body.channel === "string" ? body.channel : "";
  if (!HEX64_RE.test(tokenSha256)
      || deviceName.length < 1
      || deviceName.length > 120
      || /[\x00-\x1f\x7f]/.test(deviceName)
      || !DEVICE_KINDS.has(deviceKind)
      || !CHANNELS.has(channel)) {
    return respond({ ok: false, error: "request_invalid" }, 400);
  }

  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) {
    return respond({ ok: false, error: identity.error }, identity.status);
  }
  if (!UUID_RE.test(identity.subjectId)) {
    return respond({ ok: false, error: "device_owner_invalid" }, 403);
  }

  try {
    const enrolled = await enrollProductDevice(env, {
      ownerUserId: identity.subjectId,
      deviceName,
      deviceKind: deviceKind as "desktop" | "laptop" | "mobile" | "server" | "other",
      channel: channel as "stable" | "development",
      tokenSha256,
      machineBindingSha256,
    });
    if (enrolled.ok !== true || typeof enrolled.device_id !== "string"
        || !UUID_RE.test(enrolled.device_id)) {
      const code = typeof enrolled.error === "string"
        ? enrolled.error
        : "device_enrollment_invalid";
      const statuses: Record<string, number> = {
        device_enrollment_invalid: 400,
        device_owner_not_found: 403,
        device_owner_mismatch: 403,
        device_credential_conflict: 409,
        device_credential_missing: 409,
        enrollment_rate_limited: 429,
      };
      return respond({ ok: false, error: code }, statuses[code] ?? 502);
    }
    return respond({
      ok: true,
      protocol: "cloudflare-v3",
      device_id: enrolled.device_id,
    });
  } catch (error) {
    return postgresFailure(error);
  }
}
