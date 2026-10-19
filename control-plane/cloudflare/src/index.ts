import { DurableObject } from "cloudflare:workers";
import { authenticateProductRequest, productOwnerAccountSession, productAuthConfigured, type ProductAuthEnv } from "./product_auth";
import { createCanonicalProductMcpReadHandlers } from "./product_mcp_reads";
import { openAiAppsChallenge, publicProductPage } from "./public_pages";
import { readBoundedJsonObject } from "./request_json";
import { handleProductDevicePresence, PRODUCT_DEVICE_PRESENCE_PATH } from "./product_device_presence";
import { handleProductDeviceTransport, PRODUCT_DEVICE_TRANSPORT_PREFIX } from "./product_device_transport";
import { enrollProductDevice, identifyProductDevice, ProductPostgresError, productPostgresConfigured, type ProductPostgresEnv } from "./product_postgres_store";

// The Control Plane only exposes canonical PostgreSQL-backed product routes.
// The previously public engineering D1/WebSocket/artifact surface was retired.
// Keep the Durable Object class solely for safe deployment compatibility with
// the existing Cloudflare class migration; it owns no business state.
interface Env extends ProductAuthEnv, ProductPostgresEnv {
  OPENAI_APPS_CHALLENGE?: string;
}
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX64_RE = /^[0-9a-f]{64}$/i;
const CONTROL_PLANE_CAPABILITIES = [
  "product_subject_auth_jwks_v1",
  "product_readonly_actions_v1",
  "product_typed_actions_v2",
  "product_device_postgres_transport_v1",
];
function json(body: unknown, status = 200): Response {
  return Response.json(body, {status, headers: {"cache-control":"no-store"}});
}
async function sha256Text(value: string): Promise<string> {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return Array.from(bytes, b => b.toString(16).padStart(2,"0")).join("");
}
async function parseSmallJson(request: Request, limit: number): Promise<Record<string, unknown> | null> {
  return readBoundedJsonObject(request, limit);
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


export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const parts = path.split("/").filter(Boolean);
    if (request.method === "GET" && path === "/health") {
      return json({ok:true,service:"ordax-control-plane-v3",capabilities:CONTROL_PLANE_CAPABILITIES,
        product_auth_configured:productAuthConfigured(env),
        product_postgres_configured:productPostgresConfigured(env)});
    }
    if (request.method === "GET" && path === "/.well-known/openai-apps-challenge") return openAiAppsChallenge(env);
    if (request.method === "GET") {
      const page=publicProductPage(path);
      if(page) return page;
    }
    if (path === PRODUCT_DEVICE_PRESENCE_PATH) return handleProductDevicePresence(request,env);
    if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX || path.startsWith(PRODUCT_DEVICE_TRANSPORT_PREFIX+"/")) {
      return handleProductDeviceTransport(request,env);
    }
    if (request.method === "POST" && path === "/v3/device/setup") return deviceSetup(request,env);
    if (request.method === "GET" && path === "/v3/product/session") return productOwnerAccountSession(request,env);
    if (request.method === "GET" && path === "/v3/product/targets") return createCanonicalProductMcpReadHandlers(env).targets(request);
    if (request.method === "GET" && parts.length===4 && parts[0]==="v3"
      && parts[1]==="product" && parts[2]==="actions") {
      return createCanonicalProductMcpReadHandlers(env).getAction(request,parts[3]);
    }
    const legacy = path === "/mcp" || path === "/v3/device/ws"
      || path === "/v3/device/recover-report" || path === "/v3/devices" || path === "/v3/jobs"
      || path.startsWith("/v3/jobs/") || path.startsWith("/v3/artifacts/")
      || path.startsWith("/v3/product-grants") || path.startsWith("/v3/product/device-links")
      || path.startsWith("/v3/product/device-intelligence-grants")
      || path.startsWith("/v3/product/device-computer-grants")
      || path.startsWith("/v3/product/project-capability-grants")
      || path === "/v3/product/actions" || path === "/v3/product/audit"
      || path === "/oauth/consent" || path === "/.well-known/oauth-protected-resource"
      || path === "/v3/device/product-pairings";
    if (legacy) return json({ok:false,error:"legacy_endpoint_retired"},410);
    return json({ok:false,error:"not_found"},404);
  },
};

// Cloudflare Durable Object migrations may reference the exported class.
// All legacy sessions fail closed: no D1 binding and no engineering queue.
export class DeviceSession extends DurableObject<Env> {
  async fetch(): Promise<Response> {
    return json({ok:false,error:"legacy_device_session_retired"},410);
  }
}
