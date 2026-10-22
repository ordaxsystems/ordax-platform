import {
  authenticateProductDevice,
  ProductPostgresError,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { sha256Hex } from "./product_crypto.ts";

type ProductDeviceAuthentication =
  | { ok: true; deviceId: string }
  | { ok: false; response: Response };

function respond(value: unknown, status = 200): Response {
  return Response.json(value, {
    status,
    headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });
}

/** Reusable canonical Product device credential boundary for device routes. */
export async function authenticateProductDeviceRequest(
  request: Request,
  env: ProductPostgresEnv,
): Promise<ProductDeviceAuthentication> {
  const deviceId = (request.headers.get("x-ordax-device-id") ?? "").trim().toLowerCase();
  const rawToken = request.headers.get("x-ordax-device-token") ?? "";
  if (!isCanonicalUuid(deviceId) || rawToken.length < 32 || rawToken.length > 512
      || /[\r\n]/.test(rawToken)) {
    return { ok: false, response: respond({ ok: false, error: "device_auth_required" }, 401) };
  }
  try {
    const accepted = await authenticateProductDevice(env, {
      deviceId,
      tokenSha256: await sha256Hex(rawToken),
    });
    if (!accepted) {
      return { ok: false, response: respond({ ok: false, error: "invalid_device_token" }, 401) };
    }
    return { ok: true, deviceId };
  } catch (error) {
    if (error instanceof ProductPostgresError) {
      return { ok: false, response: respond({ ok: false, error: error.code }, error.status) };
    }
    return { ok: false, response: respond({ ok: false, error: "product_postgres_unavailable" }, 503) };
  }
}
