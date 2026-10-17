import { Client } from "pg";
import {
  ProductPostgresError,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";

type JsonObject = Record<string, unknown>;

export type CentralDeviceSessionOpenResult = Readonly<{
  ok: boolean;
  status?: "pending" | "bound";
  device_id?: string;
  challenge_id?: string;
  request_id?: string;
  expires_at?: string;
  error?: string;
}>;

export type CentralDeviceSessionPollResult = Readonly<{
  ok: boolean;
  pending?: boolean;
  challenge_id?: string;
  expires_at?: string;
  error?: string;
}>;

export type CentralDeviceSessionResolveResult = Readonly<{
  ok: boolean;
  device_id?: string;
  request_id?: string;
  expires_at?: string;
  error?: string;
}>;

const CLIENT = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,159}$/;
const HEX64 = /^[0-9a-f]{64}$/;

const RPCS = {
  ordax_open_central_device_session_v1: {
    keys: ["p_owner_user_id", "p_client_id", "p_session_sha256"],
    casts: ["uuid", "text", "text"],
  },
  ordax_poll_central_device_session_v1: {
    keys: ["p_device_id", "p_token_sha256"],
    casts: ["uuid", "text"],
  },
  ordax_confirm_central_device_session_v1: {
    keys: ["p_device_id", "p_token_sha256", "p_challenge_id"],
    casts: ["uuid", "text", "uuid"],
  },
  ordax_resolve_central_device_session_v1: {
    keys: ["p_owner_user_id", "p_client_id", "p_session_sha256"],
    casts: ["uuid", "text", "text"],
  },
} as const;

type RpcName = keyof typeof RPCS;

function connectionString(env: ProductPostgresEnv): string {
  const raw = (env.POSTGRES?.connectionString ?? "").trim();
  if (!raw) throw new ProductPostgresError("product_postgres_unconfigured", 503);
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") throw new Error("scheme");
  } catch {
    throw new ProductPostgresError("product_postgres_unconfigured", 503);
  }
  return raw;
}

async function call<T>(env: ProductPostgresEnv, rpc: RpcName, values: JsonObject): Promise<T> {
  const spec = RPCS[rpc];
  const client = new Client({
    connectionString: connectionString(env),
    query_timeout: 10_000,
  });
  const args = spec.casts.map((cast, index) => `$${index + 1}::${cast}`).join(", ");
  const query = `select public.${rpc}(${args}) as result`;
  try {
    const bound = spec.keys.map(key => values[key]);
    await client.connect();
    const response = await client.query(query, bound);
    const rows = response.rows;
    const row = rows[0] as { result?: T } | undefined;
    if (!row || !Object.prototype.hasOwnProperty.call(row, "result")) {
      throw new ProductPostgresError("product_postgres_invalid_response", 502);
    }
    return row.result as T;
  } catch (error) {
    if (error instanceof ProductPostgresError) throw error;
    throw new ProductPostgresError("product_postgres_unavailable", 503);
  } finally {
    try { await client.end(); } catch { /* Hyperdrive owns upstream pooling. */ }
  }
}

function validClient(clientId: string): boolean {
  return CLIENT.test(clientId);
}

function validHash(value: string): boolean {
  return HEX64.test(value);
}

function ensureOpenInput(ownerUserId: string, clientId: string, sessionSha256: string): void {
  if (!isCanonicalUuid(ownerUserId) || !validClient(clientId) || !validHash(sessionSha256)) {
    throw new ProductPostgresError("central_session_invalid", 400);
  }
}

export async function openCentralDeviceSession(
  env: ProductPostgresEnv,
  input: { ownerUserId: string; clientId: string; sessionSha256: string },
): Promise<CentralDeviceSessionOpenResult> {
  ensureOpenInput(input.ownerUserId, input.clientId, input.sessionSha256);
  return call(env, "ordax_open_central_device_session_v1", {
    p_owner_user_id: input.ownerUserId,
    p_client_id: input.clientId,
    p_session_sha256: input.sessionSha256,
  });
}

export async function pollCentralDeviceSession(
  env: ProductPostgresEnv,
  input: { deviceId: string; tokenSha256: string },
): Promise<CentralDeviceSessionPollResult> {
  if (!isCanonicalUuid(input.deviceId) || !validHash(input.tokenSha256)) {
    throw new ProductPostgresError("product_device_unauthorized", 401);
  }
  return call(env, "ordax_poll_central_device_session_v1", {
    p_device_id: input.deviceId,
    p_token_sha256: input.tokenSha256,
  });
}

export async function confirmCentralDeviceSession(
  env: ProductPostgresEnv,
  input: { deviceId: string; tokenSha256: string; challengeId: string },
): Promise<CentralDeviceSessionOpenResult> {
  if (!isCanonicalUuid(input.deviceId) || !validHash(input.tokenSha256)
    || !isCanonicalUuid(input.challengeId)) {
    throw new ProductPostgresError("central_session_challenge_invalid", 400);
  }
  return call(env, "ordax_confirm_central_device_session_v1", {
    p_device_id: input.deviceId,
    p_token_sha256: input.tokenSha256,
    p_challenge_id: input.challengeId,
  });
}

export async function resolveCentralDeviceSession(
  env: ProductPostgresEnv,
  input: { ownerUserId: string; clientId: string; sessionSha256: string },
): Promise<CentralDeviceSessionResolveResult> {
  ensureOpenInput(input.ownerUserId, input.clientId, input.sessionSha256);
  return call(env, "ordax_resolve_central_device_session_v1", {
    p_owner_user_id: input.ownerUserId,
    p_client_id: input.clientId,
    p_session_sha256: input.sessionSha256,
  });
}
