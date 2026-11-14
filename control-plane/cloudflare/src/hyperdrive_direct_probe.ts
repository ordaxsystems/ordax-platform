/** Diagnostic Worker, never a Product MCP authority. No D1/OAuth/owner state.
 * Uses the Hyperdrive binding of ONE ephemeral configuration and SELECT 1.
 */
import { connect } from "cloudflare:sockets";
import { openPostgresSession } from "./data_postgres_driver.ts";

type Env = {
  POSTGRES: { connectionString: string };
  ORDAX_PROBE_ORIGIN_HOST: string;
  ORDAX_PROBE_ORIGIN_PORT: string;
};

function safeError(error: unknown): string {
  const record = error && typeof error === "object"
    ? error as Record<string, unknown> : {};
  const cause = record.cause && typeof record.cause === "object"
    ? record.cause as Record<string, unknown> : {};
  const code = String(record.code ?? "").toUpperCase();
  const providerCode = String(cause.code ?? "").toUpperCase();
  const msg = [record.message, record.detail, cause.message, cause.detail]
    .filter((value): value is string => typeof value === "string")
    .map(value => value.toLowerCase()).join(" ");

  // A SQLSTATE 58000 is Hyperdrive's envelope for provider-specific runtime
  // failures. Inspect only allowlisted categories BEFORE returning the generic
  // SQLSTATE so the diagnostic can distinguish a provider failure without
  // reflecting any message, hostname, connection string or credential.
  if (msg.includes("failed to acquire a connection from the pool")) {
    return "hyperdrive_pool_acquire_failed";
  }
  if (msg.includes("server connection attempt failed")) {
    return "hyperdrive_server_connection_failed";
  }
  if (msg.includes("server return error and closed connection")) {
    return "hyperdrive_server_closed_connection";
  }
  if (msg.includes("failed to connect to the provided database")) {
    return "hyperdrive_database_connect_failed";
  }
  if (msg.includes("internal error")) return "hyperdrive_internal_error";
  if (msg.includes("generic error")) return "hyperdrive_generic_error";
  if (msg.includes("connection terminated unexpectedly")) return "connection_terminated";
  if (msg.includes("authentication") || msg.includes("password")) return "authentication_failed";
  if (msg.includes("tls") || msg.includes("certificate")) return "tls_failure";
  if (msg.includes("timeout")) return "timeout";
  if (msg.includes("network") || msg.includes("connection")) return "connection_failed";

  // Cloudflare documents provider connection codes 2008..2016. Expose only
  // that finite allowlist if a wrapped cause carries one.
  if (/^20(?:08|09|10|11|12|13|14|15|16)$/.test(providerCode)) {
    return "hyperdrive_code_" + providerCode;
  }

  // SQLSTATE is a five-character public protocol identifier. Returning only
  // this bounded code reveals the error class without arbitrary provider data.
  if (/^[0-9A-Z]{5}$/.test(code)) return "sqlstate_" + code;
  return "unclassified";
}

async function probeOriginTcp(env: Env): Promise<boolean> {
  const port = Number(env.ORDAX_PROBE_ORIGIN_PORT);
  if (!env.ORDAX_PROBE_ORIGIN_HOST || !Number.isInteger(port)
      || port < 1 || port > 65535) return false;
  const socket = connect(
    { hostname: env.ORDAX_PROBE_ORIGIN_HOST, port },
    { secureTransport: "off", allowHalfOpen: false },
  );
  try {
    await Promise.race([
      socket.opened,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("tcp_probe_timeout")), 5000)),
    ]);
    return true;
  } catch {
    return false;
  } finally {
    await socket.close().catch(() => {});
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== "GET" || new URL(request.url).pathname !== "/") {
      return new Response("Not found", { status: 404 });
    }
    const tcpReachable = await probeOriginTcp(env);
    if (!tcpReachable) {
      return Response.json(
        { ok: false, phase: "tcp", classification: "origin_tcp_unreachable" },
        { status: 503 },
      );
    }
    const client = openPostgresSession(env.POSTGRES.connectionString);
    let phase = "connect";
    try {
      await client.connect();
      phase = "query";
      const result = await client.query("select 1::int as ok");
      const ok = result.rows?.[0]?.ok === 1;
      return Response.json({ ok, phase: "complete" }, { status: ok ? 200 : 503 });
    } catch (error) {
      return Response.json({ ok: false, phase, classification: safeError(error) },
                           { status: 503 });
    } finally {
      await client.end().catch(() => {});
    }
  },
};
