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
  const code = error && typeof error === "object" && "code" in error
    ? String((error as { code?: unknown }).code ?? "").toUpperCase()
    : "";
  // SQLSTATE is a five-character public protocol identifier. Returning only
  // this bounded code reveals the error class without reflecting provider
  // messages, hosts, connection strings, credentials or arbitrary fields.
  if (/^[0-9A-Z]{5}$/.test(code)) return "sqlstate_" + code;
  const msg = error instanceof Error ? error.message.toLowerCase() : "";
  // Cloudflare documents these Hyperdrive runtime messages. Map only exact
  // bounded categories; never return provider text, hostnames or credentials.
  if (msg.includes("internal error")) return "hyperdrive_internal_error";
  if (msg.includes("generic error")) return "hyperdrive_generic_error";
  if (msg.includes("failed to acquire a connection from the pool")) {
    return "hyperdrive_pool_acquire_failed";
  }
  if (msg.includes("connection terminated unexpectedly")) return "connection_terminated";
  if (msg.includes("authentication") || msg.includes("password")) return "authentication_failed";
  if (msg.includes("tls") || msg.includes("certificate")) return "tls_failure";
  if (msg.includes("timeout")) return "timeout";
  if (msg.includes("network") || msg.includes("connection")) return "connection_failed";
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
