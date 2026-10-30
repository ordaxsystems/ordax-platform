/** Ephemeral read-only compatibility comparison; NEVER an OrdaX Product authority.
 * Same canonical Hyperdrive binding, two supported Cloudflare SQL drivers.
 * No SQL beyond SELECT 1; no authorization, identity, sessions, data reads or writes.
 */
import postgres from "postgres";
import { openPostgresSession } from "../src/data_postgres_driver.ts";

type ProbeEnv = { POSTGRES: { connectionString: string } };
type DriverName = "node_postgres" | "postgres_js";

function classify(err: unknown): string {
  const record = err && typeof err === "object" ? err as Record<string, unknown> : {};
  const msg = typeof record.message === "string" ? record.message.toLowerCase() : "";
  if (msg.includes("connection terminated unexpectedly")) return "terminated_unexpectedly";
  if (msg.includes("connection terminated") || msg.includes("connection closed")) return "connection_closed";
  if (msg.includes("authentication") || msg.includes("password")) return "authentication";
  if (msg.includes("tls") || msg.includes("certificate") || msg.includes("ssl")) return "tls";
  if (msg.includes("timeout") || msg.includes("timed out")) return "timeout";
  if (msg.includes("refused") || msg.includes("unreachable")) return "network";
  return "other";
}

function safeError(err: unknown): { classification: string; code?: string; error_class?: string } {
  const record = err && typeof err === "object" ? err as Record<string, unknown> : {};
  // Only bounded machine codes are permitted. Never expose message, stack,
  // connection URI, hostname, query text, credentials, or arbitrary metadata.
  const rawCode = record.code;
  const code = typeof rawCode === "string" && /^[A-Z0-9_]{2,32}$/.test(rawCode)
    ? rawCode : undefined;
  const rawName = record.name;
  const errorClass = typeof rawName === "string"
    && ["Error", "TypeError", "PostgresError", "AggregateError"].includes(rawName)
    ? rawName : undefined;
  return { classification: classify(err),
    ...(code ? { code } : {}), ...(errorClass ? { error_class: errorClass } : {}) };
}

async function probePg(connectionString: string): Promise<{ ok: boolean; phase: string; classification?: string }> {
  const client = openPostgresSession(connectionString);
  let phase = "connect";
  try {
    await client.connect();
    phase = "query";
    const result = await client.query<{ ok: number }>("select 1::int as ok");
    return { ok: result.rows?.[0]?.ok === 1, phase: "complete" };
  } catch (error) {
    return { ok: false, phase, ...safeError(error) };
  } finally {
    await client.end().catch(() => {});
  }
}

async function probePostgresJs(connectionString: string): Promise<{ ok: boolean; phase: string; classification?: string }> {
  // Postgres.js establishes the network connection lazily on query. Hence
  // connect_or_query is a truthful phase (not a fake separate connect stage).
  const sql = postgres(connectionString, {
    max: 1, prepare: true, fetch_types: false,
    connect_timeout: 8, idle_timeout: 1, max_lifetime: 10,
  });
  try {
    const result = await sql`select 1::int as ok`;
    return { ok: result[0]?.ok === 1, phase: "complete" };
  } catch (error) {
    return { ok: false, phase: "connect_or_query", ...safeError(error) };
  } finally {
    await sql.end({ timeout: 1 }).catch(() => {});
  }
}

export default {
  async fetch(request: Request, env: ProbeEnv): Promise<Response> {
    const url = new URL(request.url);
    const driver: DriverName | null = url.pathname === "/pg" ? "node_postgres"
      : url.pathname === "/postgres-js" ? "postgres_js" : null;
    if (request.method !== "GET" || !driver || url.search) {
      return new Response("Not found", { status: 404 });
    }
    const result = driver === "node_postgres"
      ? await probePg(env.POSTGRES.connectionString)
      : await probePostgresJs(env.POSTGRES.connectionString);
    return Response.json({ driver, ...result }, {
      status: result.ok ? 200 : 503,
      headers: { "cache-control": "no-store" },
    });
  },
};
