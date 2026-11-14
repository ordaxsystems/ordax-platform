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

type SafeErrorReceipt = {
  classification: string;
  code?: string;
  error_class?: string;
  cause_code?: string;
  cause_class?: string;
  nested_codes?: string[];
  nested_classes?: string[];
};

const SAFE_CLASSES = new Set(["Error", "TypeError", "PostgresError", "AggregateError"]);
const SAFE_CODES = new Set([
  "CONNECTION_CLOSED", "ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "EPIPE",
]);

function boundedCode(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const code = value.toUpperCase();
  if (/^[0-9A-Z]{5}$/.test(code)) return code; // SQLSTATE
  if (/^20(?:08|09|10|11|12|13|14|15|16)$/.test(code)) return code;
  return SAFE_CODES.has(code) ? code : undefined;
}

function boundedClass(value: unknown): string | undefined {
  return typeof value === "string" && SAFE_CLASSES.has(value) ? value : undefined;
}

function hyperdriveProviderCode(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  // Hyperdrive-specific runtime errors use SQLSTATE 58000 and retain the
  // provider reason as one of the documented 2008-2016 numeric codes.
  // Extract only that allowlisted number; never expose the message itself.
  const match = value.match(/\b(20(?:08|09|10|11|12|13|14|15|16))\b/);
  return match?.[1];
}

function safeError(err: unknown): SafeErrorReceipt {
  const record = err && typeof err === "object" ? err as Record<string, unknown> : {};
  const cause = record.cause && typeof record.cause === "object"
    ? record.cause as Record<string, unknown> : {};
  // Only protocol/provider codes and a fixed class allowlist are observable.
  // Never expose message, stack, connection URI, host, query or credentials.
  const code = boundedCode(record.code);
  const errorClass = boundedClass(record.name);
  const causeCode = boundedCode(cause.code)
    ?? hyperdriveProviderCode(record.message)
    ?? hyperdriveProviderCode(cause.message);
  const causeClass = boundedClass(cause.name);
  const nested = Array.isArray(record.errors) ? record.errors.slice(0, 4) : [];
  const nestedCodes = [...new Set(nested
    .map(item => item && typeof item === "object"
      ? boundedCode((item as Record<string, unknown>).code) : undefined)
    .filter((value): value is string => Boolean(value)))];
  const nestedClasses = [...new Set(nested
    .map(item => item && typeof item === "object"
      ? boundedClass((item as Record<string, unknown>).name) : undefined)
    .filter((value): value is string => Boolean(value)))];
  return {
    classification: classify(err),
    ...(code ? { code } : {}),
    ...(errorClass ? { error_class: errorClass } : {}),
    ...(causeCode ? { cause_code: causeCode } : {}),
    ...(causeClass ? { cause_class: causeClass } : {}),
    ...(nestedCodes.length ? { nested_codes: nestedCodes } : {}),
    ...(nestedClasses.length ? { nested_classes: nestedClasses } : {}),
  };
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
