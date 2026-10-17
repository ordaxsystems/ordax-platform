import { Client } from "pg";

type ProbeEnv = {
  POSTGRES: {
    connectionString: string;
  };
};

function classify(error: unknown): string {
  const record = error && typeof error === "object" ? error as Record<string, unknown> : {};
  const message = typeof record.message === "string" ? record.message.toLowerCase() : "";
  if (message.includes("connection terminated unexpectedly")) return "pg_connection_terminated_unexpectedly";
  if (message.includes("connection terminated")) return "pg_connection_terminated";
  if (message.includes("failed to acquire a connection from the pool")) return "hyperdrive_pool_acquire_failed";
  if (message.includes("internal error")) return "hyperdrive_internal_error";
  if (message.includes("server connection attempt failed")) return "hyperdrive_server_connection_failed";
  if (message.includes("failed to connect to the provided database")) return "hyperdrive_database_connect_failed";
  if (message.includes("authentication failed") || message.includes("password authentication failed")) return "authentication_failed";
  if (message.includes("tls")) return "tls_failure";
  if (message.includes("timeout")) return "timeout";
  return "unclassified";
}

function safeCode(error: unknown): string | null {
  const record = error && typeof error === "object" ? error as Record<string, unknown> : {};
  return typeof record.code === "string" && record.code.length <= 32 ? record.code : null;
}

export default {
  async fetch(request: Request, env: ProbeEnv): Promise<Response> {
    if (request.method !== "GET" || new URL(request.url).pathname !== "/") {
      return new Response("Not found", { status: 404 });
    }

    const client = new Client({ connectionString: env.POSTGRES.connectionString });
    let phase: "connect" | "query" = "connect";
    try {
      await client.connect();
      phase = "query";
      const result = await client.query("select 1::int as ok");
      return Response.json({ ok: result.rows?.[0]?.ok === 1, phase: "complete" });
    } catch (error) {
      return Response.json({
        ok: false,
        phase,
        classification: classify(error),
        code: safeCode(error),
      }, { status: 503 });
    } finally {
      await client.end().catch(() => {});
    }
  },
};
