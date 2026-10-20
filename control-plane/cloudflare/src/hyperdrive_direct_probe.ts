/** Diagnostic Worker, never a Product MCP authority. No D1/OAuth/owner state.
 * Uses the Hyperdrive binding of ONE ephemeral configuration and SELECT 1.
 */
import { Client } from "pg";

type Env = { POSTGRES: { connectionString: string } };

function safeError(error: unknown): string {
  const msg = error instanceof Error ? error.message.toLowerCase() : "";
  if (msg.includes("connection terminated unexpectedly")) return "connection_terminated";
  if (msg.includes("authentication") || msg.includes("password")) return "authentication_failed";
  if (msg.includes("tls") || msg.includes("certificate")) return "tls_failure";
  if (msg.includes("timeout")) return "timeout";
  if (msg.includes("network") || msg.includes("connection")) return "connection_failed";
  return "unclassified";
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== "GET" || new URL(request.url).pathname !== "/") {
      return new Response("Not found", { status: 404 });
    }
    const client = new Client({ connectionString: env.POSTGRES.connectionString });
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
