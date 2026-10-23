/**
 * Non-authoritative wake signalling for the canonical Product action queue.
 *
 * PostgreSQL remains the sole owner of identity, grants, queue ordering,
 * leases and results. This Durable Object never stores a job, permission,
 * device secret or queue state. Lost signalling is repaired by bounded
 * periodic Product claims, not by a second dispatch authority.
 */
import type { ProductPostgresEnv } from "./product_postgres_store.ts";

const INTERNAL_ORIGIN = "https://ordax-device-wake.internal";
const MAX_DEVICE_WATCHERS = 4;

export class ProductDeviceWake {
  constructor(private readonly ctx: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (path === "/subscribe" && request.method === "GET"
        && request.headers.get("upgrade")?.toLowerCase() === "websocket") {
      if (this.ctx.getWebSockets().length >= MAX_DEVICE_WATCHERS) {
        return Response.json({ ok: false, error: "device_wake_subscriber_limit" }, { status: 429 });
      }
      const pair = new WebSocketPair();
      this.ctx.acceptWebSocket(pair[1]);
      return new Response(null, { status: 101, webSocket: pair[0] });
    }
    if (path === "/wake" && request.method === "POST") {
      // A wake is never an action, receipt, authorization or guarantee of work.
      // The subscribing Runtime must still claim through the canonical RPC.
      for (const socket of this.ctx.getWebSockets()) {
        try {
          socket.send("wake");
        } catch {
          try { socket.close(1011, "wake_delivery_failed"); } catch { /* already disconnected */ }
        }
      }
      return Response.json({ ok: true }, { headers: { "cache-control": "no-store" } });
    }
    return Response.json({ ok: false, error: "not_found" }, { status: 404 });
  }

  webSocketMessage(socket: WebSocket): void {
    // Runtime has no authority to publish signals. Only the same Worker may
    // notify after PostgreSQL acknowledges an authenticated enqueue.
    try { socket.close(1008, "server_signals_only"); } catch { /* already disconnected */ }
  }

  webSocketClose(): void {
    // Hibernatable sockets are owned and cleaned up by the DO runtime.
  }
}

export function productWakeBound(env: ProductPostgresEnv): boolean {
  return env.DEVICE_WAKE !== undefined;
}

export function subscribeProductDeviceWake(
  env: ProductPostgresEnv, deviceId: string, request: Request,
): Promise<Response> | Response {
  if (!productWakeBound(env)) {
    return Response.json({ ok: false, error: "wake_unavailable" }, { status: 503 });
  }
  if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
    return Response.json({ ok: false, error: "upgrade_required" }, { status: 426 });
  }
  // Device ID is derived from the authenticated SQL credential in the
  // transport gateway, never from a query, path or an MCP tool argument.
  const ns = env.DEVICE_WAKE!;
  const stub = ns.get(ns.idFromName(deviceId));
  return stub.fetch(INTERNAL_ORIGIN + "/subscribe", {
    method: "GET", headers: { Upgrade: "websocket" },
  });
}

export async function notifyProductDeviceWake(
  env: ProductPostgresEnv, deviceId: string,
): Promise<void> {
  if (!productWakeBound(env)) return;
  const ns = env.DEVICE_WAKE!;
  try {
    const result = await ns.get(ns.idFromName(deviceId)).fetch(INTERNAL_ORIGIN + "/wake", {
      method: "POST",
    });
    if (!result.ok) throw new Error("wake_dispatch_rejected");
  } catch {
    // Enqueue was already committed in PostgreSQL. Never convert a lost
    // advisory signal into a second enqueue or report a false SQL failure.
    console.error(JSON.stringify({ event: "product_device_wake_delivery_failed" }));
  }
}
