/**
 * Non-authoritative wake signalling for the canonical Product action queue.
 *
 * PostgreSQL remains the sole owner of identity, grants, queue ordering,
 * leases and results. This Durable Object never stores a job, permission,
 * device secret or queue state. Lost signalling is repaired by bounded
 * periodic Product claims, not by a second dispatch authority.
 */
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import type { ProductPostgresEnv } from "./product_postgres_store.ts";

const INTERNAL_ORIGIN = "https://ordax-device-wake.internal";
const MAX_DEVICE_WATCHERS = 4;
const MAX_COMPLETION_WAITERS = 128;
const MAX_RECENT_COMPLETIONS = 256;
const COMPLETION_RETENTION_MS = 60_000;
// A single longer advisory wait reduces repeated status SQL for slow actions;
// caller deadlines still cap it and every eventual result is PostgreSQL-verified.
const MAX_COMPLETION_WAIT_MS = 10_000;

export class ProductDeviceWake {
  private readonly ctx: DurableObjectState;
  // Advisory only: never retain results, credentials, grants or queue state.
  // A lost/evicted hint causes a bounded canonical SQL recovery read.
  private readonly recentCompletions = new Map<string, number>();
  private readonly completionWaiters = new Map<string, Set<() => void>>();
  private waiterCount = 0;

  private async waitForCompletion(id: string, timeoutMs: number): Promise<Response> {
    if ((this.recentCompletions.get(id) ?? 0) > Date.now()) {
      return new Response(null, { status: 204 });
    }
    if (this.waiterCount >= MAX_COMPLETION_WAITERS) {
      return new Response(null, { status: 429 });
    }
    const waiters = this.completionWaiters.get(id) ?? new Set<() => void>();
    this.completionWaiters.set(id, waiters);
    this.waiterCount++;
    const notified = await new Promise<boolean>(resolve => {
      const finish = (signalled: boolean) => {
        clearTimeout(timer);
        waiters.delete(wake);
        if (waiters.size === 0) this.completionWaiters.delete(id);
        this.waiterCount--;
        resolve(signalled);
      };
      const wake = () => finish(true);
      const timer = setTimeout(() => finish(false), timeoutMs);
      waiters.add(wake);
    });
    return new Response(null, { status: notified ? 204 : 408 });
  }

  private publishCompletion(id: string): Response {
    const now = Date.now();
    for (const [key, expiry] of this.recentCompletions) {
      if (expiry <= now) this.recentCompletions.delete(key);
    }
    this.recentCompletions.delete(id);
    this.recentCompletions.set(id, now + COMPLETION_RETENTION_MS);
    while (this.recentCompletions.size > MAX_RECENT_COMPLETIONS) {
      const oldest = this.recentCompletions.keys().next().value;
      if (oldest === undefined) break;
      this.recentCompletions.delete(oldest);
    }
    for (const wake of this.completionWaiters.get(id) ?? []) wake();
    return new Response(null, { status: 204 });
  }

  constructor(ctx: DurableObjectState) {
    this.ctx = ctx;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === "/completion" && request.method === "POST") {
      const id = url.searchParams.get("request_id");
      if (!isCanonicalUuid(id)) return new Response(null, { status: 400 });
      return this.publishCompletion(id.toLowerCase());
    }
    if (path === "/completion-wait" && request.method === "GET") {
      const id = url.searchParams.get("request_id");
      const timeoutMs = Number(url.searchParams.get("timeout_ms"));
      if (!isCanonicalUuid(id) || !Number.isInteger(timeoutMs)
          || timeoutMs < 1 || timeoutMs > MAX_COMPLETION_WAIT_MS) {
        return new Response(null, { status: 400 });
      }
      return this.waitForCompletion(id.toLowerCase(), timeoutMs);
    }
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
  return env.DEVICE_WAKE !== undefined && env.PRODUCT_DEVICE_WAKE_ENABLED === "enabled";
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

/** One advisory signal path for committed actions and device-attested session challenges.
 * A Worker may retain the promise with waitUntil; without a request context it is awaited.
 * The signal grants nothing and the Runtime must still authenticate against PostgreSQL.
 */
export async function scheduleProductDeviceWake(
  env: ProductPostgresEnv, deviceId: string,
  scheduleWake?: (wake: Promise<void>) => void,
): Promise<void> {
  const wake = notifyProductDeviceWake(env, deviceId);
  if (scheduleWake) {
    try {
      scheduleWake(wake);
      return;
    } catch {
      // A broken scheduler cannot silently drop the best-effort wake.
    }
  }
  await wake;
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

// Both calls are internal to the existing Worker/DO binding. Only a
// committed report publishes a hint; only an authorized status read may wait.
export async function notifyProductActionCompletion(
  env: ProductPostgresEnv, deviceId: string, requestId: string,
): Promise<void> {
  if (!productWakeBound(env) || !isCanonicalUuid(deviceId) || !isCanonicalUuid(requestId)) return;
  try {
    const ns = env.DEVICE_WAKE!;
    const response = await ns.get(ns.idFromName(deviceId)).fetch(
      INTERNAL_ORIGIN + "/completion?request_id=" + requestId, { method: "POST" });
    if (!response.ok) throw new Error("completion_signal_rejected");
  } catch {
    console.error(JSON.stringify({ event: "product_action_completion_delivery_failed" }));
  }
}

export async function waitProductActionCompletion(
  env: ProductPostgresEnv, deviceId: string, requestId: string, remainingMs: number,
): Promise<"signalled" | "timeout" | "unavailable"> {
  if (!productWakeBound(env) || !isCanonicalUuid(deviceId) || !isCanonicalUuid(requestId)) return "unavailable";
  const timeoutMs = Math.min(MAX_COMPLETION_WAIT_MS, Math.floor(remainingMs));
  if (timeoutMs < 1) return "unavailable";
  try {
    const ns = env.DEVICE_WAKE!;
    const response = await ns.get(ns.idFromName(deviceId)).fetch(
      INTERNAL_ORIGIN + "/completion-wait?request_id=" + requestId + "&timeout_ms=" + timeoutMs,
      { method: "GET" });
    // 408 means recovery is due, not that the action failed. Both paths
    // require a fresh authorized SQL read. Other errors use legacy recovery.
    return response.status === 204 ? "signalled" : response.status === 408 ? "timeout" : "unavailable";
  } catch {
    return "unavailable";
  }
}
