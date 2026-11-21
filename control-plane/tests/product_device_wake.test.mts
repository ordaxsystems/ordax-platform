import test from "node:test";
import assert from "node:assert/strict";
import {
  ProductDeviceWake,
  notifyProductDeviceWake,
  waitProductActionCompletion,
  scheduleProductDeviceWake,
  subscribeProductDeviceWake,
} from "../cloudflare/src/product_device_wake.ts";
import { handleProductDeviceTransport } from "../cloudflare/src/product_device_transport.ts";

const DEVICE = "900943fd-8397-471e-bf05-c66ba4de7884";

test("canonical wake scheduler is advisory and falls back when a request context fails", async () => {
  const sent: string[] = [], tasks: Promise<void>[] = [];
  let resolve!: () => void;
  const pending = new Promise<void>(done => { resolve = done; });
  const env = { PRODUCT_DEVICE_WAKE_ENABLED: "enabled", DEVICE_WAKE: {
    idFromName: (id: string) => { assert.equal(id, DEVICE); return id; },
    get: () => ({ fetch: async () => { await pending; sent.push("signal"); return Response.json({ok:true}); } }),
  } } as any;
  const quick = scheduleProductDeviceWake(env, DEVICE, task => { tasks.push(task); });
  await quick;
  assert.equal(sent.length, 0, "request response must not await queued DO");
  assert.equal(tasks.length, 1);
  resolve();
  await Promise.all(tasks);
  assert.deepEqual(sent, ["signal"]);
  let awaited = false;
  await scheduleProductDeviceWake(env, DEVICE, () => { throw Error("context unavailable"); });
  awaited = true;
  assert.equal(awaited, true);
  assert.deepEqual(sent, ["signal", "signal"]);
});

test("unauthenticated wake subscribers cannot reach the signalling namespace", async () => {
  let called = false;
  const env = { DEVICE_WAKE: {
    idFromName: () => { called = true; throw new Error("must not be called"); },
  } } as any;
  const withoutCredentials = await handleProductDeviceTransport(new Request(
    "https://mcp.example/v3/device/transport/wake",
    { headers: { Upgrade: "websocket" } },
  ), env);
  assert.equal(withoutCredentials.status, 401);
  assert.equal(called, false);

  const posted = await handleProductDeviceTransport(new Request(
    "https://mcp.example/v3/device/transport/wake", { method: "POST" },
  ), env);
  assert.equal(posted.status, 405);
  assert.equal(called, false);
});

test("no signalling binding is a safe opt-out with no alternate execution backend", async () => {
  await notifyProductDeviceWake({} as any, DEVICE);
  const subscribed = await subscribeProductDeviceWake({} as any, DEVICE, new Request(
    "https://mcp.example/v3/device/transport/wake", { headers: { Upgrade: "websocket" } },
  ));
  assert.equal(subscribed.status, 503);
});

test("signalling stays disabled on bound Worker until explicit rollout", async () => {
  let touched = false;
  const env = { DEVICE_WAKE: { idFromName: () => { touched = true; return "unused"; } } } as any;
  await notifyProductDeviceWake(env, DEVICE);
  const rejected = await subscribeProductDeviceWake(env, DEVICE, new Request(
    "https://mcp.example/v3/device/transport/wake", { headers: { Upgrade: "websocket" } },
  ));
  assert.equal(rejected.status, 503);
  assert.equal(touched, false);
});

test("subscriber sends no credentials or untrusted arguments to signalling coordinator", async () => {
  const forwarded: Array<{ id: string; url: string; options: RequestInit }> = [];
  const env = {
    PRODUCT_DEVICE_WAKE_ENABLED: "enabled",
    DEVICE_WAKE: {
      idFromName(name: string) { assert.equal(name, DEVICE); return "internal-id"; },
      get(id: string) {
        return { fetch(url: string, options: RequestInit) {
          forwarded.push({ id, url, options });
          return Promise.resolve(new Response(null, { status: 204 }));
        } };
      },
    },
  } as any;
  const source = new Request("https://mcp.example/v3/device/transport/wake?grant=spoof", {
    headers: { Upgrade: "websocket", authorization: "Bearer secret", "x-ordax-device-token": "private" },
  });
  const response = await subscribeProductDeviceWake(env, DEVICE, source);
  assert.equal(response.status, 204);
  assert.equal(forwarded.length, 1);
  assert.equal(forwarded[0].id, "internal-id");
  assert.equal(forwarded[0].url, "https://ordax-device-wake.internal/subscribe");
  assert.deepEqual([...new Headers(forwarded[0].options.headers).entries()],
    [["upgrade", "websocket"]]);
});

test("wake notification is only a best-effort internal signal with no payload", async () => {
  const requests: Array<{ method: string; url: string }> = [];
  const env = { PRODUCT_DEVICE_WAKE_ENABLED: "enabled", DEVICE_WAKE: {
    idFromName(name: string) { assert.equal(name, DEVICE); return "internal-id"; },
    get(id: string) {
      assert.equal(id, "internal-id");
      return { fetch: async (url: string, options: RequestInit) => {
        requests.push({ url, method: String(options.method) });
        return new Response(null, { status: 204 });
      } };
    },
  } } as any;
  await notifyProductDeviceWake(env, DEVICE);
  assert.deepEqual(requests, [
    { url: "https://ordax-device-wake.internal/wake", method: "POST" },
  ]);
});

test("DO publishes only wake string, has no persistent action queue or SQL", async () => {
  const received: string[] = [];
  const sockets = [{ send(message: string) { received.push(message); } }];
  const ctx = { getWebSockets: () => sockets } as any;
  const object = new ProductDeviceWake(ctx);
  const accepted = await object.fetch(new Request("https://ordax-device-wake.internal/wake", {
    method: "POST", body: JSON.stringify({ capability: "computer.terminal_exec", grant: "spoof" }),
  }));
  assert.equal(accepted.status, 200);
  assert.deepEqual(received, ["wake"]);
  const rejected = await object.fetch(new Request("https://ordax-device-wake.internal/grants", {
    method: "POST",
  }));
  assert.equal(rejected.status, 404);
});

test("completion wakes multiple waiters for only the committed request and handles delivery races", async () => {
  const object = new ProductDeviceWake({} as any);
  const base = "https://ordax-device-wake.internal";
  const first = "900943fd-8397-471e-bf05-c66ba4de7884";
  const second = "900943fd-8397-471e-bf05-c66ba4de7885";
  const wait = (id: string, ms: number) => object.fetch(new Request(
    base + "/completion-wait?request_id=" + id + "&timeout_ms=" + ms));
  const signal = (id: string) => object.fetch(new Request(
    base + "/completion?request_id=" + id, { method: "POST" }));
  const a = wait(first, 1000), b = wait(first, 1000), c = wait(second, 20);
  assert.equal((await signal(first)).status, 204);
  assert.equal((await a).status, 204);
  assert.equal((await b).status, 204);
  assert.equal((await c).status, 408);
  assert.equal((await wait(first, 1000)).status, 204);
  assert.equal((await wait("invalid", 1000)).status, 400);
});

test("lost completion hints time out for canonical recovery, never produce a receipt", async () => {
  const object = new ProductDeviceWake({} as any);
  const response = await object.fetch(new Request(
    "https://ordax-device-wake.internal/completion-wait?request_id=" + DEVICE + "&timeout_ms=10"));
  assert.equal(response.status, 408);
  assert.equal(await response.text(), "");
});

test("completion hints wait up to 10s, never beyond the caller deadline or DO contract", async () => {
  const requests: string[] = [];
  const env = { PRODUCT_DEVICE_WAKE_ENABLED: "enabled", DEVICE_WAKE: {
    idFromName: (name: string) => { assert.equal(name, DEVICE); return "internal-id"; },
    get: (id: string) => {
      assert.equal(id, "internal-id");
      return { fetch: async (url: string, options: RequestInit) => {
        assert.equal(options.method, "GET");
        requests.push(url);
        return new Response(null, { status: 408 });
      } };
    },
  } } as any;
  for (const [budget, expected] of [[20_000, 10_000], [8000, 8000], [250, 250]] as const) {
    assert.equal(await waitProductActionCompletion(env, DEVICE, DEVICE, budget), "timeout");
    const last = new URL(requests.at(-1)!);
    assert.equal(last.pathname, "/completion-wait");
    assert.equal(last.searchParams.get("request_id"), DEVICE);
    assert.equal(Number(last.searchParams.get("timeout_ms")), expected);
  }
  assert.equal(await waitProductActionCompletion(env, DEVICE, DEVICE, 0), "unavailable");
  assert.equal(requests.length, 3, "zero wait must not call DO");
});

test("DO accepts a 10-second advisory waiter and rejects any larger duration", async () => {
  const object = new ProductDeviceWake({} as any);
  const root = "https://ordax-device-wake.internal";
  const waiting = object.fetch(new Request(root + "/completion-wait?request_id="
    + DEVICE + "&timeout_ms=10000"));
  const posted = await object.fetch(new Request(root + "/completion?request_id="
    + DEVICE, { method: "POST" }));
  assert.equal(posted.status, 204);
  assert.equal((await waiting).status, 204,
    "longer wait must still resolve immediately on the actual completion signal");
  const rejected = await object.fetch(new Request(root + "/completion-wait?request_id="
    + DEVICE + "&timeout_ms=10001"));
  assert.equal(rejected.status, 400);
});
