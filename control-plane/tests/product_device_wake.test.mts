import test from "node:test";
import assert from "node:assert/strict";
import {
  ProductDeviceWake,
  notifyProductDeviceWake,
  subscribeProductDeviceWake,
} from "../cloudflare/src/product_device_wake.ts";
import { handleProductDeviceTransport } from "../cloudflare/src/product_device_transport.ts";

const DEVICE = "900943fd-8397-471e-bf05-c66ba4de7884";

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

test("subscriber sends no credentials or untrusted arguments to signalling coordinator", async () => {
  const forwarded: Array<{ id: string; url: string; options: RequestInit }> = [];
  const env = {
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
  const env = { DEVICE_WAKE: {
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
