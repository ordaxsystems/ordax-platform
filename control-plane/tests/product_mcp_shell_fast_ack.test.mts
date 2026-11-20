import assert from "node:assert/strict";
import test from "node:test";

import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";

const DEVICE = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const ACTION_ID = "11111111-1111-4111-8111-111111111111";
const RESPONSE = { ok: true, request_id: ACTION_ID, status: "queued", replayed: false };

const invocation = (name: string, arguments_: Record<string, unknown>) =>
  new Request("https://ordax.example/mcp", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/call",
      params: { name, arguments: arguments_ } }),
  });

const handlers = (getAction: () => Promise<Response>) => ({
  session: async () => Response.json({ ok: true, session: {
    subject_id: "22222222-2222-4222-8222-222222222222",
    client_id: "33333333-3333-4333-8333-333333333333",
  } }),
  targets: async () => { throw new Error("dispatch must not enumerate targets"); },
  createAction: async () => Response.json(RESPONSE, { status: 202 }),
  getAction,
});

test("independent computer and project shells default to durable ACK without a status-poll slot", async () => {
  for (const [name, options] of [
    ["computer_terminal_exec", { device_id: DEVICE, argv: ["cmd", "/c", "echo", "a"] }],
    ["terminal_exec", { device_id: DEVICE, project: "ordaxsystems/ordax-runtime",
      argv: ["cmd", "/c", "echo", "a"] }],
  ] as const) {
    await test(name, async () => {
      let reads = 0;
      const response = await handleOrdaxMcp(invocation(name, options), handlers(async () => {
        reads++;
        throw new Error("implicit shell wait must never poll");
      }));
      assert.equal(response.status, 200);
      const body = await response.json() as any;
      assert.equal(body.result.structuredContent.ok, true);
      assert.equal(body.result.structuredContent.pending, true);
      assert.equal(body.result.structuredContent.request_id, ACTION_ID);
      assert.equal(body.result.structuredContent.action.status, "queued");
      assert.equal(reads, 0, "no second PostgreSQL RPC / status query");
    });
  }
});

test("an explicit shell wait still returns the verified terminal response", async () => {
  let reads = 0;
  const result = await handleOrdaxMcp(invocation("computer_terminal_exec", {
    device_id: DEVICE, argv: ["cmd", "/c", "echo", "a"],
    wait_for_completion_ms: 8000,
  }), handlers(async () => {
    reads++;
    return Response.json({ ok: true, action: {
      request_id: ACTION_ID, device_id: DEVICE, action: "computer.terminal_exec",
      status: "succeeded", result: { ok: true, summary: "completed" },
    } });
  }));
  assert.equal(result.status, 200);
  const payload = (await result.json() as any).result.structuredContent;
  assert.equal(payload.pending, false);
  assert.equal(payload.action.status, "succeeded");
  assert.equal(reads, 1);
});

test("short observational operations preserve their existing completion wait", async () => {
  let reads = 0;
  const response = await handleOrdaxMcp(invocation("computer_screen_info", {
    device_id: DEVICE,
  }), handlers(async () => {
    reads++;
    return Response.json({ ok: true, action: {
      request_id: ACTION_ID, device_id: DEVICE, action: "computer.screen_info",
      status: "succeeded", result: { ok: true, summary: "screen info" },
    } });
  }));
  assert.equal(response.status, 200);
  assert.equal((await response.json() as any).result.structuredContent.pending, false);
  assert.equal(reads, 1);
});

test("invalid explicit wait is denied before any enqueue", async () => {
  for (const bad of [-1, 20001, "0", null, true, 1.5]) {
    let dispatched = 0;
    const response = await handleOrdaxMcp(invocation("computer_terminal_exec", {
      device_id: DEVICE, argv: ["cmd", "/c", "echo", "a"],
      wait_for_completion_ms: bad,
    }), {
      ...handlers(async () => { throw new Error("must not poll"); }),
      createAction: async () => { dispatched++; throw new Error("must not enqueue"); },
    });
    const payload = (await response.json() as any).result.structuredContent;
    assert.equal(payload.error, "wait_for_completion_invalid");
    assert.equal(dispatched, 0);
  }
});
