import assert from "node:assert/strict";
import test from "node:test";
import { createCanonicalProductMcpGateway } from "../cloudflare/src/product_mcp_entry.ts";

const OWNER = "11111111-1111-4111-8111-111111111111";
const CLIENT = "22222222-2222-4222-8222-222222222222";
const SECRET = "offline-mcp-meter-test-key-at-least-thirty-two-characters";
const URL = "https://mcp.example/mcp";

function request(sessionMarker?: string) {
  return new Request(URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 17,
      method: "tools/call",
      params: {
        name: "ordax_targets", arguments: {},
        ...(sessionMarker === undefined ? {} : {
          _meta: { "openai/session": sessionMarker },
        }),
      },
    }),
  });
}

function gateway(recordUsage: (input: {
  ownerUserId: string;
  clientId: string;
  toolName: string;
  requestFingerprint: string;
}) => Promise<void>) {
  const reads = {
    session: async () => Response.json({
      ok: true, session: { subject_id: OWNER, client_id: CLIENT },
    }),
    targets: async () => Response.json({ ok: true, targets: [] }),
    getAction: async () => Response.json({ ok: false }, { status: 404 }),
    usageFingerprintKey: SECRET,
    recordUsage,
  };
  return createCanonicalProductMcpGateway({} as any, reads, fetch, new Set(["ordax_targets"]));
}

function blockedUsage() {
  let release!: () => void;
  let started!: () => void;
  const pending = new Promise<void>(resolve => { release = resolve; });
  const called = new Promise<void>(resolve => { started = resolve; });
  const recorded: Array<{ ownerUserId: string; clientId: string; toolName: string; requestFingerprint: string }> = [];
  return {
    recorded, called, release,
    async write(input: typeof recorded[number]) {
      recorded.push(input);
      started();
      await pending;
    },
  };
}

test("Worker waitUntil owns slow shadow accounting; MCP answer never waits for the usage SQL", async () => {
  const usage = blockedUsage();
  const scheduled: Promise<unknown>[] = [];
  const response = await gateway(input => usage.write(input))(request(), {
    waitUntil(promise) { scheduled.push(promise); },
  });
  assert.equal(response.status, 200);
  const payload = await response.json() as any;
  assert.equal(payload.jsonrpc, "2.0");
  assert.equal(payload.id, 17);
  assert.equal(payload.result.isError, false, "shadow write cannot mark accepted tool as failed");
  assert.equal(scheduled.length, 1, "exactly one request-owned background task");
  await usage.called;
  assert.equal(usage.recorded.length, 1);
  assert.deepEqual({
    ownerUserId: usage.recorded[0].ownerUserId,
    clientId: usage.recorded[0].clientId,
    toolName: usage.recorded[0].toolName,
  }, { ownerUserId: OWNER, clientId: CLIENT, toolName: "ordax_targets" });
  assert.match(usage.recorded[0].requestFingerprint, /^[a-f0-9]{64}$/);
  usage.release();
  await Promise.all(scheduled);
});

test("direct MCP callers without a Worker execution context preserve awaited metering", async () => {
  const usage = blockedUsage();
  let finished = false;
  const inFlight = gateway(input => usage.write(input))(request()).then(response => {
    finished = true;
    return response;
  });
  await usage.called;
  await Promise.resolve();
  assert.equal(finished, false, "without waitUntil, response must retain existing awaited behavior");
  usage.release();
  const response = await inFlight;
  assert.equal(response.status, 200);
  assert.equal(finished, true);
  assert.equal(usage.recorded.length, 1);
});

test("a broken waitUntil owner retains the safe awaited fallback, never silently dropping the write", async () => {
  const usage = blockedUsage();
  let finished = false;
  const inFlight = gateway(input => usage.write(input))(request(), {
    waitUntil() { throw new Error("invalid test execution context"); },
  }).then(response => { finished = true; return response; });
  await usage.called;
  await Promise.resolve();
  assert.equal(finished, false);
  usage.release();
  const response = await inFlight;
  assert.equal(response.status, 200);
  assert.equal(usage.recorded.length, 1);
});

test("shadow-meter dedup distinguishes two ChatGPT sessions sharing a JSON-RPC id and OAuth client", async () => {
  const recorded: Array<{ ownerUserId: string; clientId: string; toolName: string; requestFingerprint: string }> = [];
  const handler = gateway(async input => { recorded.push(input); });
  const scheduled: Promise<unknown>[] = [];
  const context = { waitUntil(promise: Promise<unknown>) { scheduled.push(promise); } };
  for (const marker of [
    "session-one-20261101",
    "session-one-20261101", // transport retry, same original request
    "session-two-20261101", // independent conversation reuses JSON-RPC id 17
  ]) {
    const response = await handler(request(marker), context);
    assert.equal(response.status, 200);
    const output = await response.json() as any;
    assert.equal(output.result.isError, false);
  }
  await Promise.all(scheduled);
  assert.equal(recorded.length, 3);
  assert.ok(recorded.every(row => row.ownerUserId === OWNER && row.clientId === CLIENT));
  assert.ok(recorded.every(row => row.toolName === "ordax_targets"));
  assert.equal(recorded[0].requestFingerprint, recorded[1].requestFingerprint,
    "retry from one session must retain the same dedup key");
  assert.notEqual(recorded[0].requestFingerprint, recorded[2].requestFingerprint,
    "a different conversation must count separately despite the same RPC id and args");
  for (const row of recorded) {
    assert.match(row.requestFingerprint, /^[a-f0-9]{64}$/);
    assert.deepEqual(Object.keys(row).sort(), ["clientId", "ownerUserId", "requestFingerprint", "toolName"],
      "raw ChatGPT markers must not be sent to SQL or stored in usage rows");
    assert.equal(JSON.stringify(row).includes("session-"), false);
  }
});

test("clients without valid ChatGPT session markers preserve stable conservative retry fingerprints", async () => {
  const recorded: string[] = [];
  const handler = gateway(async input => { recorded.push(input.requestFingerprint); });
  const scheduled: Promise<unknown>[] = [];
  const context = { waitUntil(promise: Promise<unknown>) { scheduled.push(promise); } };
  assert.equal((await handler(request(), context)).status, 200);
  assert.equal((await handler(request(), context)).status, 200);
  assert.equal((await handler(request("invalid marker with spaces"), context)).status, 200);
  await Promise.all(scheduled);
  assert.equal(recorded.length, 3);
  assert.equal(recorded[0], recorded[1]);
  assert.equal(recorded[1], recorded[2],
    "unverified/absent markers cannot create an authoritative session identity");
});
