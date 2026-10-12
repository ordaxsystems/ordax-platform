import assert from "node:assert/strict";
import { test } from "node:test";
import { readBoundedJsonObject } from "../cloudflare/src/request_json.ts";

test("bounded JSON counts UTF-8 bytes, accepts split Unicode, and rejects malformed input", async () => {
  const bytes = new TextEncoder().encode('{"text":"ação"}');
  const stream = new ReadableStream({ start(controller) {
    for (const byte of bytes) controller.enqueue(new Uint8Array([byte]));
    controller.close();
  } });
  assert.deepEqual(await readBoundedJsonObject(new Request("https://test", { method: "POST", body: stream, duplex: "half" } as any), bytes.length), { text: "ação" });
  assert.equal(await readBoundedJsonObject(new Request("https://test", { method: "POST", body: bytes }), bytes.length - 1), null);
  for (const body of ["[]", "null", "{bad", new Uint8Array([0xff])]) {
    assert.equal(await readBoundedJsonObject(new Request("https://test", { method: "POST", body }), 100), null);
  }
});
test("bounded parser cancels an oversized stream before consuming the remainder", async () => {
  let cancelled = false;
  const stream = new ReadableStream({ pull(controller) { controller.enqueue(new Uint8Array(100)); }, cancel() { cancelled = true; } });
  assert.equal(await readBoundedJsonObject(new Request("https://test", { method: "POST", body: stream, duplex: "half" } as any), 20), null);
  assert.equal(cancelled, true);
});

test("bounded reader enforces the actual UTF-8 byte limit even with misleading content-length", async () => {
  const body = '{"description":"' + "á".repeat(6) + '"}';
  const bytes = new TextEncoder().encode(body);
  const request = new Request("https://ordax.example/api", {
    method: "POST",
    headers: { "content-length": "2" },
    body: bytes,
  });
  assert.equal(await readBoundedJsonObject(request, bytes.byteLength - 1), null);
  const valid = new Request("https://ordax.example/api", { method: "POST", body: bytes });
  assert.deepEqual(await readBoundedJsonObject(valid, bytes.byteLength), { description: "á".repeat(6) });
});

test("bounded reader stops infinite chunked requests before consuming a full body", async () => {
  let chunksRead = 0;
  let cancelled = false;
  const body = new ReadableStream({
    pull(controller) {
      chunksRead++;
      controller.enqueue(new Uint8Array(8192));
    },
    cancel() { cancelled = true; },
  });
  assert.equal(await readBoundedJsonObject(
    new Request("https://ordax.example/api", { method: "POST", body, duplex: "half" } as any), 16 * 1024,
  ), null);
  assert.ok(chunksRead >= 3 && chunksRead <= 4, `expected early cancellation, got ${chunksRead} chunks`);
  assert.equal(cancelled, true);
});
