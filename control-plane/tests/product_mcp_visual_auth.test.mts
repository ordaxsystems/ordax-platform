import assert from "node:assert/strict";
import test from "node:test";
import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";

const png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/l9sAAAAASUVORK5CYII=";
function fixture({ status = "succeeded", resultOk = true, name = "computer.screenshot", data = { mime_type: "image/png", base64: png }, sessionStatus = 200, actionStatus = 200 } = {}) {
  let created = 0;
  const handlers = {
    session: async () => Response.json({ ok: sessionStatus === 200 }, { status: sessionStatus }),
    targets: async () => Response.json({ targets: [] }),
    createAction: async () => { created++; return Response.json({ request_id: "request-1" }); },
    getAction: async () => Response.json({ ok: true, action: { request_id: "request-1", action: name, status, result: { ok: resultOk, data } } }, { status: actionStatus }),
  };
  const call = async (tool = "ordax_action_status", method = "tools/call") => {
    const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", { method: "POST", body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: { name: tool, arguments: { request_id: "request-1", device_id: "device-1", wait_for_completion_ms: 0 } } }) }), handlers);
    return { status: response.status, body: await response.json(), headers: response.headers };
  };
  return { call, created: () => created };
}
for (const name of ["computer.screenshot", "browser.screenshot", "artifact.preview"]) {
  test(`${name} emits actual pixels exactly once without base64 in text/structured metadata`, async () => {
    const f = fixture({ name }); const { body } = await f.call();
    assert.equal(body.result.isError, false);
    assert.deepEqual(body.result.content[1], { type: "image", mimeType: "image/png", data: png });
    assert.equal(body.result.content[0].text.includes(png), false);
    assert.equal(JSON.stringify(body.result.structuredContent).includes(png), false);
    assert.equal(body.result.structuredContent.request_id, "request-1");
    assert.equal(f.created(), 0);
  });
}
test("immediate screenshot and later status both use the same image result contract", async () => {
  const f = fixture(); const { body } = await f.call("computer_screenshot");
  assert.equal(f.created(), 1); assert.equal(body.result.content[1].data, png);
});
for (const status of ["failed", "cancelled"]) test(`status ${status} is an error and never emits pixels`, async () => {
  const { body } = await fixture({ status }).call();
  assert.equal(body.result.isError, true); assert.equal(body.result.content.length, 1);
});
test("a succeeded transport with an unsuccessful Runtime result is still an error", async () => {
  const { body } = await fixture({ resultOk: false }).call(); assert.equal(body.result.isError, true);
});
test("queued image results remain pending and never claim completion or emit pixels", async () => {
  const { body } = await fixture({ status: "running" }).call();
  assert.equal(body.result.isError, false); assert.equal(body.result.structuredContent.pending, true); assert.equal(body.result.content.length, 1);
});
test("local paths, URLs, invalid rasters and excessive data never trigger image fetches", async () => {
  for (const data of [{ image_path: "C:/private/screen.png" }, { url: "http://127.0.0.1/private" }, { mime_type: "image/svg+xml", base64: btoa("<svg/>") }, { mime_type: "image/png", base64: "AA==" }, { mime_type: "image/png", base64: "A".repeat(3 * 1024 * 1024) }]) {
    const { body } = await fixture({ data }).call(); assert.equal(body.result.content.length, 1);
  }
});
test("a known unauthenticated tool signals native OAuth linking without executing any action", async () => {
  const f = fixture({ sessionStatus: 401 }); const { body, status } = await f.call("computer_screenshot");
  assert.equal(status, 200); assert.equal(body.result.isError, true); assert.equal(f.created(), 0);
  assert.match(body.result._meta["mcp/www_authenticate"][0], /resource_metadata=.*error="invalid_token".*error_description=/);
  const init = await f.call("", "initialize"); assert.equal(init.status, 401); assert.ok(init.headers.get("www-authenticate"));
});
test("expired credentials during result observation request reconnect without repeating the action", async () => {
  const f = fixture({ actionStatus: 401 }); const { body } = await f.call("computer_screenshot");
  assert.equal(f.created(), 1); assert.ok(body.result._meta["mcp/www_authenticate"]);
  assert.equal(body.result.structuredContent.request_id, "request-1");
  assert.equal(body.result.structuredContent.pending, true);
});
test("service failure is not misrepresented as a login challenge", async () => {
  const { status, headers } = await fixture({ sessionStatus: 503 }).call("", "initialize");
  assert.equal(status, 503); assert.equal(headers.get("www-authenticate"), null);
});
