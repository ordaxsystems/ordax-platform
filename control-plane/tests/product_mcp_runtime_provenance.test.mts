import assert from "node:assert/strict";
import test from "node:test";
import { createCanonicalProductMcpReadHandlers } from "../cloudflare/src/product_mcp_reads.ts";
import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";
import {
  env, requestId, device, token, withIssuer, request, actionRecord,
} from "./product_mcp_test_fixtures.mts";

async function callStatus(action: Record<string, unknown>) {
  const handlers = createCanonicalProductMcpReadHandlers(env, {
    getAction: async () => action,
  });
  return handleOrdaxMcp(new Request("https://ordax.example/mcp", {
    method: "POST",
    headers: {
      authorization: "Bearer " + await token(),
      "content-type": "application/json",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "ordax_action_status", arguments: { request_id: requestId } },
    }),
  }), handlers);
}

test("ordax_action_status publishes persisted action-time Runtime provenance", async () => {
  await withIssuer(async () => {
    const response = await callStatus(actionRecord({
      status: "succeeded",
      execution_runtime_kind: "desktop-agent",
      execution_agent_version: "0.3.0",
      result: { ok: true, summary: "done", data: {} },
      finished_at: "2026-10-16T08:00:00Z",
    }));
    assert.equal(response.status, 200);
    const rpc = await response.json();
    const data = rpc.result.structuredContent;
    assert.equal(data.request_id, requestId);
    assert.equal(data.action.device_id, device);
    assert.equal(data.action.runtime_kind, "desktop-agent");
    assert.equal(data.action.runtime_version, "0.3.0");
    assert.equal(data.action.status, "succeeded");
  });
});

test("historical action without persisted Runtime provenance remains explicitly unknown", async () => {
  await withIssuer(async () => {
    const response = await callStatus(actionRecord({
      execution_runtime_kind: null,
      execution_agent_version: null,
    }));
    assert.equal(response.status, 200);
    const rpc = await response.json();
    const data = rpc.result.structuredContent;
    assert.equal(data.action.runtime_kind, null);
    assert.equal(data.action.runtime_version, null);
  });
});

test("half or malformed Runtime provenance fails closed without leaking internal errors", async () => {
  await withIssuer(async () => {
    for (const action of [
      actionRecord({ execution_runtime_kind: "desktop-agent", execution_agent_version: null }),
      actionRecord({ execution_runtime_kind: null, execution_agent_version: "0.3.0" }),
      actionRecord({ execution_runtime_kind: "desktop", execution_agent_version: "0.3.0" }),
      actionRecord({ execution_runtime_kind: "desktop-agent", execution_agent_version: " 0.3.0" }),
      actionRecord({ execution_runtime_kind: "desktop-agent", execution_agent_version: "0.3.0\nprivate" }),
    ]) {
      const handlers = createCanonicalProductMcpReadHandlers(env, {
        getAction: async () => action,
      });
      const internal = await handlers.getAction(request(await token()), requestId);
      assert.equal(internal.status, 502);
      assert.deepEqual(await internal.json(), {
        ok: false,
        error: "product_postgres_invalid_response",
      });

      const response = await callStatus(action);
      assert.equal(response.status, 200);
      const rpc = await response.json();
      assert.equal(rpc.result.isError, true);
      assert.equal(rpc.result.structuredContent.error, "action_status_unavailable");
      assert.equal(JSON.stringify(rpc).includes("product_postgres_invalid_response"), false);
      assert.equal(JSON.stringify(rpc).includes("private"), false);
    }
  });
});
