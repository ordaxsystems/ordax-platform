import assert from "node:assert/strict";
import test from "node:test";
import { mcpCatalogRevision, handleOrdaxMcp, ORDAX_MCP_OPERATIONAL_PROTOCOL, ORDAX_MCP_INSTRUCTIONS } from "../cloudflare/src/mcp_http.ts";

test("MCP revision is a deterministic digest of tool schemas and annotations", async () => {
  const catalog = [
    {
      name: "computer_process_start",
      description: "Start device process",
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
      inputSchema: { type: "object", required: ["device_id", "argv"] },
    },
  ];
  const initial = await mcpCatalogRevision(catalog);
  assert.match(initial, /^catalog-v1-[0-9a-f]{64}$/);
  assert.equal(initial, await mcpCatalogRevision(catalog));
  assert.notEqual(initial, await mcpCatalogRevision([
    ...catalog,
    { name: "computer_process_stop", inputSchema: { type: "object" } },
  ]));
  assert.notEqual(initial, await mcpCatalogRevision([
    { ...catalog[0], annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false } },
  ]));
  assert.notEqual(initial, await mcpCatalogRevision([
    { ...catalog[0], inputSchema: { type: "object", required: ["device_id", "argv", "cwd"] } },
  ]));
});


test("operational guidance is one versioned projection, without dispatch", async () => {
  let dispatched = 0;
  const handlers = {
    session: async () => Response.json({ ok: true }),
    targets: async () => { throw new Error("unexpected target lookup"); },
    createAction: async () => { dispatched++; return Response.json({ ok: false }); },
    getAction: async () => { throw new Error("unexpected receipt lookup"); },
  };
  const call = async (method: string, params: Record<string, unknown> = {}) => {
    const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
      method: "POST", headers: { "content-type": "application/json", authorization: "Bearer fixture" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    }), handlers);
    return (await response.json()).result;
  };
  const init = await call("initialize", { protocolVersion: "2025-03-26" });
  assert.equal(init.instructions, ORDAX_MCP_INSTRUCTIONS);
  const session = await call("tools/call", { name: "ordax_session", arguments: {} });
  assert.deepEqual(session.structuredContent.operational_protocol, ORDAX_MCP_OPERATIONAL_PROTOCOL);
  assert.equal(ORDAX_MCP_OPERATIONAL_PROTOCOL.guidance_only, true);
  assert.equal(dispatched, 0);
});
