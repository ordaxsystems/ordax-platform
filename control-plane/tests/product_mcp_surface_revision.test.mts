import assert from "node:assert/strict";
import test from "node:test";
import { mcpCatalogRevision } from "../cloudflare/src/mcp_http.ts";

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
