import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { createCanonicalProductMcpGateway } from "../cloudflare/src/product_mcp_entry.ts";

const ENV = Object.freeze({
  PRODUCT_AUTH_ISSUER: "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1",
  PRODUCT_AUTH_AUDIENCE: "authenticated",
  PRODUCT_AUTH_JWKS_URL: "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1/.well-known/jwks.json",
  POSTGRES: { connectionString: "postgresql://localhost:6543/example" },
});
const MCP_URL = "https://canary.example/mcp";
const request = (name: string, args: Record<string, unknown> = {}) => new Request(MCP_URL, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
});
function fakeHandlers() {
  const calls = { session: 0, targets: 0, getAction: 0 };
  const handlers = {
    session: async () => { calls.session++; return Response.json({ ok: true, session: { subject_id: "server-subject" } }); },
    targets: async () => { calls.targets++; return Response.json({ ok: true, targets: [] }); },
    getAction: async () => { calls.getAction++; return Response.json({ ok: false, error: "not_found" }, { status: 404 }); },
  };
  return { handlers, calls };
}

test("published entry cannot accidentally import legacy D1 Worker or configure D1 binding", async () => {
  const source = await readFile(new URL("../cloudflare/src/product_mcp_entry.ts", import.meta.url), "utf8");
  const config = await readFile(new URL("../cloudflare/wrangler.product-mcp-canary.toml", import.meta.url), "utf8");
  assert.doesNotMatch(source, /env\.DB\b|from ["']\.\/index(?:\.ts)?["']/);
  assert.doesNotMatch(config, /\[\[d1_databases\]\]|\bbinding\s*=\s*["']DB["']/);
  assert.match(config, /main = "src\/product_mcp_entry.ts"/);
  assert.match(config, /binding = "POSTGRES"/);
  assert.match(config, /id = "4b601ec5815f43259bd8040053825d2a"/);
});

test("health reports canonical attested control without model relay", async () => {
  const run = createCanonicalProductMcpGateway(ENV);
  const response = await run(new Request("https://canary.example/health"));
  const status = await response.json();
  assert.equal(response.status, 200);
  assert.equal(status.service, "ordax-platform-mcp");
  assert.deepEqual({
    mode: status.mode,
    topology: status.conversation_topology,
    model_relay: status.model_relay,
    supports_attested_remote_reads: status.supports_attested_remote_reads,
    supports_remote_actions: status.supports_remote_actions,
    supports_project_continuity: status.supports_project_continuity,
    auth: status.auth_configured,
    postgres: status.postgres_configured,
  }, {
    mode: "attested-device-control",
    topology: "user_chatgpt_direct",
    model_relay: false,
    supports_attested_remote_reads: true,
    supports_remote_actions: true,
    supports_project_continuity: true,
    auth: true,
    postgres: true,
  });
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("OAuth protected resource metadata references the actual MCP origin and single issuer", async () => {
  const run = createCanonicalProductMcpGateway(ENV);
  const response = await run(new Request("https://canary.example/.well-known/oauth-protected-resource"));
  const json = await response.json();
  assert.equal(response.status, 200);
  assert.equal(json.resource, "https://canary.example/mcp");
  assert.deepEqual(json.authorization_servers, [ENV.PRODUCT_AUTH_ISSUER]);
  assert.deepEqual(json.bearer_methods_supported, ["header"]);
});

test("owner session route is exposed on canonical MCP gateway and fails closed without bearer", async () => {
  const run = createCanonicalProductMcpGateway(ENV);
  const response = await run(new Request("https://canary.example/v3/product/session"));
  const json = await response.json();
  assert.equal(response.status, 401);
  assert.deepEqual(json, { ok: false, error: "product_auth_required" });
  assert.equal(response.headers.get("cache-control"), "no-store");
});

test("MCP discovery advertises core, computer and only the bounded project continuity tranche", async () => {
  const { handlers, calls } = fakeHandlers();
  const run = createCanonicalProductMcpGateway(ENV, handlers);
  const response = await run(new Request(MCP_URL, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  }));
  const json = await response.json();
  assert.equal(response.status, 200);
  assert.deepEqual(json.result.tools.map((t: any) => t.name), [
    "ordax_session", "ordax_profile", "ordax_targets", "ordax_action_status",
    "computer_windows", "computer_active_window", "computer_screenshot", "computer_screen_info",
    "computer_focus_window", "computer_click", "computer_mouse_move", "computer_drag",
    "computer_launch_app", "computer_scroll", "computer_type", "computer_hotkey",
    "computer_access_status", "computer_processes",
    "project_briefing", "continuity_state", "continuity_update",
  ]);
  const byName = new Map(json.result.tools.map((tool: any) => [tool.name, tool]));
  assert.equal((byName.get("computer_windows") as any).annotations.readOnlyHint, true);
  assert.equal((byName.get("computer_screenshot") as any).annotations.readOnlyHint, true);
  assert.equal((byName.get("computer_click") as any).annotations.readOnlyHint, false);
  assert.equal((byName.get("computer_click") as any).annotations.destructiveHint, true);
  assert.equal((byName.get("computer_focus_window") as any).annotations.destructiveHint, false);
  assert.equal((byName.get("project_briefing") as any).annotations.readOnlyHint, true);
  assert.equal((byName.get("continuity_state") as any).annotations.readOnlyHint, true);
  assert.equal((byName.get("continuity_update") as any).annotations.readOnlyHint, false);
  assert.equal(calls.session, 1);
  assert.equal(calls.targets, 0);
});

test("filesystem, clipboard, process-control, browser and terminal families remain unadvertised", async () => {
  const { handlers, calls } = fakeHandlers();
  const run = createCanonicalProductMcpGateway(ENV, handlers);
  for (const action of [
    "computer_clipboard_read", "computer_clipboard_write", "computer_text_read",
    "computer_terminate_process", "browser_start", "terminal_exec", "project_text_write",
    "workspace_directory_list", "projects_list", "repository_catalog", "handoff_create",
  ]) {
    const response = await run(request(action, { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }));
    assert.equal(response.status, 200);
    const json = await response.json();
    assert.equal(json.error.code, -32601);
    assert.equal(calls.targets, 0);
    assert.equal(calls.getAction, 0);
  }
});

test("attested computer and continuity tools fail closed without a verified session binding", async () => {
  const { handlers } = fakeHandlers();
  const run = createCanonicalProductMcpGateway(ENV, handlers);
  for (const [tool, args] of [
    ["computer_windows", { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }],
    ["computer_click", { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", x: 10, y: 20 }],
    ["project_briefing", { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", project: "ordaxsystems/ordax-gpt" }],
    ["continuity_state", { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", project: "ordaxsystems/ordax-gpt" }],
    ["continuity_update", { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", project: "ordaxsystems/ordax-gpt", summary: "checkpoint" }],
  ] as const) {
    const response = await run(request(tool, args));
    assert.equal(response.status, 200);
    const json = await response.json();
    assert.equal(json.result.isError, true);
    assert.equal(json.result.structuredContent.error, "trusted_operation_required");
  }
});

test("reading authorized targets requires the same session but never invents devices", async () => {
  const { handlers, calls } = fakeHandlers();
  const run = createCanonicalProductMcpGateway(ENV, handlers);
  const response = await run(request("ordax_targets"));
  const json = await response.json();
  assert.deepEqual(json.result.structuredContent, { ok: true, targets: [] });
  assert.equal(calls.session, 1);
  assert.equal(calls.targets, 1);
});

test("unconfigured and unauthenticated clients fail closed, no legacy routes exposed", async () => {
  const gateway = createCanonicalProductMcpGateway({});
  const response = await gateway(request("ordax_targets"));
  assert.equal(response.status, 503);
  const metadata = await gateway(new Request("https://canary.example/.well-known/oauth-protected-resource"));
  assert.equal(metadata.status, 503);
  for (const [method, path] of [
    ["POST", "/v3/product/actions"], ["GET", "/v3/product/targets"],
    ["GET", "/v3/device/ws"], ["POST", "/v3/jobs"], ["POST", "/v3/devices"],
  ]) {
    const answer = await gateway(new Request("https://canary.example" + path, { method }));
    assert.equal(answer.status, 404, path);
  }
});

test("session reports the bounded direct Web tool count", async () => {
  const { handlers } = fakeHandlers();
  const gateway = createCanonicalProductMcpGateway(ENV, handlers);
  const response = await gateway(request("ordax_session"));
  const json = await response.json();
  assert.equal(response.status, 200);
  assert.equal(json.result.structuredContent.ok, true);
  assert.equal(json.result.structuredContent.authenticated, true);
  assert.equal(json.result.structuredContent.mcp_tool_count, 21);
  assert.match(json.result.structuredContent.mcp_tool_surface_revision, /^2026-10-/);
});

test("MCP initialize identifies the official OrdaX Platform and never an obsolete Studio or Control Plane service", async () => {
  const { handlers } = fakeHandlers();
  const gateway = createCanonicalProductMcpGateway(ENV, handlers);
  const response = await gateway(new Request(MCP_URL, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
  }));
  const json = await response.json();
  assert.equal(json.result.serverInfo.name, "OrdaX Platform");
  assert.equal(json.result.serverInfo.version, "0.5.0");
  assert.match(json.result.instructions, /OrdaX Platform MCP/);
  assert.doesNotMatch(json.result.instructions, /Use ORDAX Studio only/);
});
