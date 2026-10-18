import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { createCanonicalProductMcpGateway, resolveOrBootstrapAttestedSession } from "../cloudflare/src/product_mcp_entry.ts";

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

test("OrdaX OS presence uses the canonical MCP PostgreSQL ingress without granting actions", async () => {
  const { isProductTrustedClientPath } = await import("../cloudflare/src/product_mcp_entry.ts");
  const path = "/v3/product/device/presence";
  assert.equal(isProductTrustedClientPath(path), true);
  const run = createCanonicalProductMcpGateway(ENV);
  const origin = "https://ordax-mcp.ordaxsystems.workers.dev";
  const response = await run(new Request(origin + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      online: true, runtime_kind: "ordax-os",
      agent_version: "ordax-os", capability_digest: null,
    }),
  }));
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { ok: false, error: "product_device_unauthorized" });

  // Public MCP discovery is not expanded by the device-only route.
  const { handlers } = fakeHandlers();
  const tools = await createCanonicalProductMcpGateway(ENV, handlers)(
    new Request("https://mcp.ordax.com.br/mcp", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    }),
  );
  const list = await tools.json() as any;
  assert.equal(list.result.tools.some((tool: any) => tool.name.includes("presence")), false);
});

test("health reports canonical attested device control without model relay", async () => {
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
    auth: status.auth_configured,
    postgres: status.postgres_configured,
  }, {
    mode: "attested-device-control",
    topology: "user_chatgpt_direct",
    model_relay: false,
    supports_attested_remote_reads: true,
    supports_remote_actions: true,
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

test("MCP discovery advertises core, computer control and promoted safe computer reads", async () => {
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
    "computer_clipboard_read", "computer_focus_window", "computer_click", "computer_mouse_move",
    "computer_drag", "computer_launch_app", "computer_scroll", "computer_type", "computer_hotkey",
    "computer_access_status", "computer_file_stat", "computer_directory_list", "computer_text_read",
    "computer_search", "computer_processes", "computer_text_write", "computer_text_patch",
  ]);
  const byName = new Map(json.result.tools.map((tool: any) => [tool.name, tool]));
  assert.equal((byName.get("computer_windows") as any).annotations.readOnlyHint, true);
  assert.equal((byName.get("computer_screenshot") as any).annotations.readOnlyHint, true);
  assert.equal((byName.get("computer_clipboard_read") as any).annotations.readOnlyHint, true);
  assert.equal((byName.get("computer_text_read") as any).annotations.readOnlyHint, true);
  assert.equal((byName.get("computer_click") as any).annotations.readOnlyHint, false);
  assert.equal((byName.get("computer_text_write") as any).annotations.destructiveHint, true);
  assert.equal((byName.get("computer_text_patch") as any).annotations.destructiveHint, true);
  assert.equal((byName.get("computer_click") as any).annotations.destructiveHint, true);
  assert.equal((byName.get("computer_focus_window") as any).annotations.destructiveHint, false);
  assert.equal(calls.session, 1);
  assert.equal(calls.targets, 0);
});

test("unrelated mutations, process control, browser, terminal and project tools remain unpublished", async () => {
  const { handlers, calls } = fakeHandlers();
  const run = createCanonicalProductMcpGateway(ENV, handlers);
  for (const action of [
    "computer_clipboard_write", "computer_path_remove",
    "computer_terminate_process", "browser_start", "terminal_exec", "project_text_write",
    "workspace_directory_list",
  ]) {
    const response = await run(request(action, { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }));
    assert.equal(response.status, 200);
    const json = await response.json();
    assert.equal(json.error.code, -32601);
    assert.equal(calls.targets, 0);
    assert.equal(calls.getAction, 0);
  }
});

test("attested device tools fail closed without a verified session binding", async () => {
  const { handlers } = fakeHandlers();
  const run = createCanonicalProductMcpGateway(ENV, handlers);
  for (const [tool, args] of [
    ["computer_windows", { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }],
    ["computer_click", { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", x: 10, y: 20 }],
    ["computer_text_read", { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", path: "C:\\work\\x.txt" }],
    ["computer_text_write", { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", path: "/allowed/demo.txt", content: "a", create: true }],
    ["computer_text_patch", { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", path: "/allowed/demo.txt", expected_sha256: "a".repeat(64), replacements: [{ old: "a", new: "b" }] }],
    ["computer_clipboard_read", { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }],
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

test("session reports the expanded canonical computer tool count", async () => {
  const { handlers } = fakeHandlers();
  const gateway = createCanonicalProductMcpGateway(ENV, handlers);
  const response = await gateway(request("ordax_session"));
  const json = await response.json();
  assert.equal(response.status, 200);
  assert.equal(json.result.structuredContent.ok, true);
  assert.equal(json.result.structuredContent.authenticated, true);
  assert.equal(json.result.structuredContent.mcp_tool_count, 25);
  assert.equal(json.result.structuredContent.mcp_tool_surface_revision, "2026-10-17.1");
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

test("attested session recovery auto-opens once and waits only for Runtime proof", async () => {
  let checks = 0, opens = 0, waits = 0;
  const resolved = await resolveOrBootstrapAttestedSession(request("computer_access_status"), ENV, {
    resolve: async () => {
      checks++;
      return checks < 3 ? { ok: false, error: "central_session_unbound" }
        : { ok: true, ownerUserId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            clientId: "product-client-123", deviceId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" };
    },
    open: async () => { opens++; return Response.json({ ok: true, status: "pending" }, { status: 202 }); },
    wait: async (milliseconds) => { assert.equal(milliseconds, 1500); waits++; },
  });
  assert.equal(resolved.ok, true);
  assert.equal(checks, 3);
  assert.equal(opens, 1);
  assert.equal(waits, 2);
});

test("attested recovery never retries revoked, missing-marker or rejected challenges", async () => {
  for (const error of ["central_session_marker_required", "central_session_revoked", "central_session_invalid"]) {
    let opens = 0;
    const result = await resolveOrBootstrapAttestedSession(request("computer_access_status"), ENV, {
      resolve: async () => ({ ok: false, error }),
      open: async () => { opens++; return Response.json({ ok: true }); },
      wait: async () => { throw new Error("must_not_wait"); },
    });
    assert.equal(result.ok, false);
    assert.equal(result.error, error);
    assert.equal(opens, 0);
  }
  let retries = 0;
  const denied = await resolveOrBootstrapAttestedSession(request("computer_access_status"), ENV, {
    resolve: async () => { retries++; return { ok: false, error: "central_session_unbound" }; },
    open: async () => Response.json({ ok: false, error: "central_device_target_missing" }, { status: 403 }),
    wait: async () => { throw new Error("must_not_wait"); },
  });
  assert.equal(denied.ok, false);
  assert.equal(denied.error, "central_session_unbound");
  assert.equal(retries, 1);
});

test("pending device challenge does not enqueue any action or expand grants", async () => {
  const { handlers, calls } = fakeHandlers();
  let checks = 0, opens = 0, waits = 0;
  const gateway = createCanonicalProductMcpGateway(ENV, handlers, fetch,
    new Set(["computer_access_status"]), {
      resolve: async () => { checks++; return { ok: false, error: "central_session_unbound" }; },
      open: async () => { opens++; return Response.json({ ok: true, status: "pending" }, { status: 202 }); },
      wait: async () => { waits++; },
    });
  const response = await gateway(request("computer_access_status",
    { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }));
  assert.equal(response.status, 200);
  const body = await response.json() as any;
  assert.equal(body.result.isError, true);
  assert.equal(body.result.structuredContent.error, "central_session_pending");
  assert.equal(opens, 1);
  assert.equal(checks, 5);
  assert.equal(waits, 4);
  assert.equal(calls.targets, 0);
  assert.equal(calls.getAction, 0);
});
