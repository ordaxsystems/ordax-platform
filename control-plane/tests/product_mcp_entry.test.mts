import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { createCanonicalProductMcpGateway, resolveOrBootstrapAttestedSession, PRODUCT_MCP_DIRECT_TOOLS } from "../cloudflare/src/product_mcp_entry.ts";
import { MAX_MCP_REQUEST_BYTES } from "../cloudflare/src/mcp_http.ts";

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
  assert.match(config, /name = "ordax-mcp-validation-candidate"/);
  assert.match(config, /workers_dev\s*=\s*false/);
  assert.doesNotMatch(config, /ordax-control-plane-v3-canary/);
  assert.match(config, /main = "src\/product_mcp_entry.ts"/);
  assert.match(config, /binding = "POSTGRES"/);
  assert.match(config, /id = "4b601ec5815f43259bd8040053825d2a"/);
});

test("MCP pre-routing caps streamed tool bodies before attestation or dispatch", async () => {
  assert.equal(MAX_MCP_REQUEST_BYTES, 1024 * 1024);
  const { handlers, calls } = fakeHandlers();
  let attestationReads = 0;
  const gateway = createCanonicalProductMcpGateway(ENV, handlers, fetch,
    new Set(["computer_access_status"]), {
      resolve: async () => {
        attestationReads++;
        throw new Error("oversized body must never enter attestation");
      },
    });

  // A 4 MiB source: unbounded Request.json() would exhaust all 64 chunks.
  let pulls = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls++;
      if (pulls > 64) {
        controller.close();
        return;
      }
      controller.enqueue(new Uint8Array(64 * 1024).fill(0x20));
    },
  });
  const oversized = new Request(MCP_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: stream,
    duplex: "half",
  } as RequestInit & { duplex: "half" });
  const response = await gateway(oversized);
  const json = await response.json() as any;
  assert.equal(json.error.code, -32700);
  assert.ok(pulls < 40, `pre-routing overconsumed stream: ${pulls}`);
  assert.equal(attestationReads, 0);
  assert.equal(calls.session, 1);
  assert.equal(calls.targets, 0);
  assert.equal(calls.getAction, 0);
});

test("invalid RPC envelopes cannot trigger pre-routing attested session recovery", async () => {
  const { handlers, calls } = fakeHandlers();
  let resolutions = 0;
  let opens = 0;
  const gateway = createCanonicalProductMcpGateway(ENV, handlers, fetch,
    new Set(["computer_access_status"]), {
      resolve: async () => {
        resolutions++;
        throw new Error("invalid RPC must not resolve an attested device");
      },
      open: async () => {
        opens++;
        throw new Error("invalid RPC must not open an Owner challenge");
      },
    });
  const params = { name: "computer_access_status",
    arguments: { device_id: "22222222-2222-4222-8222-222222222222" } };
  const cases: Array<{ envelope: Record<string, unknown>; code: number }> = [
    { envelope: { jsonrpc: "2.0", method: "tools/call", params }, code: -32600 },
    { envelope: { jsonrpc: "2.0", id: null, method: "tools/call", params }, code: -32600 },
    { envelope: { jsonrpc: "2.0", id: false, method: "tools/call", params }, code: -32600 },
    { envelope: { jsonrpc: "2.0", id: [], method: "tools/call", params }, code: -32600 },
    { envelope: { jsonrpc: "2.0", id: 1.5, method: "tools/call", params }, code: -32600 },
    { envelope: { jsonrpc: "2.0", id: 7, method: "tools/call",
      params: { ...params, arguments: null } }, code: -32602 },
    { envelope: { jsonrpc: "2.0", id: 8, method: "tools/call",
      params: { ...params, arguments: [] } }, code: -32602 },
    { envelope: { jsonrpc: "2.0", id: 9, method: "tools/call",
      params: { ...params, arguments: "bad" } }, code: -32602 },
  ];
  for (const { envelope, code } of cases) {
    const response = await gateway(new Request(MCP_URL, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(envelope),
    }));
    const payload = await response.json() as any;
    assert.equal(payload.error.code, code, JSON.stringify(envelope));
  }
  assert.equal(resolutions, 0, "rejected RPC input must not enter session recovery");
  assert.equal(opens, 0, "rejected RPC input must not open an Owner challenge");
  assert.equal(calls.session, cases.length, "OAuth preflight still applies to every request");
  assert.equal(calls.targets, 0);
  assert.equal(calls.getAction, 0);
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

test("Windows Owner project-scope read is admitted on trusted Worker ingress without bypassing OAuth", async () => {
  const { isProductTrustedClientPath } = await import("../cloudflare/src/product_mcp_entry.ts");
  const path = "/v3/owner/project-scope";
  assert.equal(isProductTrustedClientPath(path), true);
  assert.equal(isProductTrustedClientPath("/v3/owner/project-scope/another"), false);
  const gateway = createCanonicalProductMcpGateway(ENV);
  const response = await gateway(new Request(
    "https://ordax-mcp.ordaxsystems.workers.dev" + path
    + "?device_id=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa&repository_full_name=ordaxsystems%2Fordax-os",
  ));
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { ok: false, error: "product_auth_required" });
  assert.equal(response.headers.get("cache-control"), "no-store");
  const forbidden = await gateway(new Request(
    "https://ordax-mcp.ordaxsystems.workers.dev/v3/owner/project-scope/another",
  ));
  assert.equal(forbidden.status, 404);
});

test("Trusted ingress manifest is the exact route inventory owned by the MCP router", async () => {
  const { isProductTrustedClientPath } = await import("../cloudflare/src/product_mcp_entry.ts");
  const manifest = JSON.parse(await readFile(new URL("../cloudflare/production-foundation.json", import.meta.url),"utf8"));
  const allowed = manifest.mcp_release.trusted_client_ingress;
  const exact = [
    "/v3/product/usage",
    "/v3/product/session",
    "/v3/device/setup",
    "/v3/product/device/presence",
    "/v3/product/device/central-session",
    "/v3/owner/project-scope",
    "/v3/owner/project-onboarding",
    "/v3/owner/project-onboarding/projects",
    "/v3/owner/github/authorization-challenges",
    "/v3/owner/github/authorization-completions",
    "/v3/owner/github/repository-candidates",
    "/v3/owner/github/repository-selections",
    "/v3/owner/central-session-selections",
    "/v3/owner/central-session-targets",
    "/v3/owner/remote-authority",
    "/v3/owner/devices",
    "/v3/owner/remote-grant-groups"
  ];
  assert.deepEqual(allowed.allowed_exact_paths,exact);
  assert.deepEqual(allowed.allowed_path_prefixes,[
    "/v3/device/transport/", "/v3/owner/remote-grant-groups/", "/v3/owner/devices/",
  ]);
  for (const path of exact) assert.equal(isProductTrustedClientPath(path),true,path);
  for (const prefix of allowed.allowed_path_prefixes) {
    assert.equal(isProductTrustedClientPath(prefix + "11111111-1111-4111-8111-111111111111"),true,prefix);
    assert.equal(isProductTrustedClientPath(prefix),false,prefix);
  }
  for (const path of [
    "/mcp","/health","/ready","/v3/product/device/setup",
    "/v3/owner/studio","/v3/owner/devices/all","/v3/owner/unknown",
  ]) assert.equal(isProductTrustedClientPath(path),false,path);
});

test("Owner MCP device inventory is exact on the trusted Runtime ingress and still requires OAuth", async () => {
  const { isProductTrustedClientPath } = await import("../cloudflare/src/product_mcp_entry.ts");
  assert.equal(isProductTrustedClientPath("/v3/owner/devices"), true);
  for (const path of [
    "/v3/owner/devices/", "/v3/owner/devices/another",
    "/v3/owner/studio", "/mcp", "/v3/owner/devices/delete",
  ]) assert.equal(isProductTrustedClientPath(path), false, path);
  const gateway = createCanonicalProductMcpGateway(ENV);
  const url = "https://ordax-mcp.ordaxsystems.workers.dev/v3/owner/devices";
  const response = await gateway(new Request(url));
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { ok: false, error: "product_auth_required" });
  assert.equal(response.headers.get("cache-control"), "no-store");
  const forbidden = await gateway(new Request(url + "/another"));
  assert.equal(forbidden.status, 404);
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
    "repository_catalog", "handoff_get", "handoff_create",
    "project_briefing", "continuity_state", "continuity_update",
    "computer_terminal_exec", "terminal_exec",
    "computer_process_status", "computer_process_list", "computer_process_logs",
    "computer_process_start", "computer_process_write_stdin", "computer_process_stop",
    "process_status", "process_list", "process_logs",
    "process_start", "process_write_stdin", "process_stop",
    "computer_windows", "computer_active_window", "computer_screenshot", "computer_screen_info",
    "computer_clipboard_read", "computer_focus_window", "computer_click", "computer_mouse_move",
    "computer_drag", "computer_clipboard_write", "computer_launch_app",
    "computer_scroll", "computer_type", "computer_hotkey",
    "computer_access_status", "ordax_surface_status", "ordax_surface_open", "forge_status", "computer_file_stat", "computer_directory_list", "computer_text_read",
    "computer_search", "computer_processes", "computer_terminate_process",
    "computer_transfer_begin", "computer_transfer_chunk", "computer_transfer_status",
    "computer_transfer_commit", "computer_transfer_abort",
    "computer_text_write", "computer_text_patch",
    "computer_directory_create", "computer_path_move", "computer_path_remove",
  ]);
  const byName = new Map(json.result.tools.map((tool: any) => [tool.name, tool]));
  for (const name of ["repository_catalog", "handoff_get", "handoff_create",
    "project_briefing", "continuity_state", "continuity_update"]) {
    assert.equal((byName.get(name) as any).inputSchema.required.includes("device_id"), true, name);
  }
  for (const name of ["handoff_get", "handoff_create", "project_briefing",
    "continuity_state", "continuity_update"]) {
    assert.equal((byName.get(name) as any).inputSchema.required.includes("repository_full_name"), true, name);
    assert.equal((byName.get(name) as any).inputSchema.required.includes("project"), false, name);
  }
  assert.equal((byName.get("continuity_update") as any).annotations.readOnlyHint, false);
  assert.equal((byName.get("handoff_create") as any).annotations.readOnlyHint, false);
  assert.equal((byName.get("ordax_surface_status") as any).annotations.readOnlyHint, true);
  assert.equal((byName.get("ordax_surface_open") as any).annotations.readOnlyHint, false);
  assert.equal((byName.get("ordax_surface_open") as any).annotations.destructiveHint, false);
  assert.deepEqual((byName.get("ordax_surface_open") as any).inputSchema.required, ["device_id", "appId"]);
  assert.equal((byName.get("computer_windows") as any).annotations.readOnlyHint, true);
  assert.equal((byName.get("computer_screenshot") as any).annotations.readOnlyHint, true);
  assert.equal((byName.get("computer_clipboard_read") as any).annotations.readOnlyHint, true);
  assert.equal((byName.get("computer_text_read") as any).annotations.readOnlyHint, true);
  assert.equal((byName.get("computer_click") as any).annotations.readOnlyHint, false);
  assert.equal((byName.get("computer_text_write") as any).annotations.destructiveHint, true);
  assert.equal((byName.get("computer_text_patch") as any).annotations.destructiveHint, true);
  assert.equal((byName.get("computer_click") as any).annotations.destructiveHint, true);
  assert.equal((byName.get("computer_focus_window") as any).annotations.destructiveHint, false);
  assert.equal((byName.get("computer_directory_create") as any).annotations.destructiveHint, false);
  assert.equal((byName.get("computer_path_move") as any).annotations.destructiveHint, true);
  assert.equal((byName.get("computer_path_remove") as any).annotations.destructiveHint, true);
  assert.equal((byName.get("computer_clipboard_write") as any).annotations.destructiveHint, false);
  assert.equal((byName.get("computer_terminate_process") as any).annotations.destructiveHint, true);
  for (const name of ["computer_terminal_exec", "terminal_exec"]) {
    const terminal = byName.get(name) as any;
    assert.equal(terminal.inputSchema.properties.timeout_seconds.default, 60);
    assert.match(terminal.description, /60-second default/);
    assert.match(terminal.description, /process_start/);
  }
  for (const name of ["computer_process_start", "process_start"]) {
    assert.match((byName.get(name) as any).description, /supervised (?:device )?process/);
  }
  assert.equal((byName.get("computer_terminal_exec") as any).annotations.destructiveHint, true);
  assert.equal((byName.get("computer_process_start") as any).annotations.destructiveHint, true);
  assert.equal((byName.get("computer_process_status") as any).annotations.readOnlyHint, true);
  assert.equal(calls.session, 1);
  assert.equal(calls.targets, 0);
});

test("MCP terminology keeps account subject, Space, device and Project independently scoped", async () => {
  const { handlers } = fakeHandlers();
  const run = createCanonicalProductMcpGateway(ENV, handlers);
  const response = await run(new Request(MCP_URL, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  }));
  assert.equal(response.status, 200);
  const { result } = await response.json() as any;
  const tools = new Map<string, any>(result.tools.map((tool: any) => [tool.name, tool]));
  const account = tools.get("ordax_profile");
  assert.ok(account);
  assert.match(account.description, /account subject id/i);
  assert.match(account.description, /not an OS Profile, Profile Pack, Space/i);
  assert.equal(account.outputSchema.properties.id.type, "string");
  assert.match(account.outputSchema.properties.id.description, /account subject ID/i);
  // Basic identity/discovery and device observation do not require a Space or Project.
  for (const name of ["ordax_session", "ordax_profile", "ordax_targets", "ordax_action_status", "computer_processes"]) {
    const tool = tools.get(name);
    assert.ok(tool, name);
    assert.equal(tool.inputSchema.required.includes("space_id"), false, name);
    assert.equal(tool.inputSchema.required.includes("project"), false, name);
  }
  assert.match(tools.get("computer_processes").description, /process/i);
  // Native processes and terminal are project-scoped, distinct from computer observation.
  for (const name of ["process_list", "terminal_exec"]) {
    const tool = tools.get(name);
    assert.ok(tool, name);
    assert.ok(tool.inputSchema.required.includes("project"), name);
    assert.equal(tool.inputSchema.required.includes("space_id"), false, name);
    assert.match(tool.inputSchema.properties.project.description, /GitHub owner\/repository/i);
  }
  assert.match(tools.get("terminal_exec").inputSchema.properties.space_id.description, /Omission never bypasses/i);
  const profileResponse = await run(request("ordax_profile"));
  const profileCall = await profileResponse.json() as any;
  assert.equal(profileCall.result.structuredContent.id, "server-subject");
});

test("unrelated browser and project tools remain unpublished", async () => {
  const { handlers, calls } = fakeHandlers();
  const run = createCanonicalProductMcpGateway(ENV, handlers);
  for (const action of [
    "browser_start", "project_text_write",
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
    assert.equal(json.result.structuredContent.error, "central_session_marker_required");
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

test("targets reports safe upstream failure reasons rather than hiding actionable grant errors", async () => {
  for (const [status, upstream, expected] of [
    [403, "product_mcp_oauth_consent_required", "product_mcp_oauth_consent_required"],
    [403, "product_target_discovery_grant_failed", "product_target_discovery_grant_failed"],
    [503, "product_targets_unavailable", "product_targets_unavailable"],
    [502, "product_postgres_invalid_response", "product_postgres_invalid_response"],
    [500, "private:postgres-exception/password", "targets_unavailable"],
  ] as const) {
    const { handlers } = fakeHandlers();
    handlers.targets = async () => Response.json(
      { ok: false, error: upstream, internal_detail: "do-not-expose" }, { status },
    );
    const response = await createCanonicalProductMcpGateway(ENV, handlers)(request("ordax_targets"));
    const json = await response.json() as any;
    assert.equal(response.status, 200);
    assert.equal(json.result.isError, true);
    assert.deepEqual(json.result.structuredContent, { ok: false, error: expected });
    assert.ok(!JSON.stringify(json).includes("do-not-expose"));
  }
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
  assert.equal(json.result.structuredContent.mcp_tool_count, PRODUCT_MCP_DIRECT_TOOLS.size);
  assert.match(json.result.structuredContent.mcp_tool_surface_revision, /^catalog-v1-[0-9a-f]{64}$/);
  // The authenticated diagnostics must reflect tools/list, not a parallel
  // hand-maintained inventory that can drift when actions are introduced.
  const listing = await gateway(new Request(MCP_URL, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }),
  }));
  const listed = await listing.json() as any;
  const names = listed.result.tools.map((tool: { name: string }) => tool.name);
  assert.deepEqual(json.result.structuredContent.mcp_tool_names, names);
  assert.equal(new Set(names).size, names.length);
  for (const tool of ["computer_transfer_begin", "computer_transfer_chunk", "computer_transfer_status",
    "computer_transfer_commit", "computer_transfer_abort"]) {
    assert.ok(names.includes(tool), tool);
  }
  assert.ok(!names.includes("project_create"));
});

test("restricted MCP projection reports only allowed names in session diagnostics", async () => {
  const { handlers } = fakeHandlers();
  const allowed = new Set(["ordax_session", "ordax_targets"]);
  const gateway = createCanonicalProductMcpGateway(ENV, handlers, fetch, allowed);
  const response = await gateway(request("ordax_session"));
  const json = await response.json() as any;
  assert.deepEqual(json.result.structuredContent.mcp_tool_names, ["ordax_session", "ordax_targets"]);
  assert.equal(json.result.structuredContent.mcp_tool_count, 2);
  assert.equal(json.result.structuredContent.mcp_tool_names.includes("computer_transfer_commit"), false);
});

test("advertised MCP projection includes device terminal and supervised processes", async () => {
  const { handlers } = fakeHandlers();
  const gateway = createCanonicalProductMcpGateway(ENV, handlers);
  const response = await gateway(new Request(MCP_URL, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  }));
  assert.equal(response.status, 200);
  const payload = await response.json();
  const names = new Set(payload.result.tools.map((tool: { name: string }) => tool.name));
  assert.equal(names.size, PRODUCT_MCP_DIRECT_TOOLS.size);
  for (const name of [
    "computer_terminal_exec",
    "computer_process_start", "computer_process_status", "computer_process_list",
    "computer_process_logs", "computer_process_write_stdin", "computer_process_stop",
  ]) {
    assert.equal(names.has(name), true, name);
  }
  assert.equal(names.has("project_create"), false);
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
    wait: async (milliseconds) => { assert.equal(milliseconds, 2000); waits++; },
  });
  assert.equal(resolved.ok, true);
  assert.equal(checks, 3);
  assert.equal(opens, 1);
  assert.equal(waits, 2);
});

test("native twenty-second heartbeat confirmation succeeds without a manual session call", async () => {
  let checks = 0, opens = 0, waitedMs = 0;
  const confirmed = await resolveOrBootstrapAttestedSession(request("computer_text_read"), ENV, {
    resolve: async () => {
      checks++;
      return checks < 13 ? { ok: false, error: "central_session_unbound" }
        : { ok: true, ownerUserId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            clientId: "product-client-123", deviceId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" };
    },
    open: async () => { opens++; return Response.json({ ok: true, status: "pending" }, { status: 202 }); },
    wait: async (milliseconds) => { assert.equal(milliseconds, 2000); waitedMs += milliseconds; },
  });
  assert.equal(confirmed.ok, true);
  assert.equal(waitedMs, 24000, "covers the actual 20s heartbeat plus confirmation latency");
  assert.equal(checks, 13);
  assert.equal(opens, 1, "never duplicates the device challenge");
});

test("bound-open race still requires canonical SQL confirmation, never trusts a response hint", async () => {
  let checks = 0, waits = 0;
  const confirmed = await resolveOrBootstrapAttestedSession(request("computer_windows"), ENV, {
    resolve: async () => {
      checks++;
      return checks === 1 ? { ok: false, error: "central_session_unbound" }
        : { ok: true, ownerUserId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            clientId: "product-client-123", deviceId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" };
    },
    open: async () => Response.json({ ok: true, status: "bound",
      device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }),
    wait: async () => { waits++; },
  });
  assert.equal(confirmed.ok, true);
  assert.equal(checks, 2);
  assert.equal(waits, 0, "already-confirmed binding has no artificial polling delay");

  let failures = 0;
  const denied = await resolveOrBootstrapAttestedSession(request("computer_windows"), ENV, {
    resolve: async () => { failures++; return { ok: false, error: "central_session_unbound" }; },
    open: async () => Response.json({ ok: true, status: "bound",
      device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }),
    wait: async () => {},
  });
  assert.equal(denied.ok, false);
  assert.equal(denied.error, "central_session_pending");
  assert.equal(failures, 18, "opening a bound ticket is never sufficient to authorize a device");
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
  assert.equal(denied.error, "central_device_target_missing");
  assert.equal(retries, 1);
});

test("ambiguous Central device selection yields a safe remediation instead of opaque trusted-operation error", async () => {
  const { handlers } = fakeHandlers();
  let opens = 0;
  const gateway = createCanonicalProductMcpGateway(ENV, handlers, fetch,
    new Set(["computer_access_status"]), {
      resolve: async () => ({ ok: false, error: "central_session_unbound" }),
      open: async () => {
        opens++;
        return Response.json({ ok: false, error: "central_device_target_ambiguous" }, { status: 409 });
      },
      wait: async () => { throw new Error("must_not_wait"); },
    });
  const response = await gateway(request("computer_access_status",
    { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }));
  const body = await response.json() as any;
  assert.equal(body.result.isError, true);
  assert.equal(body.result.structuredContent.error, "central_device_target_ambiguous");
  assert.equal(opens, 1);
});

test("offline authorized device returns reconnect guidance without waiting or observing actions", async () => {
  const { handlers, calls } = fakeHandlers();
  const gateway = createCanonicalProductMcpGateway(ENV, handlers, fetch,
    new Set(["computer_terminal_exec"]), {
      resolve: async () => ({ ok: false, error: "central_session_unbound" }),
      open: async () => Response.json({ ok: false, error: "central_device_offline" }, { status: 409 }),
      wait: async () => { assert.fail("offline device must not enter the confirmation wait loop"); },
    });
  const response = await gateway(request("computer_terminal_exec", {
    device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", argv: ["uname", "-s"],
  }));
  const body = await response.json() as any;
  assert.equal(body.result.isError, true);
  assert.deepEqual(body.result.structuredContent, {
    ok: false, error: "central_device_offline", retryable: true, action_dispatched: false,
    required_action: "reconnect_authorized_device_runtime",
  });
  assert.equal(calls.targets, 0);
  assert.equal(calls.getAction, 0);
});

test("discovery-only online device gives immediate Runtime remediation without dispatching", async () => {
  const { handlers, calls } = fakeHandlers();
  let openings = 0;
  const gateway = createCanonicalProductMcpGateway(ENV, handlers, fetch,
    new Set(["computer_access_status"]), {
      resolve: async () => ({ ok: false, error: "central_session_unbound" }),
      open: async () => {
        openings++;
        return Response.json({ ok: false, error: "central_device_runtime_not_ready" }, { status: 409 });
      },
      wait: async () => { assert.fail("do not wait for a Runtime that has not heartbeated"); },
    });
  const response = await gateway(request("computer_access_status", {
    device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
  }));
  const body = await response.json() as any;
  assert.equal(body.result.isError, true);
  assert.deepEqual(body.result.structuredContent, {
    ok: false, error: "central_device_runtime_not_ready",
    retryable: true, action_dispatched: false,
    required_action: "start_or_restore_authorized_product_action_runtime",
  });
  assert.equal(openings, 1);
  assert.equal(calls.targets, 0);
  assert.equal(calls.getAction, 0);
});

test("unclassified Central session failure remains fail-closed and generic", async () => {
  const { handlers } = fakeHandlers();
  const gateway = createCanonicalProductMcpGateway(ENV, handlers, fetch,
    new Set(["computer_access_status"]), {
      resolve: async () => ({ ok: false, error: "central_session_unbound" }),
      open: async () => Response.json({ ok: false, error: "central_session_unavailable" }, { status: 503 }),
      wait: async () => { throw new Error("must_not_wait"); },
    });
  const response = await gateway(request("computer_access_status",
    { device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }));
  const body = await response.json() as any;
  assert.equal(body.result.isError, true);
  assert.equal(body.result.structuredContent.error, "trusted_operation_required");
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
  assert.equal(checks, 17);
  assert.equal(waits, 16);
  assert.equal(calls.targets, 0);
  assert.equal(calls.getAction, 0);
});

test("first device operation accepts native five-second cadence without the legacy long wait", async () => {
  let checks = 0, opens = 0, waits = 0;
  const confirmed = await resolveOrBootstrapAttestedSession(request("computer_directory_list"), ENV, {
    resolve: async () => {
      checks++;
      return checks < 4 ? { ok: false, error: "central_session_unbound" } :
        { ok: true, ownerUserId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          clientId: "product-client-123", deviceId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" };
    },
    open: async () => { opens++; return Response.json({ ok: true, status: "pending" }, { status: 202 }); },
    wait: async (milliseconds) => { assert.equal(milliseconds, 2000); waits++; },
  });
  assert.equal(confirmed.ok, true);
  assert.equal(opens, 1);
  assert.equal(waits, 3);
  assert.equal(checks, 4);
});


test("published MCP Worker passes request-owned waitUntil to both attested action handlers", async () => {
  const source = await readFile(new URL("../cloudflare/src/product_mcp_entry.ts", import.meta.url), "utf8");
  assert.match(source, /scheduleWake: \(wake: Promise<void>\) => context\.waitUntil\(wake\)/);
  assert.match(source, /createAttestedProjectActionHandler\(env, trusted, wakeDependencies\)/);
  assert.match(source, /createAttestedDeviceActionHandler\(env, trusted, wakeDependencies\)/);
  assert.match(source, /createCanonicalProductMcpGateway\(env\)\(request, context\)/);
  assert.doesNotMatch(source, /void notifyProductDeviceWake\(/);
});


test("Owner Project binding intent is a trusted Product path but remains default-off in release config", async () => {
  const { isProductTrustedClientPath } = await import("../cloudflare/src/product_mcp_entry.ts");
  const exact = "/v3/owner/project-onboarding/device-binding-intents";
  assert.equal(isProductTrustedClientPath(exact), true);
  for (const lookalike of [
    exact + "/extra",
    "/v3/owner/project-onboarding/device-binding-intent",
    "/v3/owner/device-binding-intents",
  ]) assert.equal(isProductTrustedClientPath(lookalike), false, lookalike);

  const source = await readFile(
    new URL("../cloudflare/src/product_mcp_entry.ts", import.meta.url), "utf8",
  );
  const release = await readFile(
    new URL("../cloudflare/wrangler.mcp.toml", import.meta.url), "utf8",
  );
  assert.match(source, /PRODUCT_OWNER_PROJECT_DEVICE_BINDING_INTENTS_PATH/);
  assert.match(source, /handleProductOwnerProjectOnboarding\(request, env\)/);
  assert.doesNotMatch(release, /OWNER_PROJECT_DEVICE_BINDING_ENABLED\s*=/,
    "merging source must not activate Project binding before Runtime attestation");
});
