import assert from "node:assert/strict";
import test from "node:test";
import {
  catalogAllowsAttestedProjectAction,
  createAttestedProjectActionHandler,
  validAttestedProjectActionArguments,
} from "../cloudflare/src/product_mcp_attested_project_action.ts";

const OWNER = "11111111-1111-4111-8111-111111111111";
const DEVICE = "22222222-2222-4222-8222-222222222222";
const SPACE = "33333333-3333-4333-8333-333333333333";
const PROJECT = "44444444-4444-4444-8444-444444444444";
const REQUEST = "55555555-5555-4555-8555-555555555555";
const EFFECT = "66666666-6666-4666-8666-666666666666";
const OPERATION = "77777777-7777-4777-8777-777777777777";
const CLIENT = "chatgpt-product-mcp";
const REPOSITORY = "ordaxsystems/ordax-runtime";
const ENV = Object.freeze({});
const TRUSTED = Object.freeze({ ownerUserId: OWNER, clientId: CLIENT, deviceId: DEVICE });
const SCOPE = Object.freeze({ spaceId: SPACE, projectId: PROJECT, repositoryFullName: REPOSITORY });

const identity = async () => ({
  ok: true as const, ownerUserId: OWNER, clientKind: "product-mcp" as const,
  clientId: CLIENT, expiresAt: 2_000_000_000,
});
const resolveProject = async () => ({
  ok: true, space_id: SPACE, project_id: PROJECT, repository_full_name: REPOSITORY,
});
function actionRequest(action: string, args: Record<string, unknown> = {},
  options: { deviceId?: string; project?: string; spaceId?: string | null } = {}) {
  return new Request("https://mcp.example/v3/product/actions", {
    method: "POST", headers: { authorization: "Bearer test", "content-type": "application/json" },
    body: JSON.stringify({
      device_id: options.deviceId ?? DEVICE, space_id: options.spaceId ?? null,
      action, project: options.project ?? REPOSITORY, arguments: args,
    }),
  });
}
function grantGroup(capability: string, access_mode: "read" | "write",
  options: { profile?: string; projectId?: string; spaceId?: string } = {}) {
  return {
    profile_key: options.profile ?? (capability === "terminal.exec" ? "project-native-terminal" : "project-native-process"),
    space_id: options.spaceId ?? SPACE,
    project_id: options.projectId ?? PROJECT,
    valid_until: null,
    capabilities: [{ capability, access_mode }],
  };
}
function catalog(...groups: ReturnType<typeof grantGroup>[]) {
  return { ok: true, targets: [{ device_id: DEVICE, grant_groups: groups }] };
}

test("terminal and supervisor schemas are explicit, strict and bounded", () => {
  assert.equal(validAttestedProjectActionArguments("terminal.exec", { argv: ["python", "--version"] }), true);
  assert.equal(validAttestedProjectActionArguments("terminal.exec", { command: "echo hello", shell: true }), true);
  assert.equal(validAttestedProjectActionArguments("terminal.exec", { command: "echo hello" }), false);
  assert.equal(validAttestedProjectActionArguments("terminal.exec", { argv: ["python"], shell: "false" }), false);
  assert.equal(validAttestedProjectActionArguments("terminal.exec", { argv: ["python"], shell: true }), false);
  assert.equal(validAttestedProjectActionArguments("terminal.exec", { argv: ["python"], command: "echo" }), false);
  assert.equal(validAttestedProjectActionArguments("terminal.exec", { argv: ["python"], env: { "BAD=KEY": "x" } }), false);
  assert.equal(validAttestedProjectActionArguments("terminal.exec", { argv: ["python"], env: { BAD: "x\u0000y" } }), false);
  assert.equal(validAttestedProjectActionArguments("terminal.exec", { argv: ["python"], timeout_seconds: 1801 }), false);
  assert.equal(validAttestedProjectActionArguments("process.start", { argv: ["python", "-i"] }), true);
  assert.equal(validAttestedProjectActionArguments("process.start", { argv: [] }), false);
  assert.equal(validAttestedProjectActionArguments("process.start", { argv: ["python"], wait_seconds: 6 }), false);
  assert.equal(validAttestedProjectActionArguments("process.list", {}), true);
  assert.equal(validAttestedProjectActionArguments("process.list", { extra: "bad" }), false);
  assert.equal(validAttestedProjectActionArguments("process.status", { process_id: REQUEST }), true);
  assert.equal(validAttestedProjectActionArguments("process.logs", { process_id: REQUEST, max_bytes: 1024 }), true);
  assert.equal(validAttestedProjectActionArguments("process.logs", { process_id: REQUEST, max_bytes: 300000 }), false);
  assert.equal(validAttestedProjectActionArguments("process.write_stdin", { process_id: REQUEST, text: "hello", newline: false }), true);
  assert.equal(validAttestedProjectActionArguments("process.stop", { process_id: REQUEST }), true);
  assert.equal(validAttestedProjectActionArguments("continuity.update", { summary: "not exposed" }), false);
});

test("browser tabs require exact project grant and validated tab selectors", async () => {
  const grant = grantGroup("browser.tab_open", "write", { profile: "project-browser-automation" });
  assert.equal(catalogAllowsAttestedProjectAction(catalog(grant), DEVICE, SCOPE, "browser.tab_open"), true);
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("browser.tab_open", "read", { profile: "project-browser-automation" })),
    DEVICE, SCOPE, "browser.tab_open"), false);
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("browser.tab_open", "write", { profile: "full-computer-control" })),
    DEVICE, SCOPE, "browser.tab_open"), false);
  assert.equal(validAttestedProjectActionArguments("browser.start", { url: "https://chatgpt.com/" }), true);
  assert.equal(validAttestedProjectActionArguments("browser.start", { url: "https://chatgpt.com/", resume_session_id: REQUEST }), true);
  assert.equal(validAttestedProjectActionArguments("browser.start", { resume_session_id: "../../browser-profile" }), false);
  assert.equal(validAttestedProjectActionArguments("browser.start", { resume_session_id: "bad" }), false);
  assert.equal(validAttestedProjectActionArguments("browser.start", { url: "file:///windows/system" }), false);
  assert.equal(validAttestedProjectActionArguments("browser.start", { url: "https://someone:password@example.com/" }), false);
  assert.equal(validAttestedProjectActionArguments("browser.navigate", { session_id: REQUEST, tab_id: "A".repeat(32), url: "https://example.com/" }), true);
  assert.equal(validAttestedProjectActionArguments("browser.navigate", { session_id: REQUEST, tab_id: "bad!", url: "https://example.com/" }), false);
  assert.equal(validAttestedProjectActionArguments("browser.snapshot", { session_id: REQUEST, tab_id: "A".repeat(32) }), true);
  assert.equal(validAttestedProjectActionArguments("browser.type", { session_id: REQUEST, node_id: "n1", text: "hello" }), true);
  assert.equal(validAttestedProjectActionArguments("browser.type", { session_id: REQUEST, node_id: "n1", text: "x".repeat(10001) }), false);
  assert.equal(validAttestedProjectActionArguments("browser.tab_open", { session_id: REQUEST, url: "javascript:alert(1)" }), false);

  let received: any = null;
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity, resolveProject,
    listTargets: async () => catalog(grant),
    enqueue: async (_env, input) => {
      received = input;
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    operationId: () => OPERATION,
  });
  const result = await handler(actionRequest("browser.tab_open", {
    session_id: REQUEST, url: "https://example.com/",
  }));
  assert.equal(result.status, 202);
  assert.equal(received.capability, "browser.tab_open");
  assert.equal(received.accessMode, "write");
  assert.equal(received.projectId, PROJECT);
  assert.equal(received.payload._ordax_project_scope.repository_full_name, REPOSITORY);

  const denied = await handler(actionRequest("browser.type", {
    session_id: REQUEST, node_id: "n1", text: "no inherited write grant",
  }));
  assert.equal(denied.status, 403);
});

test("terminal enqueue uses exactly the bound Space/project, canonical hidden scope and write grant", async () => {
  let received: any = null;
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity, resolveProject,
    listTargets: async () => catalog(grantGroup("terminal.exec", "write")),
    enqueue: async (_env, input) => {
      received = input;
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    operationId: () => OPERATION,
  });
  const response = await handler(actionRequest("terminal.exec", { argv: ["python", "--version"], cwd: "." }));
  assert.equal(response.status, 202);
  assert.equal(received.clientId, CLIENT);
  assert.equal(received.deviceId, DEVICE);
  assert.equal(received.projectId, PROJECT);
  assert.equal(received.spaceId, SPACE);
  assert.equal(received.capability, "terminal.exec");
  assert.equal(received.accessMode, "write");
  assert.equal(received.idempotencyKey, "mcp-project-write-" + OPERATION);
  assert.deepEqual(received.payload, {
    argv: ["python", "--version"], cwd: ".",
    _ordax_project_scope: { project_id: PROJECT, repository_full_name: REPOSITORY },
  });
  assert.equal(Object.hasOwn(received.payload, "project"), false);
});

test("supervised process reads cannot borrow write-only capability or another profile", () => {
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("process.status", "read")), DEVICE, SCOPE, "process.status"), true);
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("process.status", "write")), DEVICE, SCOPE, "process.status"), false);
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("terminal.exec", "read")), DEVICE, SCOPE, "terminal.exec"), false);
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("terminal.exec", "write", { profile: "full-computer-control" })),
    DEVICE, SCOPE, "terminal.exec"), false);
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("terminal.exec", "write", { projectId: REQUEST })),
    DEVICE, SCOPE, "terminal.exec"), false);
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("terminal.exec", "write", { spaceId: REQUEST })),
    DEVICE, SCOPE, "terminal.exec"), false);
});

test("model-selected device/slug and mismatch fail before execution", async () => {
  let enqueued = 0;
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity, resolveProject,
    listTargets: async () => catalog(grantGroup("terminal.exec", "write")),
    enqueue: async () => { enqueued++; throw new Error("must not execute"); },
  });
  let response = await handler(actionRequest("terminal.exec", { argv: ["python"] }, { deviceId: REQUEST }));
  assert.equal(response.status, 400);
  response = await handler(actionRequest("terminal.exec", { argv: ["python"] }, { project: "local-project-slug" }));
  assert.equal(response.status, 400);
  response = await handler(actionRequest("terminal.exec", { argv: ["python"] }, { spaceId: REQUEST }));
  assert.equal(response.status, 409);
  assert.equal(enqueued, 0);
});

test("unregistered repository/Space/device binding fails before grant listing or enqueue", async () => {
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject: async () => ({ ok: false, error: "owner_project_scope_not_found" }),
    listTargets: async () => { assert.fail("cannot request grants without an attested canonical project scope"); },
    enqueue: async () => { assert.fail("cannot enqueue actions without a registered project"); },
  });
  for (const [action, args] of [
    ["process.list", {}],
    ["terminal.exec", { argv: ["python", "--version"] }],
  ] as const) {
    const response = await handler(actionRequest(action, args));
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { ok: false, error: "product_project_scope_not_found" });
  }
});

test("missing native terminal grant returns an explicit owner profile without enqueue", async () => {
  let enqueued = false;
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity, resolveProject,
    listTargets: async () => catalog(grantGroup("terminal.exec", "write", { profile: "project-native-process" })),
    enqueue: async () => { enqueued = true; throw new Error("not allowed"); },
  });
  const response = await handler(actionRequest("terminal.exec", { argv: ["python"] }));
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), {
    ok: false, error: "product_grant_not_resolved",
    required_profile: "project-native-terminal", owner_action: "authorize_in_ordax_owner_permissions",
  });
  assert.equal(enqueued, false);
});

test("OAuth owner mismatch fails closed before grant resolution", async () => {
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: async () => ({ ...await identity(), ownerUserId: REQUEST }),
  });
  const response = await handler(actionRequest("terminal.exec", { argv: ["python"] }));
  assert.equal(response.status, 403);
  assert.equal((await response.json()).error, "trusted_operation_required");
});

test("project-scoped retries reuse their PostgreSQL key after a lost response", async () => {
  const digest = "b".repeat(64);
  const keys: string[] = [];
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject,
    listTargets: async () => catalog(grantGroup("terminal.exec", "write")),
    enqueue: async (_env, input) => {
      keys.push(input.idempotencyKey);
      assert.equal(input.spaceId, SPACE);
      assert.equal(input.projectId, PROJECT);
      return { ok: true, replayed: keys.length > 1,
        request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    operationId: () => { assert.fail("stable project retry must not generate a new UUID"); },
  });
  const first = await handler(actionRequest("terminal.exec", { argv: ["python", "--version"] }), digest);
  const retried = await handler(actionRequest("terminal.exec", { argv: ["python", "--version"] }), digest);
  assert.equal(first.status, 202);
  assert.equal(retried.status, 200);
  assert.equal((await first.json()).request_id, REQUEST);
  assert.equal((await retried.json()).request_id, REQUEST);
  assert.deepEqual(keys, [`mcp-project-write-${digest}`, `mcp-project-write-${digest}`]);
  assert.equal((await handler(actionRequest("terminal.exec", { argv: ["python"] }), null)).status, 400);
  assert.equal(keys.length, 2);
});

test("project-scoped reads stay fresh when a retry digest is reused", async () => {
  const digest = "d".repeat(64);
  const ids = [
    "88888888-8888-4888-8888-888888888881",
    "88888888-8888-4888-8888-888888888882",
  ];
  const keys: string[] = [];
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject,
    listTargets: async () => catalog(grantGroup("process.status", "read")),
    enqueue: async (_env, input) => {
      keys.push(input.idempotencyKey);
      return { ok: true, replayed: false,
        request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    operationId: () => ids.shift() ?? assert.fail("unexpected third project read"),
  });
  const args = { process_id: "99999999-9999-4999-8999-999999999999" };
  assert.equal((await handler(actionRequest("process.status", args), digest)).status, 202);
  assert.equal((await handler(actionRequest("process.status", args), digest)).status, 202);
  assert.deepEqual(keys, [
    "mcp-project-read-88888888-8888-4888-8888-888888888881",
    "mcp-project-read-88888888-8888-4888-8888-888888888882",
  ]);
});

test("attested project action forwards the Worker wake scheduler without altering SQL project scope", async () => {
  const scheduleWake = (_wake: Promise<void>) => {};
  let received: any = null;
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject,
    listTargets: async () => catalog(grantGroup("terminal.exec", "write")),
    enqueue: async (_env, input) => {
      received = input;
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    scheduleWake,
  });
  assert.equal((await handler(actionRequest("terminal.exec", { argv: ["node", "--version"] }))).status, 202);
  assert.equal(received.scheduleWake, scheduleWake);
  assert.equal(received.spaceId, SPACE);
  assert.equal(received.projectId, PROJECT);
  assert.equal(Object.hasOwn(received.payload, "scheduleWake"), false);
  const noContext = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject,
    listTargets: async () => catalog(grantGroup("terminal.exec", "write")),
    enqueue: async (_env, input) => {
      assert.equal(Object.hasOwn(input, "scheduleWake"), false);
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
  });
  assert.equal((await noContext(actionRequest("terminal.exec", { argv: ["node", "--version"] }))).status, 202);
});


test("Blender Product MCP keeps typed rigging within canonical Project authority", async () => {
  const bones = [
    { name: "Root", head: [0, 0, 0], tail: [0, 0, 1] },
    { name: "Spine", head: [0, 0, 1], tail: [0, 0, 2], parent: "Root" },
  ];
  assert.equal(validAttestedProjectActionArguments("blender.live_rig_create", {
    name: "Rig", bones, location: [0, 0, 0],
  }), true);
  for (const value of [
    { name: "Rig", bones: [], },
    { name: "Rig", bones, script: "import os" },
    { name: "Rig", bones: [{ name: "Broken", head: [0, 0, 0], tail: [0, 0, 0] }] },
    { name: "Rig", bones: [{ ...bones[0], parent: "Spine" }, bones[1]] },
    { name: "Rig", bones: [bones[0], { ...bones[1], name: "Root" }] },
    { name: "Rig", bones, location: [Number.NaN, 0, 0] },
  ]) {
    assert.equal(validAttestedProjectActionArguments("blender.live_rig_create", value), false);
  }
  assert.equal(validAttestedProjectActionArguments("blender.live_run_script", { script_path: "unsafe.py" }), false);
  assert.equal(validAttestedProjectActionArguments("blender.live_save", { target_path: "scene.blend" }), true);
  assert.equal(validAttestedProjectActionArguments("blender.live_start", { adopt_blank: true }), true);

  const allowed = grantGroup("blender.live_rig_create", "write", { profile: "project-blender-control" });
  assert.equal(catalogAllowsAttestedProjectAction(catalog(allowed), DEVICE, SCOPE, "blender.live_rig_create"), true);
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("blender.live_rig_create", "read", { profile: "project-blender-control" })),
    DEVICE, SCOPE, "blender.live_rig_create"), false);
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("blender.live_rig_create", "write", { profile: "project-native-terminal" })),
    DEVICE, SCOPE, "blender.live_rig_create"), false);
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("blender.live_rig_create", "write", { profile: "project-blender-control", projectId: REQUEST })),
    DEVICE, SCOPE, "blender.live_rig_create"), false);

  let accepted: any = null;
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity, resolveProject,
    listTargets: async () => catalog(allowed),
    enqueue: async (_env, body) => {
      accepted = body;
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    operationId: () => OPERATION,
  });
  const response = await handler(actionRequest("blender.live_rig_create", { name: "Rig", bones }));
  assert.equal(response.status, 202);
  assert.equal(accepted.capability, "blender.live_rig_create");
  assert.equal(accepted.accessMode, "write");
  assert.equal(accepted.projectId, PROJECT);
  assert.equal(accepted.spaceId, SPACE);
  assert.deepEqual(accepted.payload, {
    name: "Rig", bones,
    _ordax_project_scope: { project_id: PROJECT, repository_full_name: REPOSITORY },
  });
  assert.equal(accepted.idempotencyKey, "mcp-project-write-" + OPERATION);
});

test("Blender project MCP refuses model-selected slug and foreign Space", async () => {
  let enqueued = 0;
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity, resolveProject,
    listTargets: async () => catalog(grantGroup("blender.live_status", "read", { profile: "project-blender-control" })),
    enqueue: async () => { enqueued++; throw new Error("must not enqueue"); },
  });
  const action = "blender.live_status";
  assert.equal((await handler(actionRequest(action, {}, { project: "local-scene" }))).status, 400);
  assert.equal((await handler(actionRequest(action, {}, { spaceId: REQUEST }))).status, 409);
  assert.equal(enqueued, 0);
});

test("offline project executor produces an explicit nonqueued response", async () => {
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity, resolveProject,
    listTargets: async () => catalog(grantGroup("terminal.exec", "write")),
    enqueue: async () => ({ ok: false, error: "product_device_offline" }),
  });
  const response = await handler(actionRequest("terminal.exec", { argv: ["python", "--version"] }), "a".repeat(64));
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), {
    ok: false, error: "product_device_offline", action_dispatched: false,
  });
});

test("saturated project reports busy instead of fabricating a queued receipt", async () => {
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity, resolveProject,
    listTargets: async () => catalog(grantGroup("terminal.exec", "write")),
    enqueue: async () => ({ ok: false, error: "product_device_busy" }),
  });
  const response = await handler(
    actionRequest("terminal.exec", { argv: ["python", "--version"] }),
    "f".repeat(64),
  );
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), {
    ok: false, error: "product_device_busy", action_dispatched: false,
  });
});
