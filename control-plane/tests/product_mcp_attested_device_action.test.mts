import assert from "node:assert/strict";
import test from "node:test";
import {
  catalogAllowsAttestedDeviceAction,
  createAttestedDeviceActionHandler,
  validAttestedDeviceActionArguments,
} from "../cloudflare/src/product_mcp_attested_device_action.ts";

const OWNER = "11111111-1111-4111-8111-111111111111";
const DEVICE = "22222222-2222-4222-8222-222222222222";
const REQUEST = "33333333-3333-4333-8333-333333333333";
const EFFECT = "44444444-4444-4444-8444-444444444444";
const OPERATION = "55555555-5555-4555-8555-555555555555";
const CLIENT = "chatgpt-product-mcp";
const ENV = Object.freeze({});
const TRUSTED = Object.freeze({ ownerUserId: OWNER, clientId: CLIENT, deviceId: DEVICE });

function actionRequest(action: string, args: Record<string, unknown> = {}, deviceId = DEVICE) {
  return new Request("https://mcp.example/v3/product/actions", {
    method: "POST",
    headers: { authorization: "Bearer test", "content-type": "application/json" },
    body: JSON.stringify({
      device_id: deviceId,
      space_id: null,
      action,
      project: null,
      arguments: args,
    }),
  });
}

function grantGroup(
  profile_key: string,
  capability: string,
  access_mode: "read" | "write",
) {
  return {
    profile_key,
    space_id: null,
    project_id: null,
    valid_until: null,
    capabilities: [{ capability, access_mode }],
  };
}

function catalog(...groups: ReturnType<typeof grantGroup>[]) {
  return {
    ok: true,
    targets: [{ device_id: DEVICE, grant_groups: groups }],
  };
}

const identity = async () => ({
  ok: true as const,
  ownerUserId: OWNER,
  clientKind: "product-mcp" as const,
  clientId: CLIENT,
  expiresAt: 2_000_000_000,
});

test("device process lifecycle validates payload and grant scope independently", async () => {
  const proc = "66666666-6666-4666-8666-666666666666";
  const cases: Array<[string, Record<string, unknown>, "read" | "write"]> = [
    ["computer.process_start", { argv: ["node", "--version"] }, "write"],
    ["computer.process_status", { process_id: proc }, "read"],
    ["computer.process_list", {}, "read"],
    ["computer.process_logs", { process_id: proc, max_bytes: 4096 }, "read"],
    ["computer.process_write_stdin", { process_id: proc, text: "hello", newline: true }, "write"],
    ["computer.process_stop", { process_id: proc }, "write"],
  ];
  for (const [action, args, mode] of cases) {
    assert.equal(validAttestedDeviceActionArguments(action, args), true, action);
    let calls = 0;
    const handler = createAttestedDeviceActionHandler(ENV, TRUSTED, {
      authenticate: identity,
      listTargets: async () => catalog(grantGroup("device-native-process", action, mode)),
      enqueue: async (_env, input) => {
        calls++;
        assert.equal(input.capability, action);
        assert.equal(input.projectId, null);
        assert.equal(input.accessMode, mode);
        return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
      },
    });
    assert.equal((await handler(actionRequest(action, args))).status, 202, action);
    assert.equal(calls, 1);
    const wrong = createAttestedDeviceActionHandler(ENV, TRUSTED, {
      authenticate: identity,
      listTargets: async () => catalog(grantGroup("computer-process-control", action, mode)),
      enqueue: async () => { throw Error("wrong profile must not enqueue"); },
    });
    assert.equal((await wrong(actionRequest(action, args))).status, 403, action);
  }

  const bad: Array<[string, Record<string, unknown>]> = [
    ["computer.process_start", { argv: [] }],
    ["computer.process_start", { argv: ["node"], project: "made-up" }],
    ["computer.process_start", { argv: ["node"], wait_seconds: 20 }],
    ["computer.process_list", { project: "fake" }],
    ["computer.process_status", { process_id: "../escape" }],
    ["computer.process_logs", { process_id: proc, max_bytes: 99999999 }],
    ["computer.process_write_stdin", { process_id: proc, text: "A".repeat(66000) }],
    ["computer.process_stop", { process_id: "" }],
  ];
  for (const [action, args] of bad) {
    assert.equal(validAttestedDeviceActionArguments(action, args), false, action);
  }
});

test("device terminal requires its own Owner grant and no project binding", async () => {
  assert.equal(validAttestedDeviceActionArguments("computer.terminal_exec", {
    argv: ["node", "--version"], cwd: "C:\\\\projects", timeout_seconds: 30,
  }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.terminal_exec", {
    argv: ["node"], command: "echo unsafe", shell: true,
  }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.terminal_exec", {
    argv: [], timeout_seconds: 0,
  }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.terminal_exec", {
    command: "echo ok", shell: true,
  }), true);
  let calls = 0;
  const args = { argv: ["node", "--version"] };
  const granted = createAttestedDeviceActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => catalog(grantGroup("device-native-terminal", "computer.terminal_exec", "write")),
    enqueue: async (_env, input) => {
      calls += 1;
      assert.equal(input.capability, "computer.terminal_exec");
      assert.equal(input.projectId, null);
      assert.equal(input.accessMode, "write");
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
  });
  assert.equal((await granted(actionRequest("computer.terminal_exec", args))).status, 202);
  assert.equal(calls, 1);
  const denied = createAttestedDeviceActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => catalog(grantGroup("computer-filesystem", "computer.terminal_exec", "write")),
    enqueue: async () => { throw Error("must not enqueue"); },
  });
  assert.equal((await denied(actionRequest("computer.terminal_exec", args))).status, 403);
});

test("attested device argument allowlist covers observation, interactive and promoted safe reads", () => {
  assert.equal(validAttestedDeviceActionArguments("computer.access_status", {}), true);
  assert.equal(validAttestedDeviceActionArguments("computer.active_window", {}), true);
  assert.equal(validAttestedDeviceActionArguments("computer.screen_info", {}), true);
  assert.equal(validAttestedDeviceActionArguments("computer.windows", { max_items: 100 }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.processes", { query: "node", max_items: 50 }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.screenshot", { mode: "desktop" }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.focus_window", { handle: "0x1234" }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.click", { x: 20, y: 30, button: "left", clicks: 2 }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.mouse_move", { x: -10, y: 40, duration_ms: 250 }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.drag", {
    from_x: 1, from_y: 2, to_x: 3, to_y: 4, duration_ms: 100,
  }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.launch_app", { application: "notepad.exe", args: [] }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.scroll", { amount: -3, horizontal: false }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.type", { text: "hello" }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.hotkey", { keys: ["CTRL", "L"] }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.clipboard_read", { max_bytes: 4096 }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.file_stat", { path: "C:\\work\\file.txt" }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.directory_list", {
    path: "C:\\work", max_depth: 2, max_entries: 200, include_hidden: false,
  }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.text_read", {
    path: "C:\\work\\file.txt", start_line: 10, end_line: 20,
  }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.search", {
    root: "C:\\work", query: "needle", mode: "both", max_results: 20, max_depth: 4,
  }), true);

  assert.equal(validAttestedDeviceActionArguments("computer.clipboard_write", { text: "hello" }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.clipboard_write", { text: "" }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.clipboard_write", { text: "x".repeat(8193) }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.clipboard_write", { text: "📝".repeat(2100) }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.clipboard_write", { text: "x", extra: true }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.terminate_process",
    { pid: 1234, expected_name: "notepad.exe", force: false, tree: false }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.terminate_process",
    { pid: 0, expected_name: "notepad.exe" }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.terminate_process",
    { pid: 1234, expected_name: "" }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.terminate_process",
    { pid: 1234, expected_name: "notepad.exe", force: "yes" }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.directory_create", {
    path: "C:\\work\\new", parents: true,
  }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.path_move", {
    source: "C:\\work\\old.txt", destination: "C:\\work\\new.txt",
    expected_sha256: "a".repeat(64),
  }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.path_remove", {
    path: "C:\\work\\old.txt", recursive: false,
  }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.path_move", {
    source: "same", destination: "same",
  }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.path_remove", {
    path: "x", recursive: "true",
  }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.path_move", {
    source: "x", destination: "y", expected_sha256: "not-a-hash",
  }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.text_write", { path: "x", content: "no" }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.text_write", { path: "x", content: "new", create: true }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.text_write", { path: "x", content: "updated", expected_sha256: "a".repeat(64) }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.text_patch", {
    path: "x", expected_sha256: "a".repeat(64), replacements: [{ old: "before", new: "after", expected_count: 1 }],
  }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.text_write", { path: "x", content: "changed", expected_sha256: "A".repeat(64) }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.text_write", { path: "x", content: ("bad" + String.fromCharCode(0) + "text"), create: true }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.text_write", { path: "x", content: "x".repeat(8193), create: true }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.text_patch", {
    path: "x", expected_sha256: "a".repeat(64), replacements: Array.from({ length: 17 }, () => ({ old: "x", new: "y" })),
  }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.text_patch", {
    path: "x", expected_sha256: "a".repeat(64), replacements: [{ old: "x", new: "y", extra: "no" }],
  }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.click", { x: 1, y: 2, extra: true }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.hotkey", { keys: [] }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.scroll", { amount: 101 }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.text_read", { path: "x", start_line: 20, end_line: 10 }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.clipboard_read", { max_bytes: 1_048_577 }), false);
});

test("observation enqueue remains least-privilege read authority", async () => {
  let observed: any = null;
  const handler = createAttestedDeviceActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => catalog(grantGroup("computer-observe", "computer.windows", "read")),
    enqueue: async (_env, input) => {
      observed = input;
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    now: () => 1_700_000_000_000,
    operationId: () => OPERATION,
  });
  const response = await handler(actionRequest("computer.windows", { max_items: 25 }));
  assert.equal(response.status, 202);
  assert.equal(observed.deviceId, DEVICE);
  assert.equal(observed.capability, "computer.windows");
  assert.equal(observed.accessMode, "read");
  assert.deepEqual(observed.payload, { max_items: 25 });
  assert.equal(observed.idempotencyKey, `mcp-read-${OPERATION}`);
});

test("promoted filesystem read uses the dedicated filesystem profile", async () => {
  let observed: any = null;
  const handler = createAttestedDeviceActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => catalog(grantGroup("computer-filesystem", "computer.text_read", "read")),
    enqueue: async (_env, input) => {
      observed = input;
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    operationId: () => OPERATION,
  });
  const response = await handler(actionRequest("computer.text_read", { path: "C:\\work\\readme.txt" }));
  assert.equal(response.status, 202);
  assert.equal(observed.capability, "computer.text_read");
  assert.equal(observed.accessMode, "read");
  assert.deepEqual(observed.payload, { path: "C:\\work\\readme.txt" });
});

test("typed text create and patch are independently granted and preserve write scope", async () => {
  for (const [action, args] of [
    ["computer.text_write", { path: "/safe/notes.txt", content: "created", create: true }],
    ["computer.text_patch", { path: "/safe/notes.txt", expected_sha256: "a".repeat(64), replacements: [{ old: "old", new: "new" }] }],
  ] as const) {
    let observed: any = null;
    const handler = createAttestedDeviceActionHandler(ENV, TRUSTED, {
      authenticate: identity,
      listTargets: async () => catalog(grantGroup("computer-text-edit", action, "write")),
      enqueue: async (_env, input) => {
        observed = input;
        return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
      },
      operationId: () => OPERATION,
    });
    const response = await handler(actionRequest(action, args));
    assert.equal(response.status, 202, action);
    assert.equal(observed.capability, action);
    assert.equal(observed.accessMode, "write");
    assert.equal(observed.projectId, null);
    assert.equal(observed.deviceId, DEVICE);
    assert.equal(observed.idempotencyKey, `mcp-write-${OPERATION}`);
    assert.deepEqual(observed.payload, args);
  }
});

test("computer-text-edit cannot borrow observation, interactive or wrong access mode", () => {
  for (const action of ["computer.text_write", "computer.text_patch"]) {
    for (const group of [
      grantGroup("computer-observe", action, "write"),
      grantGroup("interactive-computer-control", action, "write"),
      grantGroup("computer-text-edit", action, "read"),
    ]) {
      assert.equal(catalogAllowsAttestedDeviceAction(catalog(group), DEVICE, action), false, group.profile_key);
    }
    assert.equal(catalogAllowsAttestedDeviceAction(
      catalog(grantGroup("computer-text-edit", action, "write")), DEVICE, action,
    ), true);
    assert.equal(catalogAllowsAttestedDeviceAction(
      catalog(grantGroup("computer-filesystem", action, "write")), DEVICE, action,
    ), true); // explicitly granted legacy superset, not an automatic grant
  }
});

test("promoted clipboard read uses the dedicated clipboard profile", async () => {
  let observed: any = null;
  const handler = createAttestedDeviceActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => catalog(grantGroup("computer-clipboard", "computer.clipboard_read", "read")),
    enqueue: async (_env, input) => {
      observed = input;
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    operationId: () => OPERATION,
  });
  const response = await handler(actionRequest("computer.clipboard_read", { max_bytes: 8192 }));
  assert.equal(response.status, 202);
  assert.equal(observed.capability, "computer.clipboard_read");
  assert.equal(observed.accessMode, "read");
});

test("interactive write enqueue requires interactive profile and preserves write access mode", async () => {
  let observed: any = null;
  const handler = createAttestedDeviceActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => catalog(grantGroup("interactive-computer-control", "computer.click", "write")),
    enqueue: async (_env, input) => {
      observed = input;
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    operationId: () => OPERATION,
  });
  const response = await handler(actionRequest("computer.click", { x: 100, y: 200 }));
  assert.equal(response.status, 202);
  assert.equal(observed.capability, "computer.click");
  assert.equal(observed.accessMode, "write");
  assert.deepEqual(observed.payload, { x: 100, y: 200 });
  assert.equal(observed.idempotencyKey, `mcp-write-${OPERATION}`);
});

test("interactive screenshot stays read-mode but cannot borrow computer-observe", async () => {
  assert.equal(catalogAllowsAttestedDeviceAction(
    catalog(grantGroup("computer-observe", "computer.screenshot", "read")),
    DEVICE,
    "computer.screenshot",
  ), false);
  assert.equal(catalogAllowsAttestedDeviceAction(
    catalog(grantGroup("interactive-computer-control", "computer.screenshot", "read")),
    DEVICE,
    "computer.screenshot",
  ), true);
});

test("filesystem and clipboard reads cannot borrow observation or interactive grants", () => {
  assert.equal(catalogAllowsAttestedDeviceAction(
    catalog(grantGroup("computer-observe", "computer.text_read", "read")),
    DEVICE,
    "computer.text_read",
  ), false);
  assert.equal(catalogAllowsAttestedDeviceAction(
    catalog(grantGroup("interactive-computer-control", "computer.clipboard_read", "read")),
    DEVICE,
    "computer.clipboard_read",
  ), false);
  assert.equal(catalogAllowsAttestedDeviceAction(
    catalog(grantGroup("computer-filesystem", "computer.text_read", "read")),
    DEVICE,
    "computer.text_read",
  ), true);
  assert.equal(catalogAllowsAttestedDeviceAction(
    catalog(grantGroup("computer-clipboard", "computer.clipboard_read", "read")),
    DEVICE,
    "computer.clipboard_read",
  ), true);
});

test("overlapping observe and interactive groups remain deterministic", () => {
  const mixed = catalog(
    grantGroup("computer-observe", "computer.windows", "read"),
    grantGroup("interactive-computer-control", "computer.click", "write"),
  );
  assert.equal(catalogAllowsAttestedDeviceAction(mixed, DEVICE, "computer.windows"), true);
  assert.equal(catalogAllowsAttestedDeviceAction(mixed, DEVICE, "computer.click"), true);
});

test("full-computer-control is an explicit alternative authority for published actions", () => {
  assert.equal(catalogAllowsAttestedDeviceAction(
    catalog(grantGroup("full-computer-control", "computer.hotkey", "write")),
    DEVICE,
    "computer.hotkey",
  ), true);
  assert.equal(catalogAllowsAttestedDeviceAction(
    catalog(grantGroup("full-computer-control", "computer.text_read", "read")),
    DEVICE,
    "computer.text_read",
  ), true);
});

test("explicit Space never borrows a global device grant (#118)", async () => {
  const unauthorizedSpace = "782c01a5-0ee3-4589-9f9b-11555191f35a";
  let catalogReads = 0;
  let enqueues = 0;
  const handler = createAttestedDeviceActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => {
      catalogReads++;
      return catalog(grantGroup("computer-observe", "computer.screen_info", "read"));
    },
    enqueue: async () => {
      enqueues++;
      throw new Error("explicit ungranted Space must never dispatch");
    },
  });
  const base = await actionRequest("computer.screen_info").json() as Record<string, unknown>;
  for (const mutation of [
    { space_id: unauthorizedSpace },  // Canonical UUID previously accepted with only global grants.
    { space_id: "not-a-uuid" },
    { project: "ordaxsystems/ordax-platform" },
    { space_id: undefined }, // Missing scope must not be treated as an implicit global grant.
  ]) {
    const body = { ...base, ...mutation };
    if (mutation.space_id === undefined && Object.hasOwn(mutation, "space_id")) delete body.space_id;
    const response = await handler(new Request("https://mcp.example/v3/product/actions", {
      method: "POST",
      headers: { authorization: "Bearer test", "content-type": "application/json" },
      body: JSON.stringify(body),
    }));
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { ok: false, error: "product_device_action_invalid" });
  }
  assert.equal(catalogReads, 0);
  assert.equal(enqueues, 0);
});

test("model-selected device never overrides the attested Product device", async () => {
  let touched = false;
  const handler = createAttestedDeviceActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => { touched = true; return catalog(); },
    enqueue: async () => { touched = true; throw new Error("must not enqueue"); },
  });
  const other = "66666666-6666-4666-8666-666666666666";
  const response = await handler(actionRequest("computer.click", { x: 1, y: 2 }, other));
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), {
    ok: false,
    error: "product_attested_device_mismatch",
    required_action: "establish_attested_session_for_requested_device",
  });
  assert.equal(touched, false);
});

test("missing grant returns the capability family's owner remediation without enqueue", async () => {
  for (const [action, args, expectedProfile] of [
    ["computer.windows", {}, "computer-observe"],
    ["computer.click", { x: 1, y: 2 }, "interactive-computer-control"],
    ["computer.screenshot", {}, "interactive-computer-control"],
    ["computer.text_read", { path: "C:\\work\\x.txt" }, "computer-text-edit"],
    ["computer.text_write", { path: "/safe/new.txt", content: "new", create: true }, "computer-text-edit"],
    ["computer.text_patch", { path: "/safe/x.txt", expected_sha256: "a".repeat(64), replacements: [{ old: "x", new: "y" }] }, "computer-text-edit"],
    ["computer.clipboard_read", {}, "computer-clipboard"],
  ] as const) {
    let enqueued = false;
    const handler = createAttestedDeviceActionHandler(ENV, TRUSTED, {
      authenticate: identity,
      listTargets: async () => catalog(grantGroup("computer-observe", "computer.active_window", "read")),
      enqueue: async () => { enqueued = true; throw new Error("must not enqueue"); },
    });
    const response = await handler(actionRequest(action, args));
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), {
      ok: false,
      error: "product_grant_not_resolved",
      required_profile: expectedProfile,
      owner_action: "authorize_in_ordax_owner_permissions",
    });
    assert.equal(enqueued, false);
  }
});

test("OAuth owner mismatch and unpublished mutation capability both fail closed", async () => {
  const wrongIdentity = async () => ({
    ok: true as const,
    ownerUserId: "77777777-7777-4777-8777-777777777777",
    clientKind: "product-mcp" as const,
    clientId: CLIENT,
    expiresAt: 2_000_000_000,
  });
  const mismatch = createAttestedDeviceActionHandler(ENV, TRUSTED, { authenticate: wrongIdentity });
  const denied = await mismatch(actionRequest("computer.click", { x: 1, y: 2 }));
  assert.equal(denied.status, 403);
  assert.equal((await denied.json()).error, "trusted_operation_required");

  const unpublished = createAttestedDeviceActionHandler(ENV, TRUSTED, { authenticate: identity });
  const blocked = await unpublished(actionRequest("computer.activity_status", {}));
  assert.equal(blocked.status, 400);
  assert.equal((await blocked.json()).error, "product_device_action_invalid");
});

test("canonical filesystem owner grant dispatches typed create move remove as writes", async () => {
  for (const [action, args] of [
    ["computer.directory_create", { path: "C:/scratch/new", parents: true }],
    ["computer.path_move", { source: "C:/scratch/a", destination: "C:/scratch/b", overwrite: false }],
    ["computer.path_remove", { path: "C:/scratch/a", recursive: false }],
  ] as const) {
    let observed: any = null;
    const handler = createAttestedDeviceActionHandler(ENV, TRUSTED, {
      authenticate: identity,
      listTargets: async () => catalog(grantGroup("computer-filesystem", action, "write")),
      enqueue: async (_env, input) => {
        observed = input;
        return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
      },
      operationId: () => OPERATION,
    });
    const response = await handler(actionRequest(action, args));
    assert.equal(response.status, 202, action);
    assert.equal(observed.capability, action);
    assert.equal(observed.accessMode, "write");
    assert.equal(observed.deviceId, DEVICE);
    assert.equal(observed.projectId, null);
    assert.deepEqual(observed.payload, args);
  }
});

test("filesystem mutation rejects read grants, observation grants and unsigned device context", async () => {
  for (const action of ["computer.directory_create", "computer.path_move", "computer.path_remove"]) {
    assert.equal(catalogAllowsAttestedDeviceAction(
      catalog(grantGroup("computer-filesystem", action, "read")), DEVICE, action), false);
    assert.equal(catalogAllowsAttestedDeviceAction(
      catalog(grantGroup("computer-observe", action, "write")), DEVICE, action), false);
    assert.equal(catalogAllowsAttestedDeviceAction(
      catalog(grantGroup("full-computer-control", action, "write")), DEVICE, action), true);
  }
  let dispatched = false;
  const denied = createAttestedDeviceActionHandler(ENV, null, {
    authenticate: identity,
    enqueue: async () => {
      dispatched = true;
      throw new Error("must_not_dispatch");
    },
  });
  const response = await denied(actionRequest("computer.path_remove", { path: "C:/scratch/important" }));
  assert.equal(response.status, 403);
  assert.equal(dispatched, false);
});

test("Owner clipboard and guarded process control enqueue exact write authority", async () => {
  for (const [action, args, profile] of [
    ["computer.clipboard_write", { text: "hello from owner" }, "computer-clipboard"],
    ["computer.terminate_process", { pid: 4321, expected_name: "notepad.exe", force: false, tree: false }, "computer-process-control"],
  ] as const) {
    let observed: any = null;
    const handler = createAttestedDeviceActionHandler(ENV, TRUSTED, {
      authenticate: identity,
      listTargets: async () => catalog(grantGroup(profile, action, "write")),
      enqueue: async (_env, input) => {
        observed = input;
        return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
      },
      operationId: () => OPERATION,
    });
    const response = await handler(actionRequest(action, args));
    assert.equal(response.status, 202, action);
    assert.equal(observed.capability, action);
    assert.equal(observed.accessMode, "write");
    assert.equal(observed.deviceId, DEVICE);
    assert.deepEqual(observed.payload, args);
    assert.equal(catalogAllowsAttestedDeviceAction(
      catalog(grantGroup(profile, action, "read")), DEVICE, action), false);
    assert.equal(catalogAllowsAttestedDeviceAction(
      catalog(grantGroup("computer-observe", action, "write")), DEVICE, action), false);
    assert.equal(catalogAllowsAttestedDeviceAction(
      catalog(grantGroup("full-computer-control", action, "write")), DEVICE, action), true);
  }
});

test("Orchestrator status enqueues only a dedicated read grant with no model identity or path", async () => {
  const action = "orchestrator.app_read";
  assert.equal(validAttestedDeviceActionArguments(action, {}), true);
  for (const args of [{ path: "C:/fake" }, { grant_id: OWNER }, { operation: "tasks.create" }]) {
    assert.equal(validAttestedDeviceActionArguments(action, args), false);
  }
  let calls = 0;
  const handler = createAttestedDeviceActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => catalog(grantGroup("orchestrator-app-read", action, "read")),
    enqueue: async (_env, input) => {
      calls++;
      assert.equal(input.capability, action);
      assert.equal(input.projectId, null);
      assert.equal(input.accessMode, "read");
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
  });
  assert.equal((await handler(actionRequest(action))).status, 202);
  assert.equal(calls, 1);
  for (const profile of ["computer-full-control", "computer-read", "device-native-process"]) {
    const denied = createAttestedDeviceActionHandler(ENV, TRUSTED, {
      authenticate: identity,
      listTargets: async () => catalog(grantGroup(profile, action, "read")),
      enqueue: async () => { throw Error("wrong authority must not enqueue"); },
    });
    assert.equal((await denied(actionRequest(action))).status, 403);
  }
});

test("cross-device request requires target attestation before grant lookup or dispatch", async () => {
  const other = "99999999-9999-4999-8999-999999999999";
  let catalogQueries = 0;
  let enqueues = 0;
  const handler = createAttestedDeviceActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => {
      catalogQueries++;
      return catalog(grantGroup("full-computer-control", "computer.terminal_exec", "write"));
    },
    enqueue: async () => {
      enqueues++;
      throw Error("must_not_enqueue");
    },
  });

  const response = await handler(actionRequest("computer.terminal_exec", { argv: ["id"] }, other));
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), {
    ok: false,
    error: "product_attested_device_mismatch",
    required_action: "establish_attested_session_for_requested_device",
  });
  assert.equal(catalogQueries, 0);
  assert.equal(enqueues, 0);

  const malformed = await handler(actionRequest("computer.terminal_exec", { argv: [] }));
  assert.equal(malformed.status, 400);
  assert.equal((await malformed.json()).error, "product_device_action_invalid");
  assert.equal(catalogQueries, 0);
});
