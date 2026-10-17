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

  assert.equal(validAttestedDeviceActionArguments("computer.clipboard_write", { text: "no" }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.text_write", { path: "x", content: "no" }), false);
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

test("model-selected device never overrides the attested Product device", async () => {
  let touched = false;
  const handler = createAttestedDeviceActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => { touched = true; return catalog(); },
    enqueue: async () => { touched = true; throw new Error("must not enqueue"); },
  });
  const other = "66666666-6666-4666-8666-666666666666";
  const response = await handler(actionRequest("computer.click", { x: 1, y: 2 }, other));
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "product_device_action_invalid");
  assert.equal(touched, false);
});

test("missing grant returns the capability family's owner remediation without enqueue", async () => {
  for (const [action, args, expectedProfile] of [
    ["computer.windows", {}, "computer-observe"],
    ["computer.click", { x: 1, y: 2 }, "interactive-computer-control"],
    ["computer.screenshot", {}, "interactive-computer-control"],
    ["computer.text_read", { path: "C:\\work\\x.txt" }, "computer-filesystem"],
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
      owner_action: "authorize_in_ordax_studio",
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
  const blocked = await unpublished(actionRequest("computer.clipboard_write", { text: "no" }));
  assert.equal(blocked.status, 400);
  assert.equal((await blocked.json()).error, "product_device_action_invalid");
});
