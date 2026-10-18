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
    required_profile: "project-native-terminal", owner_action: "authorize_in_ordax_studio",
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
