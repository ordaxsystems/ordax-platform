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
const REPOSITORY = "ordaxsystems/ordax-gpt";
const ENV = Object.freeze({});
const TRUSTED = Object.freeze({ ownerUserId: OWNER, clientId: CLIENT, deviceId: DEVICE });
const SCOPE = Object.freeze({ spaceId: SPACE, projectId: PROJECT, repositoryFullName: REPOSITORY });

const identity = async () => ({
  ok: true as const,
  ownerUserId: OWNER,
  clientKind: "product-mcp" as const,
  clientId: CLIENT,
  expiresAt: 2_000_000_000,
});

const resolveProject = async () => ({
  ok: true,
  space_id: SPACE,
  project_id: PROJECT,
  repository_id: 42,
  repository_full_name: REPOSITORY,
});

function actionRequest(
  action: string,
  args: Record<string, unknown> = {},
  options: { deviceId?: string; project?: string; spaceId?: string | null } = {},
) {
  return new Request("https://mcp.example/v3/product/actions", {
    method: "POST",
    headers: { authorization: "Bearer test", "content-type": "application/json" },
    body: JSON.stringify({
      device_id: options.deviceId ?? DEVICE,
      space_id: options.spaceId ?? null,
      action,
      project: options.project ?? REPOSITORY,
      arguments: args,
    }),
  });
}

function grantGroup(
  capability: string,
  access_mode: "read" | "write",
  options: { projectId?: string; spaceId?: string; profile?: string; validUntil?: string | null } = {},
) {
  return {
    profile_key: options.profile ?? "project-continuity",
    space_id: options.spaceId ?? SPACE,
    project_id: options.projectId ?? PROJECT,
    valid_until: options.validUntil ?? null,
    capabilities: [{ capability, access_mode }],
  };
}

function catalog(...groups: ReturnType<typeof grantGroup>[]) {
  return { ok: true, targets: [{ device_id: DEVICE, grant_groups: groups }] };
}

test("project continuity exposes only bounded briefing/get/update argument shapes", () => {
  assert.equal(validAttestedProjectActionArguments("agent.project_briefing", {}), true);
  assert.equal(validAttestedProjectActionArguments("agent.project_briefing", { query: "continue", recall_limit: 10 }), true);
  assert.equal(validAttestedProjectActionArguments("continuity.get", {}), true);
  assert.equal(validAttestedProjectActionArguments("continuity.update", { summary: "checkpoint" }), true);
  assert.equal(validAttestedProjectActionArguments("continuity.update", {
    summary: "checkpoint",
    next_action: "test",
    completed: ["a"],
    blockers: [],
    changed_paths: ["src/a.ts"],
  }), true);

  assert.equal(validAttestedProjectActionArguments("continuity.update", {}), false);
  assert.equal(validAttestedProjectActionArguments("continuity.get", { extra: true }), false);
  assert.equal(validAttestedProjectActionArguments("project.text_read", {}), false);
});

test("briefing enqueue binds canonical project UUID and hidden repository attestation", async () => {
  let observed: any = null;
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject,
    listTargets: async () => catalog(grantGroup("agent.project_briefing", "read")),
    enqueue: async (_env, input) => {
      observed = input;
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    now: () => 1_700_000_000_000,
    operationId: () => OPERATION,
  });

  const response = await handler(actionRequest("agent.project_briefing", { query: "resume", recall_limit: 8 }));
  assert.equal(response.status, 202);
  assert.equal(observed.deviceId, DEVICE);
  assert.equal(observed.spaceId, SPACE);
  assert.equal(observed.projectId, PROJECT);
  assert.equal(observed.capability, "agent.project_briefing");
  assert.equal(observed.accessMode, "read");
  assert.equal(observed.idempotencyKey, `mcp-project-read-${OPERATION}`);
  assert.deepEqual(observed.payload, {
    query: "resume",
    recall_limit: 8,
    _ordax_project_scope: {
      project_id: PROJECT,
      repository_full_name: REPOSITORY,
    },
  });
  assert.equal(Object.hasOwn(observed.payload, "project"), false);
});

test("continuity update is write authority and cannot borrow a read grant", async () => {
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("continuity.update", "read")),
    DEVICE,
    SCOPE,
    "continuity.update",
  ), false);
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("continuity.update", "write")),
    DEVICE,
    SCOPE,
    "continuity.update",
  ), true);

  let observed: any = null;
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject,
    listTargets: async () => catalog(grantGroup("continuity.update", "write")),
    enqueue: async (_env, input) => {
      observed = input;
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    operationId: () => OPERATION,
  });
  const response = await handler(actionRequest("continuity.update", { summary: "durable checkpoint" }));
  assert.equal(response.status, 202);
  assert.equal(observed.accessMode, "write");
  assert.equal(observed.idempotencyKey, `mcp-project-write-${OPERATION}`);
});

test("project grant must match the exact resolved Space and project pair", () => {
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("continuity.get", "read")), DEVICE, SCOPE, "continuity.get",
  ), true);
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("continuity.get", "read", { projectId: "88888888-8888-4888-8888-888888888888" })),
    DEVICE, SCOPE, "continuity.get",
  ), false);
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("continuity.get", "read", { spaceId: "99999999-9999-4999-8999-999999999999" })),
    DEVICE, SCOPE, "continuity.get",
  ), false);
  assert.equal(catalogAllowsAttestedProjectAction(
    catalog(grantGroup("continuity.get", "read", { profile: "project-browser-automation" })),
    DEVICE, SCOPE, "continuity.get",
  ), false);
});

test("model-selected device, invalid repository and conflicting Space fail before enqueue", async () => {
  let touched = false;
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject: async (...args) => { touched = true; return resolveProject(...args); },
    listTargets: async () => { touched = true; return catalog(); },
    enqueue: async () => { touched = true; throw new Error("must not enqueue"); },
  });

  const otherDevice = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  let response = await handler(actionRequest("continuity.get", {}, { deviceId: otherDevice }));
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "product_project_action_invalid");
  assert.equal(touched, false);

  response = await handler(actionRequest("continuity.get", {}, { project: "local-slug" }));
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "product_project_action_invalid");
  assert.equal(touched, false);

  touched = false;
  response = await handler(actionRequest("continuity.get", {}, {
    spaceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  }));
  assert.equal(response.status, 409);
  assert.equal((await response.json()).error, "product_project_scope_mismatch");
  assert.equal(touched, true);
});

test("missing or wrong project grant fails closed with explicit owner remediation", async () => {
  let enqueued = false;
  const handler = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject,
    listTargets: async () => catalog(grantGroup("continuity.get", "read", { profile: "project-browser-automation" })),
    enqueue: async () => { enqueued = true; throw new Error("must not enqueue"); },
  });
  const response = await handler(actionRequest("continuity.get"));
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), {
    ok: false,
    error: "product_grant_not_resolved",
    required_profile: "project-continuity",
    owner_action: "authorize_in_ordax_studio",
  });
  assert.equal(enqueued, false);
});

test("OAuth owner mismatch and unresolved canonical project both fail closed", async () => {
  const wrongIdentity = async () => ({
    ok: true as const,
    ownerUserId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    clientKind: "product-mcp" as const,
    clientId: CLIENT,
    expiresAt: 2_000_000_000,
  });
  const mismatch = createAttestedProjectActionHandler(ENV, TRUSTED, { authenticate: wrongIdentity });
  const denied = await mismatch(actionRequest("continuity.get"));
  assert.equal(denied.status, 403);
  assert.equal((await denied.json()).error, "trusted_operation_required");

  const unresolved = createAttestedProjectActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject: async () => ({ ok: false, error: "owner_project_scope_not_found" }),
  });
  const absent = await unresolved(actionRequest("continuity.get"));
  assert.equal(absent.status, 403);
  assert.equal((await absent.json()).error, "product_project_scope_not_found");
});
