import assert from "node:assert/strict";
import test from "node:test";
import {
  catalogAllowsAttestedProjectContinuityAction,
  createAttestedProjectContinuityHandler,
  validAttestedProjectContinuityArguments,
} from "../cloudflare/src/product_mcp_attested_project_continuity.ts";

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

const identity = async () => ({
  ok: true as const,
  ownerUserId: OWNER,
  clientKind: "product-mcp" as const,
  clientId: CLIENT,
  expiresAt: 2_000_000_000,
});

function actionRequest(action: string, args: Record<string, unknown>, deviceId = DEVICE) {
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
  capability: string,
  access_mode: "read" | "write",
  overrides: Record<string, unknown> = {},
) {
  return {
    profile_key: "project-continuity",
    space_id: SPACE,
    project_id: PROJECT,
    valid_until: null,
    capabilities: [{ capability, access_mode }],
    ...overrides,
  };
}

function catalog(...groups: ReturnType<typeof grantGroup>[]) {
  return { ok: true, targets: [{ device_id: DEVICE, grant_groups: groups }] };
}

const resolvedProject = async () => ({
  ok: true,
  space_id: SPACE,
  project_id: PROJECT,
  repository_id: 123,
  repository_full_name: "OrdaXSystems/ordax-gpt",
});

test("continuity argument contracts are repository-bound and reject caller-injected authority", () => {
  assert.equal(validAttestedProjectContinuityArguments("continuity.get", {
    repository_full_name: REPOSITORY,
  }), true);
  assert.equal(validAttestedProjectContinuityArguments("agent.project_briefing", {
    repository_full_name: REPOSITORY, query: "continue", recall_limit: 10,
  }), true);
  assert.equal(validAttestedProjectContinuityArguments("continuity.update", {
    repository_full_name: REPOSITORY, summary: "done", completed: ["one"],
  }), true);
  assert.equal(validAttestedProjectContinuityArguments("handoff.create", {
    repository_full_name: REPOSITORY, summary: "handoff", ttl_hours: 24,
  }), true);
  assert.equal(validAttestedProjectContinuityArguments("handoff.get", {
    repository_full_name: REPOSITORY, handoff_id: "handoff_123",
  }), true);

  assert.equal(validAttestedProjectContinuityArguments("continuity.get", {}), false);
  assert.equal(validAttestedProjectContinuityArguments("continuity.get", {
    repository_full_name: REPOSITORY,
    project_id: PROJECT,
  }), false);
  assert.equal(validAttestedProjectContinuityArguments("continuity.update", {
    repository_full_name: REPOSITORY,
    summary: "done",
    _ordax_project_scope: { project_id: PROJECT },
  }), false);
});

test("read continuity action resolves canonical project and injects immutable scope", async () => {
  let observed: any = null;
  const handler = createAttestedProjectContinuityHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject: resolvedProject,
    listTargets: async () => catalog(grantGroup("continuity.get", "read")),
    enqueue: async (_env, input) => {
      observed = input;
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    now: () => 1_700_000_000_000,
    operationId: () => OPERATION,
  });

  const response = await handler(actionRequest("continuity.get", { repository_full_name: REPOSITORY }));
  assert.equal(response.status, 202);
  assert.equal(observed.deviceId, DEVICE);
  assert.equal(observed.spaceId, SPACE);
  assert.equal(observed.projectId, PROJECT);
  assert.equal(observed.capability, "continuity.get");
  assert.equal(observed.accessMode, "read");
  assert.equal(observed.idempotencyKey, `mcp-read-${OPERATION}`);
  assert.deepEqual(observed.payload, {
    _ordax_project_scope: {
      project_id: PROJECT,
      repository_full_name: REPOSITORY,
    },
  });
});

test("write continuity action cannot borrow read authority", async () => {
  assert.equal(catalogAllowsAttestedProjectContinuityAction(
    catalog(grantGroup("continuity.update", "read")),
    DEVICE, SPACE, PROJECT, "continuity.update",
  ), false);
  assert.equal(catalogAllowsAttestedProjectContinuityAction(
    catalog(grantGroup("continuity.update", "write")),
    DEVICE, SPACE, PROJECT, "continuity.update",
  ), true);

  let observed: any = null;
  const handler = createAttestedProjectContinuityHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject: resolvedProject,
    listTargets: async () => catalog(grantGroup("continuity.update", "write")),
    enqueue: async (_env, input) => {
      observed = input;
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    operationId: () => OPERATION,
  });
  const response = await handler(actionRequest("continuity.update", {
    repository_full_name: REPOSITORY,
    summary: "checkpoint",
    next_action: "continue",
  }));
  assert.equal(response.status, 202);
  assert.equal(observed.accessMode, "write");
  assert.deepEqual(observed.payload, {
    summary: "checkpoint",
    next_action: "continue",
    _ordax_project_scope: {
      project_id: PROJECT,
      repository_full_name: REPOSITORY,
    },
  });
});

test("wrong project, wrong profile and expired grants all fail closed", () => {
  assert.equal(catalogAllowsAttestedProjectContinuityAction(
    catalog(grantGroup("continuity.get", "read", { project_id: "88888888-8888-4888-8888-888888888888" })),
    DEVICE, SPACE, PROJECT, "continuity.get",
  ), false);
  assert.equal(catalogAllowsAttestedProjectContinuityAction(
    catalog(grantGroup("continuity.get", "read", { profile_key: "project-browser-automation" })),
    DEVICE, SPACE, PROJECT, "continuity.get",
  ), false);
  assert.equal(catalogAllowsAttestedProjectContinuityAction(
    catalog(grantGroup("continuity.get", "read", { valid_until: "2000-01-01T00:00:00.000Z" })),
    DEVICE, SPACE, PROJECT, "continuity.get",
  ), false);
});

test("model-selected device and unresolved repository never reach enqueue", async () => {
  let enqueued = false;
  const handler = createAttestedProjectContinuityHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject: async () => ({ ok: false, error: "owner_project_scope_not_found" }),
    listTargets: async () => { throw new Error("must not list grants"); },
    enqueue: async () => { enqueued = true; throw new Error("must not enqueue"); },
  });

  const wrongDevice = await handler(actionRequest(
    "continuity.get",
    { repository_full_name: REPOSITORY },
    "99999999-9999-4999-8999-999999999999",
  ));
  assert.equal(wrongDevice.status, 400);
  assert.equal((await wrongDevice.json()).error, "product_project_continuity_action_invalid");

  const unresolved = await handler(actionRequest("continuity.get", { repository_full_name: REPOSITORY }));
  assert.equal(unresolved.status, 404);
  assert.equal((await unresolved.json()).error, "owner_project_scope_not_found");
  assert.equal(enqueued, false);
});

test("missing continuity grant returns explicit owner remediation", async () => {
  let enqueued = false;
  const handler = createAttestedProjectContinuityHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject: resolvedProject,
    listTargets: async () => catalog(grantGroup("continuity.get", "read")),
    enqueue: async () => { enqueued = true; throw new Error("must not enqueue"); },
  });
  const response = await handler(actionRequest("handoff.create", {
    repository_full_name: REPOSITORY,
    summary: "continue later",
  }));
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), {
    ok: false,
    error: "product_grant_not_resolved",
    required_profile: "project-continuity",
    owner_action: "authorize_in_ordax_owner_permissions",
  });
  assert.equal(enqueued, false);
});

test("repository resolver may not retarget continuity even with matching owner, Space and project", async () => {
  let grantLookups = 0;
  let enqueues = 0;
  const handler = createAttestedProjectContinuityHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject: async () => ({
      ok: true,
      space_id: SPACE,
      project_id: PROJECT,
      repository_full_name: "ordaxsystems/another-private-project",
    }),
    listTargets: async () => { grantLookups++; return catalog(grantGroup("continuity.get", "read")); },
    enqueue: async () => { enqueues++; throw new Error("must not enqueue"); },
  });
  const result = await handler(actionRequest("continuity.get", {
    repository_full_name: REPOSITORY,
  }));
  assert.equal(result.status, 409);
  assert.equal((await result.json()).error, "product_project_scope_mismatch");
  assert.equal(grantLookups, 0);
  assert.equal(enqueues, 0);
});

test("continuity denies foreign OAuth owner and caller-supplied Space before project resolution", async () => {
  let resolved = 0;
  const foreignOwner = createAttestedProjectContinuityHandler(ENV, TRUSTED, {
    authenticate: async () => ({
      ok: true as const,
      ownerUserId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      clientKind: "product-mcp" as const,
      clientId: CLIENT,
      expiresAt: 2_000_000_000,
    }),
    resolveProject: async () => { resolved++; return resolvedProject(); },
  });
  const ownerDenied = await foreignOwner(actionRequest("continuity.get", {
    repository_full_name: REPOSITORY,
  }));
  assert.equal(ownerDenied.status, 403);
  assert.equal((await ownerDenied.json()).error, "trusted_operation_required");

  const spaceHandler = createAttestedProjectContinuityHandler(ENV, TRUSTED, {
    authenticate: identity,
    resolveProject: async () => { resolved++; return resolvedProject(); },
  });
  const spaceDenied = await spaceHandler(new Request("https://mcp.example/v3/product/actions", {
    method: "POST",
    headers: { authorization: "Bearer test", "content-type": "application/json" },
    body: JSON.stringify({
      device_id: DEVICE, space_id: SPACE, project: null,
      action: "continuity.get", arguments: { repository_full_name: REPOSITORY },
    }),
  }));
  assert.equal(spaceDenied.status, 400);
  assert.equal((await spaceDenied.json()).error, "product_project_continuity_action_invalid");
  assert.equal(resolved, 0);
});
