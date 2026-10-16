import assert from "node:assert/strict";
import test from "node:test";
import {
  createAttestedDeviceReadActionHandler,
  validAttestedDeviceReadArguments,
} from "../cloudflare/src/product_mcp_attested_device_read.ts";

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

function readCatalog(capability = "computer.windows", access_mode = "read") {
  return {
    ok: true,
    targets: [{
      device_id: DEVICE,
      grant_groups: [{
        profile_key: "computer-observe",
        space_id: null,
        project_id: null,
        valid_until: null,
        capabilities: [{ capability, access_mode }],
      }],
    }],
  };
}

const identity = async () => ({
  ok: true as const,
  ownerUserId: OWNER,
  clientKind: "product-mcp" as const,
  clientId: CLIENT,
  expiresAt: 2_000_000_000,
});

test("attested device read arguments expose only the five observation shapes", () => {
  assert.equal(validAttestedDeviceReadArguments("computer.access_status", {}), true);
  assert.equal(validAttestedDeviceReadArguments("computer.active_window", {}), true);
  assert.equal(validAttestedDeviceReadArguments("computer.screen_info", {}), true);
  assert.equal(validAttestedDeviceReadArguments("computer.windows", { max_items: 100 }), true);
  assert.equal(validAttestedDeviceReadArguments("computer.processes", { query: "node", max_items: 50 }), true);
  assert.equal(validAttestedDeviceReadArguments("computer.screenshot", {}), false);
  assert.equal(validAttestedDeviceReadArguments("computer.click", {}), false);
  assert.equal(validAttestedDeviceReadArguments("computer.windows", { extra: true }), false);
  assert.equal(validAttestedDeviceReadArguments("computer.processes", { max_items: 1001 }), false);
});

test("successful read enqueue derives authority from attested session and current grant", async () => {
  let observed: any = null;
  const handler = createAttestedDeviceReadActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => readCatalog(),
    enqueue: async (_env, input) => {
      observed = input;
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    now: () => 1_700_000_000_000,
    operationId: () => OPERATION,
  });
  const response = await handler(actionRequest("computer.windows", { max_items: 25 }));
  const body = await response.json();
  assert.equal(response.status, 202);
  assert.deepEqual(body, {
    ok: true, request_id: REQUEST, effect_id: EFFECT, status: "queued", replayed: false,
  });
  assert.equal(observed.ownerUserId, OWNER);
  assert.equal(observed.clientId, CLIENT);
  assert.equal(observed.clientKind, "product-mcp");
  assert.equal(observed.deviceId, DEVICE);
  assert.equal(observed.spaceId, null);
  assert.equal(observed.projectId, null);
  assert.equal(observed.capability, "computer.windows");
  assert.equal(observed.accessMode, "read");
  assert.deepEqual(observed.payload, { max_items: 25 });
  assert.equal(observed.idempotencyKey, `mcp-read-${OPERATION}`);
});

test("model-selected device never overrides the attested Product device", async () => {
  let touched = false;
  const handler = createAttestedDeviceReadActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => { touched = true; return readCatalog(); },
    enqueue: async () => { touched = true; throw new Error("must not enqueue"); },
  });
  const other = "66666666-6666-4666-8666-666666666666";
  const response = await handler(actionRequest("computer.windows", {}, other));
  const body = await response.json();
  assert.equal(response.status, 400);
  assert.equal(body.error, "product_read_action_invalid");
  assert.equal(touched, false);
});

test("missing or write-mode observation grant fails closed with canonical owner remediation", async () => {
  for (const catalog of [
    { ok: true, targets: [{ device_id: DEVICE, grant_groups: [] }] },
    readCatalog("computer.windows", "write"),
  ]) {
    let enqueued = false;
    const handler = createAttestedDeviceReadActionHandler(ENV, TRUSTED, {
      authenticate: identity,
      listTargets: async () => catalog,
      enqueue: async () => { enqueued = true; throw new Error("must not enqueue"); },
    });
    const response = await handler(actionRequest("computer.windows"));
    const body = await response.json();
    assert.equal(response.status, 403);
    assert.deepEqual(body, {
      ok: false,
      error: "product_grant_not_resolved",
      required_profile: "computer-observe",
      owner_action: "authorize_in_ordax_studio",
    });
    assert.equal(enqueued, false);
  }
});

test("enqueue and PostgreSQL grant rejection use the same canonical remediation", async () => {
  const expected = {
    ok: false,
    error: "product_grant_not_resolved",
    required_profile: "computer-observe",
    owner_action: "authorize_in_ordax_studio",
  };

  const rejected = createAttestedDeviceReadActionHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => readCatalog(),
    enqueue: async () => ({ ok: false as const, error: "product_grant_not_resolved" as const }),
  });
  const response = await rejected(actionRequest("computer.windows"));
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), expected);
});

test("OAuth owner/client mismatch and mutating capability both fail closed", async () => {
  const wrongIdentity = async () => ({
    ok: true as const,
    ownerUserId: "77777777-7777-4777-8777-777777777777",
    clientKind: "product-mcp" as const,
    clientId: CLIENT,
    expiresAt: 2_000_000_000,
  });
  const mismatch = createAttestedDeviceReadActionHandler(ENV, TRUSTED, {
    authenticate: wrongIdentity,
  });
  const denied = await mismatch(actionRequest("computer.windows"));
  assert.equal(denied.status, 403);
  assert.equal((await denied.json()).error, "trusted_operation_required");

  const mutation = createAttestedDeviceReadActionHandler(ENV, TRUSTED, {
    authenticate: identity,
  });
  const blocked = await mutation(actionRequest("computer.click"));
  assert.equal(blocked.status, 400);
  assert.equal((await blocked.json()).error, "product_read_action_invalid");
});
