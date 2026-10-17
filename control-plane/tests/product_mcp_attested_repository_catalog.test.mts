import assert from "node:assert/strict";
import test from "node:test";
import {
  catalogAllowsRepositoryCatalog,
  createAttestedRepositoryCatalogHandler,
} from "../cloudflare/src/product_mcp_attested_repository_catalog.ts";

const OWNER = "11111111-1111-4111-8111-111111111111";
const DEVICE = "22222222-2222-4222-8222-222222222222";
const REQUEST = "33333333-3333-4333-8333-333333333333";
const EFFECT = "44444444-4444-4444-8444-444444444444";
const OPERATION = "55555555-5555-4555-8555-555555555555";
const CLIENT = "chatgpt-product-mcp";
const ENV = Object.freeze({});
const TRUSTED = Object.freeze({ ownerUserId: OWNER, clientId: CLIENT, deviceId: DEVICE });

const identity = async () => ({
  ok: true as const,
  ownerUserId: OWNER,
  clientKind: "product-mcp" as const,
  clientId: CLIENT,
  expiresAt: 2_000_000_000,
});

function request(deviceId = DEVICE, args: Record<string, unknown> = {}) {
  return new Request("https://mcp.example/v3/product/actions", {
    method: "POST",
    headers: { authorization: "Bearer test", "content-type": "application/json" },
    body: JSON.stringify({
      device_id: deviceId,
      space_id: null,
      action: "workspace.repository_catalog",
      project: null,
      arguments: args,
    }),
  });
}

function catalog(profile = "repository-catalog-read", access_mode: "read" | "write" = "read") {
  return {
    ok: true,
    targets: [{
      device_id: DEVICE,
      grant_groups: [{
        profile_key: profile,
        space_id: null,
        project_id: null,
        valid_until: null,
        capabilities: [{ capability: "workspace.repository_catalog", access_mode }],
      }],
    }],
  };
}

test("repository catalog requires exact least-privilege device grant", () => {
  assert.equal(catalogAllowsRepositoryCatalog(catalog(), DEVICE), true);
  assert.equal(catalogAllowsRepositoryCatalog(catalog("computer-observe"), DEVICE), false);
  assert.equal(catalogAllowsRepositoryCatalog(catalog("repository-catalog-read", "write"), DEVICE), false);
});

test("repository catalog enqueues read-only action for attested device", async () => {
  let observed: any = null;
  const handler = createAttestedRepositoryCatalogHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => catalog(),
    enqueue: async (_env, input) => {
      observed = input;
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    now: () => 1_700_000_000_000,
    operationId: () => OPERATION,
  });

  const response = await handler(request());
  assert.equal(response.status, 202);
  assert.equal(observed.deviceId, DEVICE);
  assert.equal(observed.spaceId, null);
  assert.equal(observed.projectId, null);
  assert.equal(observed.capability, "workspace.repository_catalog");
  assert.equal(observed.accessMode, "read");
  assert.deepEqual(observed.payload, {});
  assert.equal(observed.idempotencyKey, `mcp-read-${OPERATION}`);
});

test("repository catalog rejects model-selected device and extra arguments", async () => {
  let touched = false;
  const handler = createAttestedRepositoryCatalogHandler(ENV, TRUSTED, {
    authenticate: identity,
    listTargets: async () => { touched = true; return catalog(); },
    enqueue: async () => { touched = true; throw new Error("must not enqueue"); },
  });

  const wrongDevice = await handler(request("66666666-6666-4666-8666-666666666666"));
  assert.equal(wrongDevice.status, 400);
  assert.equal((await wrongDevice.json()).error, "product_repository_catalog_action_invalid");

  const extra = await handler(request(DEVICE, { query: "no" }));
  assert.equal(extra.status, 400);
  assert.equal((await extra.json()).error, "product_repository_catalog_action_invalid");
  assert.equal(touched, false);
});
