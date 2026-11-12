import assert from "node:assert/strict";
import test from "node:test";
import {
  validAttestedDeviceActionArguments,
  createAttestedDeviceActionHandler,
} from "../cloudflare/src/product_mcp_attested_device_action.ts";
import { OWNER_MCP_GRANT_PROFILES, productCapabilityAccessMode } from "../cloudflare/src/product_owner_grant_profiles.ts";

const OWNER = "11111111-1111-4111-8111-111111111111";
const DEVICE = "22222222-2222-4222-8222-222222222222";
const REQUEST = "33333333-3333-4333-8333-333333333333";
const EFFECT = "44444444-4444-4444-8444-444444444444";
const CLIENT = "chatgpt-product-mcp";
const TRANSFER = "a".repeat(32);
const SHA = "a".repeat(64);

function actionRequest(action: string, args: Record<string, unknown>) {
  return new Request("https://mcp.example/v3/product/actions", {
    method: "POST",
    headers: { authorization: "Bearer test", "content-type": "application/json" },
    body: JSON.stringify({
      device_id: DEVICE, space_id: null, project: null, action, arguments: args,
    }),
  });
}

test("transfer tool contracts and strict fail-closed limits", () => {
  const specs: Array<[string, Record<string, unknown>, "read" | "write"]> = [
    ["computer.transfer_begin", { path: "C:\\data\\f.bin", size_bytes: 33554432,
      sha256: SHA, create: true }, "write"],
    ["computer.transfer_chunk", { transfer_id: TRANSFER, offset: 0,
      data_base64: "YQ==" }, "write"],
    ["computer.transfer_status", { transfer_id: TRANSFER }, "read"],
    ["computer.transfer_commit", { transfer_id: TRANSFER }, "write"],
    ["computer.transfer_abort", { transfer_id: TRANSFER }, "write"],
  ];
  for (const [action, args, mode] of specs) {
    assert.equal(validAttestedDeviceActionArguments(action, args), true, action);
    assert.equal(productCapabilityAccessMode(action), mode, action);
    const full = OWNER_MCP_GRANT_PROFILES["full-computer-control"].capabilities;
    assert.equal(full.some(x => x.capability === action && x.accessMode === mode), true);
    const least = OWNER_MCP_GRANT_PROFILES["computer-text-edit"].capabilities;
    assert.equal(least.some(x => x.capability === action && x.accessMode === mode), true);
    assert.equal(validAttestedDeviceActionArguments(action, { ...args, extra: 1 }), false);
  }
  assert.equal(validAttestedDeviceActionArguments("computer.transfer_chunk", {
    transfer_id: TRANSFER, offset: 0, text_utf8: "café e código 🧪",
  }), true);
  assert.equal(validAttestedDeviceActionArguments("computer.transfer_chunk", {
    transfer_id: TRANSFER, offset: 0, text_utf8: "x", data_base64: "YQ==",
  }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.transfer_begin", {
    path: "x", size_bytes: 33554433, sha256: SHA, create: true,
  }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.transfer_begin", {
    path: "x", size_bytes: 1, sha256: SHA,
  }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.transfer_chunk", {
    transfer_id: TRANSFER, offset: 0, data_base64: "a".repeat(65540),
  }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.transfer_chunk", {
    transfer_id: TRANSFER, offset: -1, data_base64: "YQ==",
  }), false);
  assert.equal(validAttestedDeviceActionArguments("computer.transfer_commit", {
    transfer_id: "../outside",
  }), false);
});

test("bounded chunk passes attested enqueue only with explicit live grant", async () => {
  let queued = 0;
  const validGroup = {
    profile_key: "computer-text-edit", space_id: null, project_id: null,
    valid_until: null, capabilities: [{ capability: "computer.transfer_chunk", access_mode: "write" }],
  };
  let allowed = true;
  const handler = createAttestedDeviceActionHandler({}, {
    ownerUserId: OWNER, deviceId: DEVICE, clientId: CLIENT,
  }, {
    authenticate: async () => ({
      ok: true as const, ownerUserId: OWNER, clientKind: "product-mcp" as const,
      clientId: CLIENT, expiresAt: 2000000000,
    }),
    listTargets: async () => ({ ok: true, targets: [{
      device_id: DEVICE, grant_groups: allowed ? [validGroup] : [],
    }] }) as any,
    enqueue: async (_env, input) => {
      queued++;
      assert.equal(input.capability, "computer.transfer_chunk");
      assert.equal(input.accessMode, "write");
      return { ok: true, replayed: false, request_id: REQUEST, effect_id: EFFECT, status: "queued" };
    },
    operationId: () => "55555555-5555-4555-8555-555555555555",
  });
  const args = { transfer_id: TRANSFER, offset: 0, data_base64: "A".repeat(65536) };
  const accepted = await handler(actionRequest("computer.transfer_chunk", args));
  assert.equal(accepted.status, 202);
  assert.equal(queued, 1);
  allowed = false;
  const denied = await handler(actionRequest("computer.transfer_chunk", {
    transfer_id: TRANSFER, offset: 0, data_base64: "YQ==",
  }));
  assert.equal(denied.status, 403);
  assert.equal(queued, 1);
});
