import assert from "node:assert/strict";
import test from "node:test";
import { ownerMcpGrantProfile, productCapabilityAccessMode } from "../cloudflare/src/product_owner_grant_profiles.ts";
import { DEVICE_SCOPED_ACTIONS } from "../cloudflare/src/product_action_scope.ts";
import {
  ATTESTED_MCP_DEVICE_ACTIONS,
  validAttestedDeviceActionArguments,
  catalogAllowsAttestedDeviceAction,
} from "../cloudflare/src/product_mcp_attested_device_action.ts";
import { PRODUCT_MCP_DIRECT_TOOLS } from "../cloudflare/src/product_mcp_entry.ts";

const DEVICE = "22222222-2222-4222-8222-222222222222";
const serial = "6699E36B";
function catalog(profile: string, action: string, access_mode: string) {
  return {
    ok: true,
    targets: [{
      device_id: DEVICE,
      grant_groups: [{
        profile_key: profile, space_id: null, project_id: null,
        valid_until: null, capabilities: [{ capability: action, access_mode }],
      }],
    }],
  };
}

test("USB media observations have a dedicated least-privilege grant, never inherited Computer Control", () => {
  const owner = ownerMcpGrantProfile("usb-media-read");
  assert.deepEqual(owner, {
    scope: "device",
    capabilities: [
      { capability: "usb.inspect", accessMode: "read" },
      { capability: "usb.list", accessMode: "read" },
    ],
  });
  for (const action of ["usb.list", "usb.inspect"]) {
    assert.equal(DEVICE_SCOPED_ACTIONS.has(action), true);
    assert.equal(ATTESTED_MCP_DEVICE_ACTIONS.has(action), true);
    assert.equal(productCapabilityAccessMode(action), "read");
    assert.equal(catalogAllowsAttestedDeviceAction(
      catalog("usb-media-read", action, "read"), DEVICE, action,
    ), true);
    for (const wrong of ["full-computer-control", "computer-observe", "device-native-terminal", "usb-media-read-extra"]) {
      assert.equal(catalogAllowsAttestedDeviceAction(catalog(wrong, action, "read"), DEVICE, action), false, wrong);
    }
    assert.equal(catalogAllowsAttestedDeviceAction(catalog("usb-media-read", action, "write"), DEVICE, action), false);
    for (const wrong of ["full-computer-control", "computer-observe", "device-native-terminal"]) {
      assert.equal(ownerMcpGrantProfile(wrong)?.capabilities.some(item => item.capability === action), false);
    }
  }
  assert.equal(PRODUCT_MCP_DIRECT_TOOLS.has("usb_list"), true);
  assert.equal(PRODUCT_MCP_DIRECT_TOOLS.has("usb_inspect"), true);
  assert.equal(PRODUCT_MCP_DIRECT_TOOLS.has("usb_update"), false);
  assert.equal(PRODUCT_MCP_DIRECT_TOOLS.has("usb_repair"), false);
});

test("USB Device actions reject paths, commands, write flags and untrusted device values", () => {
  assert.equal(validAttestedDeviceActionArguments("usb.list", {}), true);
  for (const bad of [{ disk_number: 1 }, { command: "powershell" }, { write: true }, { path: "D:" }]) {
    assert.equal(validAttestedDeviceActionArguments("usb.list", bad), false);
  }
  assert.equal(validAttestedDeviceActionArguments("usb.inspect", { disk_number: 1, serial }), true);
  for (const bad of [
    {}, { disk_number: 1 }, { disk_number: -1, serial }, { disk_number: 1000, serial },
    { disk_number: true, serial }, { disk_number: 1.5, serial },
    { disk_number: 1, serial: "" }, { disk_number: 1, serial: "C:\\unsafe" },
    { disk_number: 1, serial, path: "D:" }, { disk_number: 1, serial, activate: true },
    { disk_number: 1, serial, physical_write: true }, { disk_number: 1, serial, project: "spoof" },
  ]) {
    assert.equal(validAttestedDeviceActionArguments("usb.inspect", bad), false, JSON.stringify(bad));
  }
  assert.equal(validAttestedDeviceActionArguments("usb.update", {}), false);
  assert.equal(validAttestedDeviceActionArguments("usb.repair", {}), false);
});
