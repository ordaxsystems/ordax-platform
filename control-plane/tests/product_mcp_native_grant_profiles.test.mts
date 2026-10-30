import assert from "node:assert/strict";
import test from "node:test";
import { ownerMcpGrantProfile, productCapabilityAccessMode } from "../cloudflare/src/product_owner_grant_profiles.ts";

test("terminal grant cannot be inherited from local full-computer-control", () => {
  const owner = ownerMcpGrantProfile("full-computer-control");
  const terminal = ownerMcpGrantProfile("project-native-terminal");
  assert.equal(owner?.scope, "device");
  assert.equal(owner?.capabilities.some(c => c.capability === "terminal.exec"), false);
  assert.equal(terminal?.scope, "project");
  assert.deepEqual(terminal?.capabilities, [{ capability: "terminal.exec", accessMode: "write" }]);
});

test("supervisor grant retains independent read and write modes", () => {
  const supervisor = ownerMcpGrantProfile("project-native-process");
  assert.equal(supervisor?.scope, "project");
  assert.deepEqual(
    supervisor?.capabilities.map(c => [c.capability, c.accessMode]),
    [
      ["process.list", "read"], ["process.logs", "read"],
      ["process.start", "write"], ["process.status", "read"],
      ["process.stop", "write"], ["process.write_stdin", "write"],
    ],
  );
  for (const capability of ["terminal.exec", "process.start", "process.write_stdin", "process.stop"]) {
    assert.equal(productCapabilityAccessMode(capability), "write", capability);
  }
  for (const capability of ["process.list", "process.logs", "process.status"]) {
    assert.equal(productCapabilityAccessMode(capability), "read", capability);
  }
});

test("workspace snapshot grant is project-scoped and read-only", () => {
  const workspace = ownerMcpGrantProfile("project-workspace-read");
  assert.deepEqual(workspace, {
    scope: "project",
    capabilities: [{ capability: "workspace.project_snapshot", accessMode: "read" }],
  });
  assert.equal(productCapabilityAccessMode("workspace.project_snapshot"), "read");
  assert.equal(ownerMcpGrantProfile("full-computer-control")?.capabilities.some(
    item => item.capability === "workspace.project_snapshot",
  ), false);
});
