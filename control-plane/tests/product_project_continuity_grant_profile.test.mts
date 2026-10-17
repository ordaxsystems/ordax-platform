import assert from "node:assert/strict";
import test from "node:test";
import {
  ownerMcpGrantProfile,
  productCapabilityAccessMode,
} from "../cloudflare/src/product_owner_grant_profiles.ts";
import { PROJECT_CONTINUITY_ACTIONS } from "../cloudflare/src/product_action_scope.ts";

test("project-continuity is a bounded project profile with explicit read/write modes", () => {
  const profile = ownerMcpGrantProfile("project-continuity");
  assert.ok(profile);
  assert.equal(profile.scope, "project");
  assert.deepEqual(
    profile.capabilities.map((item) => [item.capability, item.accessMode]),
    [
      ["agent.project_briefing", "read"],
      ["continuity.get", "read"],
      ["continuity.update", "write"],
    ],
  );
  assert.deepEqual([...PROJECT_CONTINUITY_ACTIONS].sort(), [
    "agent.project_briefing",
    "continuity.get",
    "continuity.update",
  ]);
  assert.equal(productCapabilityAccessMode("continuity.update"), "write");
  assert.equal(productCapabilityAccessMode("continuity.get"), "read");
  assert.equal(productCapabilityAccessMode("agent.project_briefing"), "read");
});
