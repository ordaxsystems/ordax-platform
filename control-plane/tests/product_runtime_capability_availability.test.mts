import test from "node:test";
import assert from "node:assert/strict";
import { runtimeCapabilityAvailability } from "../cloudflare/src/product_runtime_capability_availability.ts";

const DEVICE = "22222222-2222-4222-8222-222222222222";
const OTHER = "33333333-3333-4333-8333-333333333333";
const catalog = (actions: unknown) => ({
  ok: true,
  targets: [
    { device_id: DEVICE, runtime_capabilities: actions },
    { device_id: OTHER, runtime_capabilities: ["computer.access_status", "computer.terminal_exec"] },
  ],
});

test("exact device Runtime registry is an independent availability preflight", () => {
  const native = catalog(["agent.status", "computer.access_status", "ordax.surface.open", "ordax.surface.status"]);
  assert.equal(runtimeCapabilityAvailability(native, DEVICE, "ordax.surface.status"), "available");
  assert.equal(runtimeCapabilityAvailability(native, DEVICE, "computer.processes"), "unavailable");
  assert.equal(runtimeCapabilityAvailability(native, OTHER, "computer.terminal_exec"), "available");
  assert.equal(runtimeCapabilityAvailability(native, OTHER, "ordax.surface.status"), "unavailable");
});

test("legacy absent manifest stays unverified; malformed or cross-device manifest denies", () => {
  assert.equal(runtimeCapabilityAvailability(catalog(null), DEVICE, "computer.processes"), "unverified");
  assert.equal(runtimeCapabilityAvailability(catalog(undefined), DEVICE, "computer.processes"), "unverified");
  for (const actions of [[], ["computer.windows", "computer.windows"],
    ["z", "a"], ["computer.windows", null], "computer.windows"]) {
    assert.equal(runtimeCapabilityAvailability(catalog(actions), DEVICE, "computer.windows"), "unavailable");
  }
  assert.equal(runtimeCapabilityAvailability(catalog(["computer.windows"]), "44444444-4444-4444-8444-444444444444", "computer.windows"), "unavailable");
  assert.equal(runtimeCapabilityAvailability({ ok: true, targets: [catalog(["a"]).targets[0], catalog(["b"]).targets[0]] }, DEVICE, "a"), "unavailable");
});
