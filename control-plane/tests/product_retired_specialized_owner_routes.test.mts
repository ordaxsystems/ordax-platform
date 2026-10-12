import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const entry = readFileSync(new URL("../cloudflare/src/index.ts", import.meta.url), "utf8");

test("legacy Product owner grant endpoints fail closed without D1 handlers", () => {
  for (const segment of ["device-computer-grants", "device-intelligence-grants", "project-capability-grants"]) {
    assert.ok(entry.includes(`"/v3/product/${segment}"`));
    assert.ok(entry.includes(`"${segment}"`));
  }
  assert.match(entry, /error: "legacy_product_grants_retired" \}, 410/);
  for (const handler of [
    "createOwnerDeviceComputerGrant", "listOwnerDeviceComputerGrants", "revokeOwnerDeviceComputerGrant",
    "createOwnerDeviceIntelligenceGrant", "listOwnerDeviceIntelligenceGrants", "revokeOwnerDeviceIntelligenceGrant",
    "createOwnerProjectGrant", "listOwnerProjectGrants", "revokeOwnerProjectGrant",
  ]) {
    assert.ok(!entry.includes(handler), `${handler} must not ship in legacy worker`);
  }
});
