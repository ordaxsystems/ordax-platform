import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

// Temporary regression guard until canonical PostgreSQL cutover.
for (const [file, handler] of [
  ["product_device_grants.ts", "revokeOwnerDeviceComputerGrant"],
  ["product_project_grants.ts", "revokeOwnerProjectGrant"],
] as const) {
  test(`${handler} requires an active linked device`, () => {
    const source = readFileSync(new URL(`../cloudflare/src/${file}`, import.meta.url), "utf8");
    const revoke = source.slice(source.indexOf(`export async function ${handler}`));
    assert.ok(revoke.startsWith(`export async function ${handler}`));
    const query = revoke.match(/FROM ordax_product_grants g([\s\S]*?)LIMIT 1/);
    assert.ok(query, "expected owner-scoped grant lookup");
    assert.match(query[0], /JOIN ordax_product_device_links l/);
    assert.match(query[0], /JOIN ordax_devices d ON d\.id = l\.device_id/);
    assert.match(query[0], /g\.subject_id = \?2/);
    assert.match(query[0], /l\.revoked_at IS NULL/);
    assert.match(query[0], /d\.revoked_at IS NULL/);
  });
}
