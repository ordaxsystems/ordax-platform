import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

// Guard the legacy authorization reads until the canonical PostgreSQL cutover.
// This guards SQL predicates; integration authorization requires separate tests.
const source = readFileSync(new URL("../cloudflare/src/product_intelligence_grants.ts", import.meta.url), "utf8");

test("owner Intelligence grants always restrict revoked devices", () => {
  const sql = Array.from(source.matchAll(/`([\s\S]*?)`/g), match => match[1]);
  const queries = sql.filter(value => value.includes("ordax_product_device_links"));
  assert.equal(queries.length, 4, "creation plus filtered list, full list, revocation");
  for (const query of queries) {
    assert.match(query, /JOIN ordax_devices d ON d\.id = l\.device_id/);
    assert.match(query, /l\.revoked_at IS NULL/);
    assert.match(query, /d\.revoked_at IS NULL/);
  }
});
