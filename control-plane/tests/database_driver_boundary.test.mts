import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";

const root = new URL("../cloudflare/src/", import.meta.url);
const driver = readFileSync(new URL("data_postgres_driver.ts", root), "utf8");
const store = readFileSync(new URL("product_postgres_store.ts", root), "utf8");
const entry = readFileSync(new URL("index.ts", root), "utf8");

test("database driver dependency is isolated behind an explicit session boundary", () => {
  assert.match(driver, /import \{ Client \} from "pg"/);
  assert.match(driver, /export interface DatabaseSession/);
  assert.match(driver, /export function openPostgresSession/);
  assert.match(store, /from "\.\/data_postgres_driver\.ts"/);
  assert.doesNotMatch(store, /new Client\(|from "pg"/);
  assert.doesNotMatch(entry, /from "pg"|new Client\(|env\.DB/);
});

test("database-dependent source cannot import node-postgres outside the driver adapter", () => {
  const offenders = readdirSync(root, { withFileTypes: true })
    .filter(item => item.isFile() && /\.(ts|mts|js)$/.test(item.name) && item.name !== "data_postgres_driver.ts")
    .filter(item => /from ["']pg["']|require\(["']pg["']\)/.test(
      readFileSync(new URL(item.name, root), "utf8"),
    ))
    .map(item => item.name);
  assert.deepEqual(offenders, []);
});

test("no direct database client or fallback in the canonical route layer", () => {
  assert.doesNotMatch(entry, /new Client\(|D1Database|\.prepare\(/);
  assert.match(entry, /handleProductDeviceTransport/);
  assert.match(store, /openPostgresSession\(connectionString\)/);
});
