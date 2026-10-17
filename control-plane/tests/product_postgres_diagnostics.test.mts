import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { safePostgresFailure } from "../cloudflare/src/product_postgres_store.ts";

const SECRET = "postgres://ordax:super-secret@private-db.invalid/postgres";

test("PostgreSQL diagnostics expose only allowlisted non-secret fields", () => {
  const error = Object.assign(new Error(`password=${SECRET}`), {
    code: "28P01", errno: -4078, syscall: "connect", address: SECRET,
    cause: { name: "SocketError", code: "ETIMEDOUT", message: SECRET, host: SECRET },
  });
  const diagnostic = safePostgresFailure(error, "ordax_authenticate_product_device_v1");
  assert.deepEqual(diagnostic, {
    event: "product_postgres_failure",
    rpc: "ordax_authenticate_product_device_v1",
    name: "Error",
    code: "28P01",
    errno: -4078,
    syscall: "connect",
    cause_name: "SocketError",
    cause_code: "ETIMEDOUT",
  });
  assert.equal(JSON.stringify(diagnostic).includes(SECRET), false);
  assert.equal(Object.hasOwn(diagnostic, "message"), false);
  assert.equal(Object.hasOwn(diagnostic, "stack"), false);
});

test("store logs only the safe diagnostic envelope before generic failure", () => {
  const source = fs.readFileSync(new URL("../cloudflare/src/product_postgres_store.ts", import.meta.url), "utf8");
  assert.match(source, /console\.error\(JSON\.stringify\(safePostgresFailure\(error, rpc\)\)\)/);
  assert.doesNotMatch(source, /console\.error\([^\n]*(?:error\.message|connectionString|query|values)/);
});
