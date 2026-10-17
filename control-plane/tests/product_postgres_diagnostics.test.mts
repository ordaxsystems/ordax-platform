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
    classification: "unclassified",
    signals: [],
  });
  assert.equal(JSON.stringify(diagnostic).includes(SECRET), false);
  assert.equal(Object.hasOwn(diagnostic, "message"), false);
  assert.equal(Object.hasOwn(diagnostic, "stack"), false);
});

test("store logs only the safe diagnostic envelope before generic failure", () => {
  const source = fs.readFileSync(new URL("../cloudflare/src/product_postgres_store.ts", import.meta.url), "utf8");
  assert.match(source, /console\.error\(JSON\.stringify\(\{ \.\.\.safePostgresFailure\(error, rpc\), phase \}\)\)/);
  assert.match(source, /let phase: "connect" \| "query" \| "decode" = "connect"/);
  assert.match(source, /phase = "query"/);
  assert.match(source, /phase = "decode"/);
  assert.doesNotMatch(source, /console\.error\([^\n]*(?:error\.message|connectionString|query|values)/);
});


test("Hyperdrive messages are reduced to stable non-secret classifications", () => {
  const cases = [
    ["Internal error.", "hyperdrive_internal_error", ["internal_error"]],
    ["Failed to acquire a connection from the pool.", "hyperdrive_pool_acquire_failed", ["pool_acquire"]],
    ["Server connection attempt failed: connection_refused", "hyperdrive_origin_connection_refused", ["server_connection_attempt", "connection_refused"]],
    ["Server connection attempt failed: connection_failure", "hyperdrive_server_connection_failed", ["server_connection_attempt"]],
    ["Server return error and closed connection.", "hyperdrive_server_closed_connection", ["server_closed_connection"]],
    ["Failed to connect to the provided database", "hyperdrive_database_connect_failed", ["database_connect"]],
    ["TLS handshake failed: cert validation failed", "hyperdrive_tls_handshake_failed", ["tls", "certificate"]],
    ["something private that must never be logged", "unclassified", []],
  ];
  for (const [message, expected, signals] of cases) {
    const diagnostic = safePostgresFailure(Object.assign(new Error(message as string), { code: "58000" }), "fixture_rpc");
    assert.equal(diagnostic.classification, expected);
    assert.deepEqual(diagnostic.signals, signals);
    assert.equal(JSON.stringify(diagnostic).includes(message as string), false);
  }
});
