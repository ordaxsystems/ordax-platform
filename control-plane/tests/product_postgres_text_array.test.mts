import assert from "node:assert/strict";
import test from "node:test";

import {
  encodePostgresTextArrayLiteral,
  InvalidPostgresTextArrayError,
} from "../cloudflare/src/product_postgres_text_array.ts";

test("text[] RPC parameters use canonical PostgreSQL array literals", () => {
  assert.equal(
    encodePostgresTextArrayLiteral(["computer.access_status", "computer.windows"]),
    '{"computer.access_status","computer.windows"}',
  );
  assert.equal(encodePostgresTextArrayLiteral([]), "{}");
});

test("text[] literals quote and escape PostgreSQL array syntax safely", () => {
  assert.equal(
    encodePostgresTextArrayLiteral(["a,b", 'a"b', "a\\b", "{brace}", "NULL", ""]),
    '{"a,b","a\\\"b","a\\\\b","{brace}","NULL",""}',
  );
});

test("text[] encoder fails closed for non-string members", () => {
  assert.throws(
    () => encodePostgresTextArrayLiteral(["ok", 7]),
    InvalidPostgresTextArrayError,
  );
});
