import test from "node:test";
import assert from "node:assert/strict";
import {
  canonicalReadPath, canonicalPathWithinRoot, validCanonicalReadActionArguments,
} from "../cloudflare/src/product_relay_read_contract.ts";
import {
  RELAY_PROJECT_READ_CAPABILITIES, RELAY_DEVICE_READ_CAPABILITIES,
} from "../cloudflare/src/product_relay_scope.ts";

test("one SSOT allows only four read-only project capabilities", () => {
  assert.deepEqual([...RELAY_PROJECT_READ_CAPABILITIES].sort(),
    ["project.text_read", "workspace.directory_list", "workspace.file_stat", "workspace.text_read"].sort());
  for (const action of RELAY_DEVICE_READ_CAPABILITIES) {
    assert.equal(validCanonicalReadActionArguments(action, { path: "workspace/file.txt" }), false);
  }
  for (const action of ["terminal.exec", "workspace.text_write", "computer.click", "project.delete"]) {
    assert.equal(validCanonicalReadActionArguments(action, { path: "workspace/file.txt" }), false);
  }
});

test("both Relay and scoped MCP reject traversal, Windows aliases, and Unicode slash confusion", () => {
  for (const path of [
    "", "/workspace/file", "workspace/", "workspace//file", "workspace/../private",
    "workspace/./file", "workspace/C:\\private", "workspace/C:private",
    "workspace/CON", "workspace/file.", "workspace/file ", "workspace/file%2fother",
    "workspace/\u2215escape", "workspace/\u2044escape", "workspace/\uFF0Fescape",
    "workspace/\x00bad", "workspace/\u212Aernel", "workspace/file\\private",
    "workspace/PRN.txt", "workspace/" + "x".repeat(513),
  ]) {
    assert.equal(canonicalReadPath(path), false, path);
    assert.equal(canonicalPathWithinRoot("workspace", path), false, path);
    assert.equal(validCanonicalReadActionArguments("workspace.text_read", { path }), false, path);
  }
});

test("root is trusted and segment-bound; prefix trick and another project are denied", () => {
  assert.equal(canonicalPathWithinRoot("workspace/project", "workspace/project/doc.txt"), true);
  assert.equal(canonicalPathWithinRoot("workspace/project", "workspace/project2/doc.txt"), false);
  assert.equal(canonicalPathWithinRoot("workspace/project", "workspace/other/doc.txt"), false);
  assert.equal(canonicalPathWithinRoot("workspace/project", "workspace/project"), true);
  assert.equal(canonicalPathWithinRoot("../root", "../root/file"), false);
  assert.equal(validCanonicalReadActionArguments("workspace.text_read",
    { path: "workspace/project/file.txt", start_line: 1, end_line: 20 }, "workspace/project"), true);
  assert.equal(validCanonicalReadActionArguments("workspace.text_read",
    { path: "workspace/other/file.txt" }, "workspace/project"), false);
});

test("bounded read argument contract prevents hidden writes and range abuse", () => {
  assert.equal(validCanonicalReadActionArguments("workspace.directory_list",
    { path: "workspace/project", max_depth: 12, max_entries: 5000, include_hidden: false }), true);
  for (const [action, data] of [
    ["workspace.text_read", { path: "workspace/file", start_line: 3, end_line: 2 }],
    ["workspace.text_read", { path: "workspace/file", start_line: 1000001 }],
    ["workspace.text_read", { path: "workspace/file", end_line: 0 }],
    ["workspace.directory_list", { path: "workspace", max_depth: 13 }],
    ["workspace.directory_list", { path: "workspace", include_hidden: "true" }],
    ["workspace.file_stat", { path: "workspace/file", create: true }],
    ["project.text_read", { path: "workspace/file", arguments: { write: true } }],
    ["workspace.text_read", { path: "workspace/file", __proto__: null, "x-owner": "other" }],
  ] as const) assert.equal(validCanonicalReadActionArguments(action, data), false);
});
