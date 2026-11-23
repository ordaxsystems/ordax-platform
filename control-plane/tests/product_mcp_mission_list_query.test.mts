import assert from "node:assert/strict";
import test from "node:test";
import { validMissionProcessListQuery } from "../cloudflare/src/product_mcp_mission_list_query.ts";

test("mission discovery retains default and exact bounded filters", () => {
  assert.equal(validMissionProcessListQuery({}), true);
  assert.equal(validMissionProcessListQuery({ offset: 0 }), true);
  assert.equal(validMissionProcessListQuery({ mission_id: "runtime-multichat-proof-20261122" }), true);
  assert.equal(validMissionProcessListQuery({ mission_id: "run-1", mission_project: "ordax-runtime", offset: 24 }), true);
  assert.equal(validMissionProcessListQuery({ mission_id: "run-1", offset: 1000000 }), true);
});

test("mission discovery fails closed without inventing authority", () => {
  for (const value of [
    { mission_project: "project" }, { mission_id: "" }, { mission_id: "../outside" },
    { mission_id: "x".repeat(81) }, { mission_id: "run-1", mission_project: "bad name" },
    { mission_id: "run-1", offset: -1 }, { offset: 1000001 }, { offset: 2.5 },
    { offset: true }, { offset: "24" }, { process_id: "foreign" },
  ]) assert.equal(validMissionProcessListQuery(value), false, JSON.stringify(value));
});
