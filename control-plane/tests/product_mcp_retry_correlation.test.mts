import assert from "node:assert/strict";
import test from "node:test";

import { verifiedMcpRetryDigest } from "../cloudflare/src/mcp_http.ts";

const CLIENT = "11111111-1111-4111-8111-111111111111";
const SESSION = "chatgpt-session-abcdefgh";
const sessionPayload = { session: { client_id: CLIENT } };

const params = (name: string, args: Record<string, unknown>) => ({
  name,
  arguments: args,
  _meta: { "openai/session": SESSION },
});

test("MCP retry correlation distinguishes sequential JSON-RPC id reuse", async () => {
  const first = await verifiedMcpRetryDigest(
    sessionPayload, 1, params("computer_directory_create", {
      device_id: "22222222-2222-4222-8222-222222222222",
      path: "C:/one",
      parents: true,
    }),
  );
  const differentTool = await verifiedMcpRetryDigest(
    sessionPayload, 1, params("computer_terminal_exec", {
      device_id: "22222222-2222-4222-8222-222222222222",
      argv: ["cmd", "/c", "echo", "two"],
    }),
  );
  const differentPayload = await verifiedMcpRetryDigest(
    sessionPayload, 1, params("computer_directory_create", {
      device_id: "22222222-2222-4222-8222-222222222222",
      path: "C:/two",
      parents: true,
    }),
  );

  assert.match(first ?? "", /^[a-f0-9]{64}$/);
  assert.notEqual(first, differentTool);
  assert.notEqual(first, differentPayload);
  assert.notEqual(differentTool, differentPayload);
});

test("MCP retry correlation remains stable for the exact semantic retry", async () => {
  const first = await verifiedMcpRetryDigest(
    sessionPayload, "7", params("computer_terminal_exec", {
      device_id: "22222222-2222-4222-8222-222222222222",
      argv: ["cmd", "/c", "echo", "stable"],
      timeout_seconds: 30,
    }),
  );
  const reordered = await verifiedMcpRetryDigest(
    sessionPayload, "7", params("computer_terminal_exec", {
      timeout_seconds: 30,
      argv: ["cmd", "/c", "echo", "stable"],
      device_id: "22222222-2222-4222-8222-222222222222",
    }),
  );
  const numericId = await verifiedMcpRetryDigest(
    sessionPayload, 7, params("computer_terminal_exec", {
      device_id: "22222222-2222-4222-8222-222222222222",
      argv: ["cmd", "/c", "echo", "stable"],
      timeout_seconds: 30,
    }),
  );

  const changedWaitOnly = await verifiedMcpRetryDigest(
    sessionPayload, "7", params("computer_terminal_exec", {
      device_id: "22222222-2222-4222-8222-222222222222",
      argv: ["cmd", "/c", "echo", "stable"],
      timeout_seconds: 30,
      wait_for_completion_ms: 20000,
    }),
  );

  assert.equal(first, reordered);
  assert.equal(first, changedWaitOnly, "response wait policy cannot create a second device effect");
  assert.notEqual(first, numericId, "JSON-RPC id type remains part of retry identity");
});

test("MCP retry correlation still requires verified client/session metadata", async () => {
  assert.equal(await verifiedMcpRetryDigest(
    { session: { client_id: "not-a-uuid" } }, 1,
    params("computer_access_status", { device_id: "22222222-2222-4222-8222-222222222222" }),
  ), null);
  assert.equal(await verifiedMcpRetryDigest(
    sessionPayload, 1, {
      name: "computer_access_status",
      arguments: { device_id: "22222222-2222-4222-8222-222222222222" },
      _meta: { "openai/session": "bad" },
    },
  ), null);
});
