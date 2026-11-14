import assert from "node:assert/strict";
import test from "node:test";
import { verifiedMcpRetryDigest } from "../cloudflare/src/mcp_http.ts";

const CLIENT = "11111111-1111-4111-8111-111111111111";
const SESSION = "chatgpt_session_reused_rpc_id";

function params(name: string, args: Record<string, unknown>, wait = 20000) {
  return {
    name,
    arguments: { ...args, wait_for_completion_ms: wait },
    _meta: { "openai/session": SESSION },
  };
}

test("retry correlation survives ChatGPT reusing JSON-RPC id without conflating different effects", async () => {
  const session = { session: { client_id: CLIENT } };
  const first = await verifiedMcpRetryDigest(
    session, 1,
    params("computer_terminal_exec", {
      device_id: "22222222-2222-4222-8222-222222222222",
      argv: ["cmd.exe", "/c", "echo one"],
    }),
  );
  const exactRetry = await verifiedMcpRetryDigest(
    session, 1,
    params("computer_terminal_exec", {
      argv: ["cmd.exe", "/c", "echo one"],
      device_id: "22222222-2222-4222-8222-222222222222",
    }, 0),
  );
  const differentCommandSameRpcId = await verifiedMcpRetryDigest(
    session, 1,
    params("computer_terminal_exec", {
      device_id: "22222222-2222-4222-8222-222222222222",
      argv: ["cmd.exe", "/c", "echo two"],
    }),
  );
  const differentToolSameRpcId = await verifiedMcpRetryDigest(
    session, 1,
    params("computer_directory_create", {
      device_id: "22222222-2222-4222-8222-222222222222",
      path: "C:\\Users\\ordax\\two",
    }),
  );

  assert.match(first ?? "", /^[a-f0-9]{64}$/);
  assert.equal(exactRetry, first, "wait policy and object key order do not create a new write effect");
  assert.notEqual(differentCommandSameRpcId, first, "different write payload cannot collide on reused RPC id");
  assert.notEqual(differentToolSameRpcId, first, "different tool cannot collide on reused RPC id");
});

test("retry correlation preserves JSON-RPC id type and fails closed without trusted session metadata", async () => {
  const session = { session: { client_id: CLIENT } };
  const numeric = await verifiedMcpRetryDigest(session, 1, params("computer_terminal_exec", { argv: ["id"] }));
  const textual = await verifiedMcpRetryDigest(session, "1", params("computer_terminal_exec", { argv: ["id"] }));
  assert.notEqual(numeric, textual);

  const missingMeta = await verifiedMcpRetryDigest(
    session, 1, { name: "computer_terminal_exec", arguments: { argv: ["id"] } },
  );
  assert.equal(missingMeta, null);
});
