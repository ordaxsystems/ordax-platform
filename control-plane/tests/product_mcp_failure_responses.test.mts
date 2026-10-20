import assert from "node:assert/strict";
import test from "node:test";
import { handleOrdaxMcp, type OrdaxMcpHandlers } from "../cloudflare/src/mcp_http.ts";

const acceptedId = "accepted-request-1";
function record(overrides: Record<string, unknown> = {}) {
  return { ok: true, action: { request_id: acceptedId, action: "git.status", status: "running", ...overrides } };
}

async function call(name: string, overrides: Partial<OrdaxMcpHandlers> = {}, args: Record<string, unknown> = {}) {
  const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: {
      request_id: acceptedId, device_id: "device-1", project: "demo", wait_for_completion_ms: 0, ...args,
    } } }),
  }), {
    session: async () => Response.json({ ok: true }),
    targets: async () => Response.json({ ok: true, targets: [] }),
    createAction: async () => Response.json({ ok: true, request_id: acceptedId }),
    getAction: async () => Response.json(record()),
    ...overrides,
  });
  assert.equal(response.headers.get("cache-control"), "no-store");
  return { response, body: await response.json() };
}

test("invalid session probes block every tool before discovery or dispatch", async () => {
  for (const payload of [null, {}, { ok: false }, { ok: "true" }, []]) {
    for (const name of ["ordax_targets", "git_status", "ordax_session"]) {
      const { response, body } = await call(name, {
        session: async () => Response.json(payload),
        targets: async () => { assert.fail("invalid session cannot discover targets"); },
        createAction: async () => { assert.fail("invalid session cannot dispatch"); },
      });
      assert.equal(response.status, 503);
      assert.deepEqual(body, { ok: false, error: "product_session_invalid_response" });
    }
  }
});

test("session transport failure reports unavailability without exception details", async () => {
  const { response, body } = await call("ordax_targets", {
    session: async () => { throw new Error("postgres://secret@private-host SQL private_table"); },
  });
  assert.equal(response.status, 503);
  assert.deepEqual(body, { ok: false, error: "product_session_unavailable" });
});

test("a second session response cannot convert revoked or malformed identity to authenticated", async () => {
  for (const payload of [{ ok: false }, {}, []]) {
    let probes = 0;
    const { body } = await call("ordax_session", { session: async () => Response.json(++probes === 1 ? { ok: true } : payload) });
    assert.equal(body.result.isError, true);
    assert.equal(body.result.structuredContent.authenticated, false);
  }
});

test("catalog errors and malformed JSON cannot look like a valid empty device list", async () => {
  for (const makeResponse of [
    () => Response.json({}), () => Response.json({ ok: false, targets: [] }),
    () => Response.json({ ok: true, targets: {} }), () => Response.json([]),
    () => new Response("<html>proxy error with internal details</html>"),
  ]) {
    const { body } = await call("ordax_targets", { targets: async () => makeResponse() });
    assert.equal(body.result.isError, true);
    assert.deepEqual(body.result.structuredContent, { ok: false, error: "targets_invalid_response", targets: [] });
  }
  const validEmpty = await call("ordax_targets");
  assert.equal(validEmpty.body.result.isError, false);
  assert.deepEqual(validEmpty.body.result.structuredContent, { ok: true, targets: [] });
});

test("unknown status, missing action and mismatched request stop observation without success or another dispatch", async () => {
  for (const payload of [
    {}, { ok: true }, { ok: true, action: {} }, record({ status: "unknown" }), record({ status: "" }),
    record({ request_id: "another-request" }), record({ action: undefined }),
    { ...record({ status: "unknown" }), pending: true, request_id: acceptedId },
    { ok: true, pending: true, request_id: "another-request" },
  ]) {
    for (const name of ["ordax_action_status", "git_status"]) {
      let dispatched = 0;
      let reads = 0;
      const { body } = await call(name, {
        getAction: async () => { reads++; return Response.json(payload); },
        createAction: async () => { dispatched++; return Response.json({ ok: true, request_id: acceptedId }); },
      });
      if (name === "ordax_action_status") {
        assert.equal(body.result.isError, true);
        assert.deepEqual(body.result.structuredContent, {
          ok: false, pending: false, request_id: acceptedId, error: "action_status_invalid_response",
        });
      } else {
        // An ACK is already durable. A malformed status read gives no proof
        // that execution stopped; prevent an accidental duplicate dispatch.
        assert.equal(body.result.isError, false);
        assert.equal(body.result.structuredContent.ok, true);
        assert.equal(body.result.structuredContent.pending, true);
        assert.equal(body.result.structuredContent.request_id, acceptedId);
        assert.equal(body.result.structuredContent.monitoring_error, "action_status_unavailable");
        assert.match(body.result.structuredContent.message, /Do not resubmit/);
      }
      assert.equal(reads, 1);
      assert.equal(dispatched, name === "git_status" ? 1 : 0);
    }
  }
});

test("accepted action retains continuation ID across HTTP and thrown status failures without leaking upstream data", async () => {
  for (const statusFailure of [
    async () => Response.json({ error: "private SQL details", connection: "secret" }, { status: 503 }),
    async () => { throw new Error("postgres://secret@private-host"); },
  ]) {
    for (const name of ["git_status", "ordax_action_status"]) {
      let dispatched = 0;
      let reads = 0;
      const { body } = await call(name, {
        getAction: async () => { reads++; return statusFailure(); },
        createAction: async () => { dispatched++; return Response.json({ ok: true, request_id: acceptedId }); },
      });
      assert.equal(body.result.structuredContent.request_id, acceptedId);
      if (name === "ordax_action_status") {
        assert.equal(body.result.isError, true);
        assert.equal(body.result.structuredContent.pending, false);
        assert.equal(body.result.structuredContent.error, "action_status_unavailable");
      } else {
        assert.equal(body.result.isError, false);
        assert.equal(body.result.structuredContent.ok, true);
        assert.equal(body.result.structuredContent.pending, true);
        assert.equal(body.result.structuredContent.monitoring_error, "action_status_unavailable");
        assert.match(body.result.structuredContent.message, /Do not resubmit/);
      }
      assert.equal(reads, 1); assert.equal(dispatched, name === "git_status" ? 1 : 0);
      for (const secret of ["secret", "private", "SQL", "postgres://"]) assert.equal(JSON.stringify(body).includes(secret), false);
    }
  }
});

test("failed envelope takes precedence over pending or a superficially successful action", async () => {
  const payload = { ...record({ status: "succeeded" }), ok: false, pending: true, request_id: acceptedId, error: "product_owner_auth_ineligible" };
  const { body } = await call("ordax_action_status", { getAction: async () => Response.json(payload) });
  assert.equal(body.result.isError, true);
  assert.deepEqual(body.result.structuredContent, {
    ok: false, pending: false, request_id: acceptedId, error: "product_owner_auth_ineligible",
  });
});

test("malformed dispatch acknowledgement cannot start polling or export private response fields", async () => {
  for (const payload of [
    {}, { ok: false, request_id: acceptedId }, { ok: true, request_id: "../../escape" },
    { ok: true, request_id: "x".repeat(129) }, { ok: true, private_token: "secret" },
  ]) {
    let dispatched = 0;
    const { body } = await call("git_status", {
      createAction: async () => { dispatched++; return Response.json(payload); },
      getAction: async () => { assert.fail("invalid ACK cannot start polling"); },
    });
    assert.equal(dispatched, 1);
    assert.equal(body.result.isError, true);
    assert.deepEqual(body.result.structuredContent, { ok: false, error: "product_request_id_missing" });
  }
});

test("grant denial still points to owner authorization without exporting arbitrary backend columns", async () => {
  const { body } = await call("computer_windows", { createAction: async () => Response.json({
    ok: false, error: "product_grant_not_resolved", private_token: "secret", raw_path: "C:/private",
  }, { status: 403 }) });
  assert.equal(body.result.isError, true);
  assert.equal(body.result.structuredContent.error, "product_grant_not_resolved");
  assert.equal(body.result.structuredContent.authorization_required, true);
  assert.equal(typeof body.result.structuredContent.required_owner_profile, "string");
  assert.match(body.result.structuredContent.authorization_surface, /\/v3\/owner\/remote-grant-groups/);
  assert.doesNotMatch(body.result.structuredContent.authorization_surface, /Studio/i);
  for (const secret of ["secret", "C:/private", "private_token"]) assert.equal(JSON.stringify(body).includes(secret), false);
});

test("unregistered project explains exact Owner setup without inventing grants or device bindings", async () => {
  let dispatched = 0;
  for (const action of ["process_list", "terminal_exec"]) {
    const { body } = await call(action, {
      createAction: async (request) => {
        dispatched++;
        const input = await request.json() as any;
        assert.equal(input.project, "ordaxsystems/ordax-platform");
        assert.equal(input.device_id, "device-1");
        return Response.json({
          ok: false, error: "product_project_scope_not_found",
          private_repository_id: 999, debug_connection_string: "postgres://secret",
        }, { status: 403 });
      },
      getAction: async () => { assert.fail("missing project scope must not start polling"); },
    }, { project: "ordaxsystems/ordax-platform" });
    assert.equal(body.result.isError, true);
    assert.deepEqual(body.result.structuredContent, {
      ok: false, error: "product_project_scope_not_found",
      setup_required: "space_project_repository_device_binding",
      owner_action: "register_project_and_device_in_ordax_owner",
    });
    assert.doesNotMatch(JSON.stringify(body), /999|postgres:|debug_connection_string/);
  }
  assert.equal(dispatched, 2);
});

test("device observation and missing project grant never reuse Owner project setup hint", async () => {
  for (const action of ["computer_processes", "process_list"]) {
    const { body } = await call(action, {
      createAction: async () => Response.json({
        ok: false, error: "product_grant_not_resolved",
      }, { status: 403 }),
    }, { project: "ordaxsystems/ordax-platform" });
    assert.equal(body.result.isError, true);
    assert.equal(body.result.structuredContent.error, "product_grant_not_resolved");
    // A grant denial must never be misreported as missing project
    // registration, irrespective of the UI hint for this tool family.
    assert.equal("setup_required" in body.result.structuredContent, false);
    assert.equal("owner_action" in body.result.structuredContent, false);
  }
});

test("tool exceptions and invalid request paths are contained without dispatch or exception details", async () => {
  const { body } = await call("ordax_targets", { targets: async () => { throw new Error("SQL private_table secret"); } });
  assert.equal(body.result.isError, true);
  assert.deepEqual(body.result.structuredContent, { ok: false, error: "ordax_mcp_internal_error" });
  const invalid = await call("ordax_action_status", {
    getAction: async () => { assert.fail("invalid request ID cannot read another route"); },
  }, { request_id: "../../private" });
  assert.deepEqual(invalid.body.result.structuredContent, { ok: false, error: "product_request_id_invalid" });
});

test("oversized and invalid UTF-8 responses are rejected and their readers cancelled", async () => {
  for (const bytes of [new Uint8Array(2 * 1024 * 1024 + 1), new Uint8Array([0xff, 0xfe])]) {
    let cancelled = 0;
    const { body } = await call("ordax_targets", { targets: async () => new Response(new ReadableStream({
      start(controller) { controller.enqueue(bytes); },
      cancel() { cancelled++; },
    })) });
    assert.equal(body.result.isError, true);
    assert.equal(body.result.structuredContent.error, "targets_invalid_response");
    assert.equal(cancelled, 1);
  }
});

test("explicit malformed Space never becomes a global Product request", async () => {
  let dispatched = 0;
  for (const space_id of [null, "", "not-a-uuid", 0, false, [], {}, "782c01a5-0ee3-4589-9f9b-11555191f35a/../"]) {
    const { body } = await call("computer_screen_info", {
      createAction: async () => {
        dispatched++;
        assert.fail("malformed caller-supplied Space reached Product dispatch");
      },
    }, { space_id });
    assert.equal(body.result.isError, true);
    assert.deepEqual(body.result.structuredContent, { ok: false, error: "space_id_invalid" });
  }
  assert.equal(dispatched, 0);
});

test("well-formed explicit Space reaches canonical Product grant decision unchanged", async () => {
  const space_id = "782c01a5-0ee3-4589-9f9b-11555191f35a";
  let seen = 0;
  const { body } = await call("computer_screen_info", {
    createAction: async (request) => {
      seen++;
      const submitted = await request.json();
      assert.equal(submitted.space_id, space_id);
      assert.equal(submitted.action, "computer.screen_info");
      // The canonical Product backend owns this denial. MCP must not
      // reinterpret an explicit UUID as a global Space grant.
      return Response.json({ ok: false, error: "product_grant_not_resolved" }, { status: 403 });
    },
  }, { space_id });
  assert.equal(seen, 1);
  assert.equal(body.result.isError, true);
  assert.equal(body.result.structuredContent.error, "product_grant_not_resolved");
});

test("omitted Space remains explicitly unscoped, not a fabricated Space grant", async () => {
  let seen = 0;
  const { body } = await call("computer_screen_info", {
    createAction: async (request) => {
      seen++;
      assert.equal((await request.json()).space_id, null);
      return Response.json({ ok: false, error: "product_grant_not_resolved" }, { status: 403 });
    },
  });
  assert.equal(seen, 1);
  assert.equal(body.result.isError, true);
  assert.equal(body.result.structuredContent.error, "product_grant_not_resolved");
});
