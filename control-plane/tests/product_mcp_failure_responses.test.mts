import assert from "node:assert/strict";
import test from "node:test";
import { handleOrdaxMcp, type OrdaxMcpHandlers } from "../cloudflare/src/mcp_http.ts";

const acceptedId = "11111111-1111-4111-8111-111111111111";
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


test("MCP wait_for_completion_ms follows its integer schema before any queue write", async () => {
  let enqueues = 0;
  let reads = 0;
  for (const invalid of [null, "", "0", "8000", false, true, [], {}, [1],
    -1, 20001, 0.5, 1.25, Number.MAX_SAFE_INTEGER + 1]) {
    const { body } = await call("computer_terminal_exec", {
      createAction: async () => { enqueues++; throw Error("invalid wait must not enqueue"); },
      getAction: async () => { reads++; throw Error("invalid wait must not poll"); },
    }, { wait_for_completion_ms: invalid });
    assert.deepEqual(body.result.structuredContent, {
      ok: false, error: "wait_for_completion_invalid", action_dispatched: false,
    }, JSON.stringify(invalid));
    assert.equal(body.result.isError, true);
  }
  assert.equal(enqueues, 0);
  assert.equal(reads, 0);
  // Zero wait must expose the durable queued receipt without an extra query.
  const zero = await call("computer_terminal_exec", {
    createAction: async () => {
      enqueues++;
      return Response.json({ ok: true, request_id: acceptedId, status: "queued" }, { status: 202 });
    },
    getAction: async () => { reads++; throw Error("zero wait does not need queued status query"); },
  }, { wait_for_completion_ms: 0 });
  assert.equal(zero.body.result.structuredContent.request_id, acceptedId);
  assert.equal(zero.body.result.structuredContent.pending, true);
  assert.equal(reads, 0);
  // Values at the top of the published schema are valid: the first read is
  // already terminal, so the gateway neither waits nor repeats the enqueue.
  const maximum = await call("computer_terminal_exec", {
    createAction: async () => {
      enqueues++;
      return Response.json({ ok: true, request_id: acceptedId, status: "running" }, { status: 202 });
    },
    getAction: async () => {
      reads++;
      return Response.json(record({ status: "succeeded" }));
    },
  }, { wait_for_completion_ms: 20000 });
  assert.equal(maximum.body.result.structuredContent.pending, false);
  assert.equal(maximum.body.result.structuredContent.request_id, acceptedId);
  assert.equal(enqueues, 2, "each valid invocation enqueues at most once");
  assert.equal(reads, 1);
});

test("MCP status rejects non-UUID request identifiers before status SQL", async () => {
  let reads = 0, enqueues = 0;
  for (const invalid of ["request-1", "accepted-request-1", "legacy:status:1", "not_a_uuid"]) {
    const { body } = await call("ordax_action_status", {
      createAction: async () => { enqueues++; throw Error("status tool must not enqueue"); },
      getAction: async () => { reads++; throw Error("malformed id must not read PostgreSQL"); },
    }, { request_id: invalid });
    assert.deepEqual(body.result.structuredContent, {
      ok: false, error: "product_request_id_invalid",
    }, invalid);
    assert.equal(body.result.isError, true);
  }
  assert.equal(reads, 0);
  assert.equal(enqueues, 0);
});

test("invalid JSON-RPC ids cannot dispatch or lose action correlation", async () => {
  let sessions = 0;
  let dispatched = 0;
  const handlers: OrdaxMcpHandlers = {
    session: async () => { sessions++; return Response.json({ ok: true }); },
    targets: async () => { dispatched++; throw new Error("invalid RPC ID reached target discovery"); },
    createAction: async () => { dispatched++; throw new Error("invalid RPC ID reached action dispatch"); },
    getAction: async () => { dispatched++; throw new Error("invalid RPC ID reached status polling"); },
  };
  const send = (id: unknown, method = "tools/call") => handleOrdaxMcp(
    new Request("https://ordax.example/mcp", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0", ...(id === undefined ? {} : { id }), method,
        params: { name: "ordax_targets", arguments: {} },
      }),
    }), handlers,
  );

  for (const invalidId of [undefined, null, false, true, {}, [], 1.5,
    Number.MAX_SAFE_INTEGER + 1, "", "x".repeat(257)]) {
    const response = await send(invalidId);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request" },
    });
  }
  assert.equal(dispatched, 0);
  assert.equal(sessions, 10, "normal OAuth preflight stays mandatory for invalid requests");

  const notification = await send(undefined, "notifications/initialized");
  assert.equal(notification.status, 202);
  assert.equal(dispatched, 0);
  const masqueradingNotification = await send(42, "notifications/initialized");
  assert.equal((await masqueradingNotification.json() as any).error.code, -32600);
  assert.equal(dispatched, 0);
});

test("malformed explicit JSON-RPC arguments fail before a device action", async () => {
  let dispatched = 0;
  const handlers: OrdaxMcpHandlers = {
    session: async () => Response.json({ ok: true }),
    targets: async () => { dispatched++; throw new Error("malformed arguments reached discovery"); },
    createAction: async () => { dispatched++; throw new Error("malformed arguments reached action enqueue"); },
    getAction: async () => { dispatched++; throw new Error("malformed arguments reached status polling"); },
  };
  const send = (id: string | number, name: string, args: unknown, includeArgs = true) =>
    handleOrdaxMcp(new Request("https://ordax.example/mcp", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call",
        params: { name, ...(includeArgs ? { arguments: args } : {}) } }),
    }), handlers);

  for (const args of [null, [], false, 42, "not-an-object"]) {
    for (const tool of ["ordax_targets", "computer_screen_info"]) {
      const response = await send("action-correlation-1", tool, args);
      const payload = await response.json() as any;
      assert.equal(payload.id, "action-correlation-1");
      assert.equal(payload.error.code, -32602);
      assert.equal(payload.error.message, "Invalid params");
    }
  }
  assert.equal(dispatched, 0);

  const valid = await send("status-request-1", "ordax_session", undefined, false);
  const body = await valid.json() as any;
  assert.equal(body.id, "status-request-1");
  assert.equal(body.result.isError, false, "omitted optional arguments remain valid");
  const numeric = await send(42, "ordax_session", {});
  assert.equal((await numeric.json() as any).id, 42);
});

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
          ok: false, monitoring_state: "unknown", request_id: acceptedId, error: "action_status_invalid_response",
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

test("public status output enforces canonical machine error codes without exposing diagnostics", async () => {
  for (const suspicious of [
    "postgres://user:secret@db.internal",
    "private_token=secret",
    "runtime failure with credentials",
    "database\\nprivate",
    "X".repeat(121),
  ]) {
    for (const name of ["ordax_action_status", "git_status"]) {
      const { body } = await call(name, {
        getAction: async () => Response.json(record({ status: "failed", error_code: suspicious })),
      });
      const projected = body.result.structuredContent;
      assert.equal(projected.request_id, acceptedId);
      assert.doesNotMatch(JSON.stringify(body), /secret|credentials|database\\nprivate/);
      if (name === "ordax_action_status") {
        assert.equal(body.result.isError, true);
        assert.deepEqual(projected, {
          ok: false, monitoring_state: "unknown", request_id: acceptedId,
          error: "action_status_invalid_response",
        });
      } else {
        // The enqueue is already acknowledged. Malformed monitoring data must
        // never invite a duplicate write or be represented as a failed action.
        assert.equal(projected.ok, true);
        assert.equal(projected.pending, true);
        assert.equal(projected.monitoring_error, "action_status_unavailable");
        assert.match(projected.message, /Do not resubmit/);
      }
    }
  }

  for (const code of ["EACCES", "runtime_action_failed", "ENOENT_2"]) {
    const { body } = await call("ordax_action_status", {
      getAction: async () => Response.json(record({ status: "failed", error_code: code })),
    });
    assert.equal(body.result.structuredContent.action.error_code, code);
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
        assert.equal(Object.hasOwn(body.result.structuredContent, "pending"), false);
        assert.equal(body.result.structuredContent.monitoring_state, "unknown");
        assert.equal(body.result.structuredContent.error, "action_status_unavailable");
        assert.match(body.result.structuredContent.message, /Do not resubmit/);
      } else {
        assert.equal(body.result.isError, false);
        assert.equal(body.result.structuredContent.ok, true);
        assert.equal(body.result.structuredContent.pending, true);
        assert.equal(body.result.structuredContent.monitoring_error, "action_status_unavailable");
        assert.match(body.result.structuredContent.message, /Do not resubmit/);
      }
      assert.equal(reads, name === "ordax_action_status" ? 2 : 1);
      assert.equal(dispatched, name === "git_status" ? 1 : 0);
      for (const secret of ["secret", "private", "SQL", "postgres://"]) assert.equal(JSON.stringify(body).includes(secret), false);
    }
  }
});

test("an accepted action remains uncertain after a 401, 403 or 404 status lookup", async () => {
  for (const status of [401, 403, 404]) {
    let enqueues = 0;
    const { body } = await call("git_status", {
      createAction: async () => {
        enqueues++;
        return Response.json({ ok: true, request_id: acceptedId });
      },
      getAction: async () => Response.json({ error: "secret internal status" }, { status }),
    });
    const result = body.result.structuredContent;
    assert.equal(enqueues, 1);
    assert.equal(body.result.isError, true);
    assert.equal(result.ok, false);
    assert.equal(result.request_id, acceptedId);
    assert.equal(Object.hasOwn(result, "pending"), false);
    assert.equal(result.monitoring_state, "unknown");
    assert.equal(result.upstream_status, status);
    assert.equal(result.error, status === 404 ? "action_status_not_visible" : "action_status_access_denied");
    assert.match(result.message, /Do not resubmit/);
    assert.doesNotMatch(JSON.stringify(result), /secret/);
  }
});

test("direct status read distinguishes revoked access or invisible request from transient gateway failure", async () => {
  for (const [status, expected] of [
    [401, "action_status_access_denied"],
    [403, "action_status_access_denied"],
    [404, "action_status_not_visible"],
    [429, "action_status_unavailable"],
    [503, "action_status_unavailable"],
  ] as const) {
    let reads = 0;
    const { body } = await call("ordax_action_status", {
      createAction: async () => { assert.fail("status lookup cannot enqueue"); },
      getAction: async () => {
        reads++;
        return Response.json({ error: "private SQL secret", trace: "sensitive" }, {status});
      },
    });
    assert.equal(reads, status === 503 ? 2 : 1,
      "only transient failures can consume the one bounded status retry");
    assert.equal(body.result.isError, true);
    const projected = body.result.structuredContent;
    assert.equal(projected.ok, false);
    assert.equal(projected.error, expected);
    assert.equal(projected.request_id, acceptedId);
    assert.equal(projected.upstream_status, status);
    assert.equal(projected.monitoring_state, "unknown");
    assert.equal(Object.hasOwn(projected, "pending"), false);
    assert.match(projected.message, /Do not resubmit/);
    assert.doesNotMatch(JSON.stringify(projected), /private|secret|sensitive|trace/);
  }
});

test("untrusted pending status message cannot expose backend diagnostics to public MCP", async () => {
  for (const name of ["ordax_action_status", "git_status"]) {
    let created = 0;
    const {body} = await call(name, {
      createAction: async () => {
        created++;
        return Response.json({ok:true,request_id:acceptedId});
      },
      getAction: async () => Response.json({
        ok: true, pending: true, request_id: acceptedId,
        message: "private SQL token=secret connection=postgres://credentials",
        debug_stack: "sensitive",
      }),
    });
    const content = body.result.structuredContent;
    assert.equal(content.request_id, acceptedId);
    assert.equal(content.ok, true);
    assert.equal(content.pending, true);
    assert.equal(body.result.isError, false);
    assert.match(content.message, /ordax_action_status/);
    assert.doesNotMatch(JSON.stringify(body), /secret|private SQL|postgres:|sensitive/);
    assert.equal(created, name === "git_status" ? 1 : 0);
  }
});

test("failed envelope takes precedence over pending or a superficially successful action", async () => {
  const payload = { ...record({ status: "succeeded" }), ok: false, pending: true, request_id: acceptedId, error: "product_owner_auth_ineligible" };
  const { body } = await call("ordax_action_status", { getAction: async () => Response.json(payload) });
  assert.equal(body.result.isError, true);
  assert.deepEqual(body.result.structuredContent, {
    ok: false, monitoring_state: "unknown", request_id: acceptedId, error: "product_owner_auth_ineligible",
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

test("availability failures explain recovery without blaming arguments or leaking backend fields", async () => {
  for (const [error, required_action] of [
    ["central_device_offline", "reconnect_authorized_device_runtime"],
    ["central_session_pending", "wait_for_device_session_confirmation"],
  ]) {
    const { body } = await call("computer_terminal_exec", {
      createAction: async () => Response.json({ ok: false, error, private_token: "secret" }, { status: 409 }),
      getAction: async () => { assert.fail("no dispatched action to observe"); },
    }, { argv: ["uname", "-s"] });
    assert.equal(body.result.isError, true);
    assert.deepEqual(body.result.structuredContent, {
      ok: false, error, retryable: true, action_dispatched: false, required_action,
    });
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


test("MCP projects cross-device attestation errors without leaking the bound device or proposing a grant", async () => {
  const { body } = await call("computer_terminal_exec", {
    createAction: async () => Response.json({
      ok: false,
      error: "product_attested_device_mismatch",
      internal_device_id: "private-device",
    }, { status: 403 }),
    getAction: async () => { assert.fail("no action status after attestation denial"); },
  }, { device_id: "22222222-2222-4222-8222-222222222222", argv: ["id"] });
  assert.equal(body.result.isError, true);
  assert.deepEqual(body.result.structuredContent, {
    ok: false,
    error: "product_attested_device_mismatch",
    required_action: "establish_attested_session_for_requested_device",
    grant_evaluated: false,
  });
  assert.equal(JSON.stringify(body).includes("private-device"), false);
});

test("shadow usage records one successful authenticated tool call and ignores MCP protocol or error responses", async () => {
  const ownerUserId = "11111111-1111-4111-8111-111111111111";
  const clientId = "22222222-2222-4222-8222-222222222222";
  const recorded: any[] = [];
  const handlers: OrdaxMcpHandlers = {
    session: async () => Response.json({ ok: true, session: { subject_id: ownerUserId, client_id: clientId } }),
    targets: async () => Response.json({ ok: true, targets: [] }),
    createAction: async () => Response.json({ ok: false }),
    getAction: async () => Response.json({ ok: false }),
    recordUsage: async (usage) => { recorded.push(usage); },
    usageFingerprintKey: "fixture-only-random-secret-key-with-32-bytes",
  };
  const send = (method: string, id: string | number | undefined, params?: unknown) => handleOrdaxMcp(
    new Request("https://ordax.example/mcp", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", ...(id === undefined ? {} : { id }), method, ...(params === undefined ? {} : { params }) }),
    }), handlers,
  );

  const first = await send("tools/call", 7, { name: "ordax_targets", arguments: {} });
  assert.equal((await first.json() as any).result.isError, false);
  assert.equal(recorded.length, 1);
  assert.deepEqual(Object.keys(recorded[0]).sort(), ["clientId", "ownerUserId", "requestFingerprint", "toolName"]);
  assert.equal(recorded[0].ownerUserId, ownerUserId);
  assert.equal(recorded[0].clientId, clientId);
  assert.equal(recorded[0].toolName, "ordax_targets");
  assert.match(recorded[0].requestFingerprint, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(recorded).includes("arguments"), false);

  await send("tools/call", 7, { name: "ordax_targets", arguments: {} });
  assert.equal(recorded[1].requestFingerprint, recorded[0].requestFingerprint, "retry digest is stable");
  await send("tools/call", 8, { name: "ordax_targets", arguments: {} });
  assert.notEqual(recorded[2].requestFingerprint, recorded[0].requestFingerprint, "a distinct request ID is a distinct call");

  await send("initialize", 9);
  await send("ping", 10);
  await send("notifications/initialized", undefined);
  const failedHandlers = {
    ...handlers,
    targets: async () => Response.json({ ok: false, error: "targets_unavailable" }, { status: 503 }),
  };
  const failedResponse = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 11, method: "tools/call", params: { name: "ordax_targets", arguments: {} } }),
  }), failedHandlers);
  assert.equal((await failedResponse.json() as any).result.isError, true);
  assert.equal(recorded.length, 3, "protocol methods and failed tools are not usage calls");

  const noIdentity = { ...handlers, session: async () => Response.json({ ok: true, session: {} }) };
  const noIdentityResponse = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 12, method: "tools/call", params: { name: "ordax_targets", arguments: {} } }),
  }), noIdentity);
  assert.equal((await noIdentityResponse.json() as any).result.isError, false);
  assert.equal(recorded.length, 3, "unbound identity is never metered");

  const noSecret = { ...handlers, usageFingerprintKey: undefined };
  const noSecretResponse = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 121, method: "tools/call", params: { name: "ordax_targets", arguments: {} } }),
  }), noSecret);
  assert.equal((await noSecretResponse.json() as any).result.isError, false);
  assert.equal(recorded.length, 3, "missing fingerprint key fails closed to unmetered mode");

  const meterUnavailable = { ...handlers, recordUsage: async () => { throw new Error("private backend detail"); } };
  const originalError = console.error;
  const logs: string[] = [];
  console.error = (...values: unknown[]) => logs.push(values.map(String).join(" "));
  try {
    const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 13, method: "tools/call", params: { name: "ordax_targets", arguments: {} } }),
    }), meterUnavailable);
    assert.equal((await response.json() as any).result.isError, false, "meter outage cannot fail a completed MCP call");
    assert.equal(JSON.stringify(logs).includes("private backend detail"), false);
  } finally { console.error = originalError; }
});

test("MCP retry correlation survives transport failure and isolates clients, sessions and call IDs", async () => {
  const CLIENT_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const CLIENT_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const OWNER = "11111111-1111-4111-8111-111111111111";
  const markerA = "openai-device-attested-session-retry-A";
  const markerB = "openai-device-attested-session-retry-B";
  const correlations: Array<string | null | undefined> = [];
  let verifiedClient = CLIENT_A;
  const handlers: OrdaxMcpHandlers = {
    session: async () => Response.json({
      ok: true, session: { subject_id: OWNER, client_id: verifiedClient },
    }),
    targets: async () => { assert.fail("no discovery needed for correlation proof"); },
    createAction: async (req, retryDigest) => {
      assert.equal(req.headers.get("x-ordax-internal-idempotency-sha256"), null);
      correlations.push(retryDigest);
      // Simulate a lost gateway response AFTER the PostgreSQL write. Retries
      // must reconstruct the same backend key, not enqueue with a fresh UUID.
      throw new Error("transport lost after durable enqueue");
    },
    getAction: async () => { assert.fail("lost enqueue response cannot be polled"); },
  };
  const invoke = async (id: string | number, marker?: string) => {
    const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
      method: "POST",
      headers: { "content-type": "application/json",
        "x-ordax-internal-idempotency-sha256": "f".repeat(64) },
      body: JSON.stringify({
        jsonrpc: "2.0", id, method: "tools/call",
        params: {
          name: "computer_screen_info",
          arguments: { device_id: "22222222-2222-4222-8222-222222222222" },
          ...(marker === undefined ? {} : { _meta: { "openai/session": marker } }),
        },
      }),
    }), handlers);
    const body = await response.json() as any;
    assert.equal(body.result.isError, true);
  };
  await invoke(7, markerA);
  await invoke(7, markerA);
  await invoke(8, markerA);
  await invoke("7", markerA);
  await invoke(7, markerB);
  verifiedClient = CLIENT_B;
  await invoke(7, markerA);
  await invoke(7);
  assert.equal(correlations.length, 7);
  assert.match(correlations[0]!, /^[0-9a-f]{64}$/);
  assert.equal(correlations[0], correlations[1], "exact retry uses identical SQL identity");
  assert.equal(new Set(correlations.slice(0, 6)).size, 5,
    "other ID, ID type, marker and signed client must not share an enqueue key");
  assert.equal(correlations[6], null, "missing session marker cannot mint stable correlation");
  assert.notEqual(correlations[0], "f".repeat(64), "untrusted inbound header cannot select the retry key");
});

test("queued PostgreSQL ACK with zero wait is a durable receipt without a redundant status query", async () => {
  let enqueues = 0, reads = 0;
  const { body } = await call("computer_screen_info", {
    createAction: async () => {
      enqueues++;
      return Response.json({ ok: true, request_id: acceptedId, status: "queued", replayed: false }, { status: 202 });
    },
    getAction: async () => {
      reads++;
      throw new Error("no status query needed after an authenticated queued ACK");
    },
  });
  const result = body.result.structuredContent;
  assert.equal(body.result.isError, false);
  assert.deepEqual(result, {
    ok: true, pending: true, request_id: acceptedId,
    action: { name: "computer.screen_info", status: "queued" },
    message: "Action is queued and has not started; check ordax_action_status with this request_id.",
  });
  assert.equal(enqueues, 1);
  assert.equal(reads, 0, "zero-wait read must not consume another PostgreSQL connection");
});

test("zero wait does not invent queued state for terminal or malformed ACKs", async () => {
  for (const status of ["succeeded", "failed", "running", null, undefined]) {
    let reads = 0;
    const { body } = await call("computer_screen_info", {
      createAction: async () => Response.json({ ok: true, request_id: acceptedId, status }),
      getAction: async () => {
        reads++;
        return Response.json(record({ status: "succeeded", result: { source: "actual status RPC" } }));
      },
    });
    assert.equal(reads, 1, "unverified/terminal receipts still require canonical status");
    assert.equal(body.result.structuredContent.action.status, "succeeded");
    assert.deepEqual(body.result.structuredContent.action.result, { source: "actual status RPC" });
  }
});

test("accepted action recovers one transient status 503 without enqueueing twice", async () => {
  let dispatched = 0, reads = 0;
  const { body } = await call("computer_screen_info", {
    createAction: async () => {
      dispatched++;
      return Response.json({ ok: true, request_id: acceptedId, status: "queued" }, { status: 202 });
    },
    getAction: async () => {
      reads++;
      return reads === 1
        ? Response.json({ error: "private credentials" }, { status: 503 })
        : Response.json(record({ status: "succeeded", result: { ok: true } }));
    },
  }, { wait_for_completion_ms: 1000 });
  assert.equal(dispatched, 1);
  assert.equal(reads, 2);
  assert.equal(body.result.isError, false);
  assert.equal(body.result.structuredContent.request_id, acceptedId);
  assert.equal(body.result.structuredContent.action.status, "succeeded");
  assert.equal(JSON.stringify(body).includes("private credentials"), false);
});

test("one transient exception is recoverable, but repeated failure preserves request ID and caps reads", async () => {
  for (const recover of [true, false]) {
    let reads = 0, enqueues = 0;
    const { body } = await call("computer_screen_info", {
      createAction: async () => {
        enqueues++;
        return Response.json({ ok: true, request_id: acceptedId, status: "queued" }, { status: 202 });
      },
      getAction: async () => {
        reads++;
        if (reads === 1 || !recover) throw new Error("postgres://private-token/unknown");
        return Response.json(record({ status: "succeeded" }));
      },
    }, { wait_for_completion_ms: 1000 });
    assert.equal(reads, 2);
    assert.equal(enqueues, 1);
    assert.equal(body.result.structuredContent.request_id, acceptedId);
    if (recover) {
      assert.equal(body.result.structuredContent.action.status, "succeeded");
    } else {
      assert.equal(body.result.structuredContent.monitoring_error, "action_status_unavailable");
      assert.equal(body.result.structuredContent.pending, true);
      assert.equal(body.result.isError, false);
    }
    assert.equal(JSON.stringify(body).includes("postgres://private-token"), false);
  }
});

test("status denials and rate limits do not trigger automatic retry under load", async () => {
  for (const status of [401, 403, 404, 429]) {
    let reads = 0, enqueues = 0;
    const { body } = await call("computer_screen_info", {
      createAction: async () => {
        enqueues++;
        return Response.json({ ok: true, request_id: acceptedId, status: "queued" }, { status: 202 });
      },
      getAction: async () => {
        reads++;
        return Response.json({ error: "private SQL error" }, { status });
      },
    }, { wait_for_completion_ms: 1000 });
    assert.equal(enqueues, 1);
    assert.equal(reads, 1);
    assert.equal(body.result.structuredContent.request_id, acceptedId);
    assert.equal(body.result.structuredContent.upstream_status, status);
    assert.equal(body.result.structuredContent.error, status === 429 ? undefined
      : status === 404 ? "action_status_not_visible" : "action_status_access_denied");
  }
});

test("direct status reads recover one transient 408/503 or thrown transport error", async () => {
  for (const transient of [408, 500, 503, "throw"] as const) {
    let reads = 0, enqueues = 0;
    const seen: Array<{ url: string; id: string; auth: string | null }> = [];
    const source = new Request("https://ordax.example/mcp", {
      method: "POST", headers: { "authorization": "Bearer signed-mcp-client", "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 10, method: "tools/call",
        params: { name: "ordax_action_status", arguments: { request_id: acceptedId } } }),
    });
    const response = await handleOrdaxMcp(source, {
      session: async () => Response.json({ ok: true }),
      targets: async () => { assert.fail("direct status cannot discover targets"); },
      createAction: async () => { enqueues++; assert.fail("direct status cannot enqueue"); },
      getAction: async (req, id) => {
        reads++;
        seen.push({ url: req.url, id, auth: req.headers.get("authorization") });
        if (reads === 1) {
          if (transient === "throw") throw Error("postgres://secret@internal");
          return Response.json({ error: "private database state" }, { status: transient });
        }
        return Response.json(record({ status: "succeeded", result: { completion: "canonical" } }));
      },
    });
    assert.equal(response.status, 200);
    const body = await response.json() as any;
    assert.equal(enqueues, 0);
    assert.equal(reads, 2);
    assert.deepEqual(seen, [
      { url: "https://ordax.example/v3/product/actions/" + acceptedId,
        id: acceptedId, auth: "Bearer signed-mcp-client" },
      { url: "https://ordax.example/v3/product/actions/" + acceptedId,
        id: acceptedId, auth: "Bearer signed-mcp-client" },
    ]);
    assert.equal(body.result.isError, false);
    assert.equal(body.result.structuredContent.request_id, acceptedId);
    assert.equal(body.result.structuredContent.action.status, "succeeded");
    assert.deepEqual(body.result.structuredContent.action.result, { completion: "canonical" });
    assert.doesNotMatch(JSON.stringify(body), /postgres:\/\/secret|private database state/);
  }
});

test("direct status caps 5xx retries, retains uncertainty and never retries 401/403/404/429", async () => {
  for (const status of [401, 403, 404, 429, 503]) {
    let calls = 0;
    const { body } = await call("ordax_action_status", {
      createAction: async () => { assert.fail("status must remain read-only"); },
      getAction: async () => {
        calls++;
        return Response.json({ internal: "server secret" }, { status });
      },
    });
    assert.equal(calls, status === 503 ? 2 : 1);
    assert.equal(body.result.isError, true);
    assert.equal(body.result.structuredContent.monitoring_state, "unknown");
    assert.equal(body.result.structuredContent.request_id, acceptedId);
    assert.equal(Object.hasOwn(body.result.structuredContent, "pending"), false);
    assert.doesNotMatch(JSON.stringify(body), /server secret/);
  }
});

test("direct status succeeds immediately without extra queries when PostgreSQL responds", async () => {
  let reads = 0;
  const { body } = await call("ordax_action_status", {
    createAction: async () => { assert.fail("status cannot enqueue"); },
    getAction: async () => {
      reads++;
      return Response.json(record({ status: "queued" }));
    },
  });
  assert.equal(reads, 1);
  assert.equal(body.result.isError, false);
  assert.equal(body.result.structuredContent.pending, true);
  assert.equal(body.result.structuredContent.action.status, "queued");
});
