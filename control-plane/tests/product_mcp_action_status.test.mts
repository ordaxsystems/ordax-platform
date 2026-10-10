import assert from "node:assert/strict";
import test from "node:test";
import { createCanonicalProductMcpReadHandlers } from "../cloudflare/src/product_mcp_reads.ts";
import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";
import {
  env, owner, otherOwner, client, otherClient, requestId, projectId,
  token, withIssuer, request, actionRecord,
} from "./product_mcp_test_fixtures.mts";

test("status reader receives only signed owner/exact client and the requested canonical action UUID", async () => {
  await withIssuer(async () => {
    const calls: unknown[] = [];
    const handlers = createCanonicalProductMcpReadHandlers(env, {
      listTargets: async () => { assert.fail("accepted history must not enumerate devices"); },
      getAction: async (receivedEnv, input) => {
        assert.equal(receivedEnv, env);
        calls.push(input);
        return input.ownerUserId === owner && input.clientId === client ? actionRecord() : null;
      },
    });
    for (const [signedOwner, signedClient, expectedStatus] of [
      [owner, client, 200], [owner, otherClient, 404], [otherOwner, client, 404],
    ] as const) {
      const response = await handlers.getAction(request(await token({ sub: signedOwner, client_id: signedClient }),
        `/v3/product/actions/${requestId}?owner_user_id=${owner}&client_id=${client}`), requestId);
      assert.equal(response.status, expectedStatus);
      assert.equal(response.headers.get("cache-control"), "no-store");
      if (expectedStatus === 404) assert.deepEqual(await response.json(), { ok: false, error: "product_action_not_found" });
    }
    assert.deepEqual(calls, [
      { ownerUserId: owner, clientKind: "product-mcp", clientId: client, requestId },
      { ownerUserId: owner, clientKind: "product-mcp", clientId: otherClient, requestId },
      { ownerUserId: otherOwner, clientKind: "product-mcp", clientId: client, requestId },
    ]);
  });
});

test("invalid credentials and invalid request UUID are denied before reading action authority", async () => {
  await withIssuer(async () => {
    const handlers = createCanonicalProductMcpReadHandlers(env, {
      getAction: async () => { assert.fail("invalid caller/resource must not reach RPC"); },
    });
    for (const [claims, status] of [
      [{ client_id: undefined }, 403], [{ role: "anon" }, 403],
      [{ exp: Math.floor(Date.now() / 1000) - 3600 }, 401],
    ] as const) {
      assert.equal((await handlers.getAction(request(await token(claims)), requestId)).status, status);
    }
    for (const invalidId of ["", "request-1", "../../private", requestId + "?owner=another"]) {
      const response = await handlers.getAction(request(await token()), invalidId);
      assert.equal(response.status, 400);
      assert.deepEqual(await response.json(), { ok: false, error: "product_request_id_invalid" });
    }
    assert.equal((await handlers.getAction(new Request("https://ordax.example/mcp"), requestId)).status, 401);
  });
});

test("status preserves published UUIDs and Product result, excluding extra database columns", async () => {
  await withIssuer(async () => {
    const result = { ok: true, summary: "Arquivo consultado", data: { content: "texto autorizado" } };
    const handlers = createCanonicalProductMcpReadHandlers(env, { getAction: async () => actionRecord({
      status: "succeeded", result, finished_at: "2026-10-09T12:02:00Z",
      private_token: "private-device-token", payload: { api_key: "private-api-key" },
      owner_user_id: owner, grant_id: "internal-grant", client_id: client,
    }) });
    const response = await handlers.getAction(request(await token()), requestId.toUpperCase());
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.action.request_id, requestId);
    assert.equal(body.action.device_id, "dddddddd-dddd-4ddd-8ddd-dddddddddddd");
    assert.equal(body.action.subject_id, owner);
    assert.equal(body.action.client_id, client);
    assert.equal(body.action.project_id, projectId);
    assert.equal(body.action.project, null);
    assert.equal(body.action.action, "project.text_read");
    assert.equal(body.action.status, "succeeded");
    assert.equal(body.action.created_at, "2026-10-09T12:00:00.000Z");
    assert.equal(body.action.finished_at, "2026-10-09T12:02:00.000Z");
    assert.deepEqual(body.action.result, result);
    for (const secret of ["private-device-token", "private-api-key", "internal-grant", owner, client]) {
      assert.equal(JSON.stringify(body).includes(secret), false);
    }
  });
});

test("MCP polls the same accepted action through all statuses without dispatch or device discovery", async () => {
  await withIssuer(async () => {
    let status = "queued";
    let calls = 0;
    const handlers = createCanonicalProductMcpReadHandlers(env, {
      listTargets: async () => { assert.fail("offline/unknown device does not block accepted history"); },
      getAction: async (_, input) => {
        calls++;
        assert.equal(input.requestId, requestId);
        return actionRecord({ status, error_code: status === "failed" ? "runtime_action_failed" : null });
      },
    });
    for (const next of ["queued", "leased", "running", "succeeded", "failed", "cancelled"]) {
      status = next;
      const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
        method: "POST", headers: { authorization: "Bearer " + await token(), "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: {
          name: "ordax_action_status", arguments: { request_id: requestId, owner_user_id: otherOwner, client_id: otherClient },
        } }),
      }), { ...handlers, createAction: async () => { assert.fail("status polling must never dispatch or replay"); } });
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("cache-control"), "no-store");
      const body = await response.json();
      const data = body.result.structuredContent;
      assert.equal(data.request_id, requestId);
      assert.equal(data.action.status, next);
      assert.equal(data.action.name, "project.text_read");
      assert.equal(data.action.device_id, "dddddddd-dddd-4ddd-8ddd-dddddddddddd");
      assert.equal(data.action.subject_id, undefined);
      assert.equal(data.action.client_id, undefined);
      assert.equal(data.action.project_id, projectId);
      assert.equal(data.action.project, null);
      assert.equal(data.pending, ["queued", "leased", "running"].includes(next));
      assert.equal(data.action.error_code, next === "failed" ? "runtime_action_failed" : null);
    }
    assert.equal(calls, 6);
  });
});

test("account eligibility is checked by the status RPC on each read, without retaining a prior result", async () => {
  await withIssuer(async () => {
    let reads = 0;
    const handlers = createCanonicalProductMcpReadHandlers(env, { getAction: async () => {
      reads++;
      return reads === 1 ? actionRecord() : { ok: false, error: "product_owner_auth_ineligible", private_detail: "not-public" };
    } });
    const req = request(await token());
    assert.equal((await handlers.getAction(req, requestId)).status, 200);
    const denied = await handlers.getAction(req, requestId);
    assert.equal(denied.status, 403);
    assert.equal(denied.headers.get("cache-control"), "no-store");
    assert.deepEqual(await denied.json(), { ok: false, error: "product_owner_auth_ineligible" });
    assert.equal(reads, 2);
  });
});

test("malformed/mismatched canonical results cannot masquerade as an accepted action", async () => {
  await withIssuer(async () => {
    for (const result of [
      {}, [], actionRecord({ ok: false }), actionRecord({ request_id: projectId }),
      actionRecord({ device_id: "legacy-device" }), actionRecord({ project_id: "legacy-project" }),
      actionRecord({ effect_id: null }), actionRecord({ capability: "shell; private" }),
      actionRecord({ status: "unknown" }), actionRecord({ created_at: "not-a-date" }),
      actionRecord({ started_at: "not-a-date" }), actionRecord({ finished_at: 42 }),
      actionRecord({ error_code: "private\nSQL" }), actionRecord({ result: undefined }),
    ]) {
      const handlers = createCanonicalProductMcpReadHandlers(env, { getAction: async () => result as any });
      const response = await handlers.getAction(request(await token()), requestId);
      assert.equal(response.status, 502);
      assert.deepEqual(await response.json(), { ok: false, error: "product_postgres_invalid_response" });
    }
  });
});

test("missing PostgreSQL configuration and transport failure do not fall back or expose SQL details", async () => {
  await withIssuer(async () => {
    const req = request(await token());
    const unavailable = await createCanonicalProductMcpReadHandlers(env).getAction(req, requestId);
    assert.equal(unavailable.status, 503);
    assert.deepEqual(await unavailable.json(), { ok: false, error: "product_postgres_unconfigured" });
    const failed = await createCanonicalProductMcpReadHandlers(env, { getAction: async () => {
      throw new Error("postgres://secret@internal SQL private_table");
    } }).getAction(req, requestId);
    assert.equal(failed.status, 503);
    assert.equal(failed.headers.get("cache-control"), "no-store");
    assert.deepEqual(await failed.json(), { ok: false, error: "product_action_status_unavailable" });
  });
});
