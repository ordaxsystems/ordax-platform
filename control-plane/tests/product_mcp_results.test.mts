import assert from "node:assert/strict";
import test from "node:test";
import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";
import { scopeProductResult } from "../cloudflare/src/product_results.ts";

for (const status of ["queued", "leased", "running", "succeeded", "failed", "cancelled"]) {
  test(`action status preserves ${status} and its continuation id`, async () => {
    const handlers = {
      session: async () => Response.json({ ok: true }),
      targets: async () => Response.json({ ok: true, targets: [] }),
      createAction: async () => Response.json({ ok: true, request_id: "request-1" }),
      getAction: async () => Response.json({ ok: true, action: { request_id: "request-1", action: "git.status", status, result: null } }),
    };
    for (const name of ["ordax_action_status", "git_status"]) {
      const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: {
          name, arguments: { request_id: "request-1", device_id: "device-1", project: "review", wait_for_completion_ms: 0 },
        } }),
      }), handlers);
      const { result } = await response.json();
      const pending = ["queued", "leased", "running"].includes(status);
      assert.equal(result.structuredContent.pending, pending);
      assert.equal(result.structuredContent.request_id, "request-1");
      if (name === "ordax_action_status") assert.equal(result.structuredContent.action.status, status);
      if (pending) assert.equal(result.isError, false);
      else if (name === "git_status") assert.equal(result.isError, status !== "succeeded");
    }
  });
}


async function callQueuedAction(handlers: Parameters<typeof handleOrdaxMcp>[1], waitMs: number) {
  const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 5, method: "tools/call", params: {
      name: "git_status", arguments: { device_id: "device-1", project: "review", wait_for_completion_ms: waitMs },
    } }),
  }), handlers);
  const { result } = await response.json();
  return result;
}

test("pending tool wait preserves the exact queued, leased and running stage", async () => {
  for (const stage of ["queued", "leased", "running"]) {
    const result = await callQueuedAction({
      session: async () => Response.json({ ok: true }),
      targets: async () => Response.json({ ok: true, targets: [] }),
      createAction: async () => Response.json({ ok: true, request_id: "request-1" }),
      getAction: async () => Response.json({ ok: true, action: {
        request_id: "request-1", action: "git.status", status: stage, result: null,
      } }),
    }, 0);
    assert.equal(result.structuredContent.pending, true);
    assert.equal(result.structuredContent.action.status, stage);
    assert.equal(result.structuredContent.request_id, "request-1");
    assert.match(result.structuredContent.message, /ordax_action_status/);
    assert.doesNotMatch(result.structuredContent.message, /Action is still running/);
  }
});

test("a lost status query after accepted enqueue does not assert action failure or enqueue twice", async () => {
  for (const failure of ["throw", "503", "429", "401", "invalid"] as const) {
    let createCount = 0;
    const result = await callQueuedAction({
      session: async () => Response.json({ ok: true }),
      targets: async () => Response.json({ ok: true, targets: [] }),
      createAction: async () => {
        createCount++;
        return Response.json({ ok: true, request_id: "request-1" });
      },
      getAction: async () => {
        if (failure === "throw") throw new Error("db unreachable");
        if (failure === "invalid") return Response.json({ ok: true, action: { invalid: true } });
        return Response.json({ ok: false }, { status: Number(failure) });
      },
    }, 0);
    assert.equal(createCount, 1);
    assert.equal(result.structuredContent.request_id, "request-1");
    if (failure === "401") {
      assert.equal(result.structuredContent.ok, false);
      assert.equal(result.structuredContent.pending, false);
      assert.equal(result.isError, true);
    } else {
      assert.equal(result.structuredContent.ok, true);
      assert.equal(result.structuredContent.pending, true);
      assert.equal(result.structuredContent.monitoring_error, "action_status_unavailable");
      assert.match(result.structuredContent.message, /Do not resubmit/);
      assert.equal(result.isError, false);
    }
  }
});

test("queued wait uses bounded backoff instead of a 250ms database polling loop", async () => {
  let reads = 0;
  const result = await callQueuedAction({
    session: async () => Response.json({ ok: true }),
    targets: async () => Response.json({ ok: true, targets: [] }),
    createAction: async () => Response.json({ ok: true, request_id: "request-1" }),
    getAction: async () => {
      reads++;
      return Response.json({ ok: true, action: {
        request_id: "request-1", action: "git.status", status: "queued", result: null,
      } });
    },
  }, 1100);
  assert.equal(result.structuredContent.action.status, "queued");
  assert.equal(result.structuredContent.pending, true);
  assert.ok(reads >= 2 && reads <= 4, `unexpected status-poll count: ${reads}`);
});

test("successful completion during a bounded wait is returned, not left pending", async () => {
  let reads = 0;
  const result = await callQueuedAction({
    session: async () => Response.json({ ok: true }),
    targets: async () => Response.json({ ok: true, targets: [] }),
    createAction: async () => Response.json({ ok: true, request_id: "request-1" }),
    getAction: async () => {
      reads++;
      return Response.json({ ok: true, action: {
        request_id: "request-1", action: "git.status",
        status: reads === 1 ? "queued" : "succeeded", result: { ok: true },
      } });
    },
  }, 2000);
  assert.equal(reads, 2);
  assert.equal(result.structuredContent.pending, false);
  assert.equal(result.structuredContent.action.status, "succeeded");
});


const legacyResult = { ok: true, summary: "projects", data: {
  default_project: "private", active_project: "private", root: "C:/private",
  projects: [
    { slug: "review", apps: [], available: true, path: "C:/review", repository: { branch: "main", root: "C:/review" } },
    { slug: "private", apps: ["blender"], available: true },
  ],
} };

for (const action of ["projects.list", "workspace.repository_catalog"]) {
  test(`${action} filters older agent results with the original grant`, () => {
    const result = scopeProductResult(action, legacyResult, '["review"]') as any;
    assert.deepEqual(result.data.projects.map((item: any) => item.slug), ["review"]);
    assert.equal(result.data.default_project, undefined);
    assert.equal(result.data.active_project, undefined);
    assert.equal(JSON.stringify(result).includes("C:/"), false);
    assert.deepEqual(legacyResult.data.projects.map((item) => item.slug), ["review", "private"]);
  });
  for (const grant of [null, "invalid", "[]", '["review",42]']) {
    test(`${action} fails closed for grant ${grant}`, () => {
      const result = scopeProductResult(action, legacyResult, grant) as any;
      assert.deepEqual(result.data.projects, []);
    });
  }
}

test("authorized default and project-specific results remain available", () => {
  const result = scopeProductResult("projects.list", legacyResult, '["private"]') as any;
  assert.equal(result.data.default_project, "private");
  assert.equal(scopeProductResult("project.text_read", legacyResult, null), legacyResult);
  assert.equal(scopeProductResult("projects.list", null, '["review"]'), null);
});
