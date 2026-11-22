import assert from "node:assert/strict";
import test from "node:test";
import { handleOrdaxMcp, canonicalProductStatusPollDelayMs } from "../cloudflare/src/mcp_http.ts";
import { scopeProductResult } from "../cloudflare/src/product_results.ts";

// PostgreSQL Product queue receipts are UUIDs, not arbitrary transport strings.
const acceptedId = "11111111-1111-4111-8111-111111111111";

for (const status of ["queued", "leased", "running", "succeeded", "failed", "cancelled"]) {
  test(`action status preserves ${status} and its continuation id`, async () => {
    const handlers = {
      session: async () => Response.json({ ok: true }),
      targets: async () => Response.json({ ok: true, targets: [] }),
      createAction: async () => Response.json({ ok: true, request_id: acceptedId }),
      getAction: async () => Response.json({ ok: true, action: { request_id: acceptedId, action: "git.status", status, result: null } }),
    };
    for (const name of ["ordax_action_status", "git_status"]) {
      const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: {
          name, arguments: { request_id: acceptedId, device_id: "device-1", project: "review", wait_for_completion_ms: 0 },
        } }),
      }), handlers);
      const { result } = await response.json();
      const pending = ["queued", "leased", "running"].includes(status);
      assert.equal(result.structuredContent.pending, pending);
      assert.equal(result.structuredContent.request_id, acceptedId);
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
      createAction: async () => Response.json({ ok: true, request_id: acceptedId }),
      getAction: async () => Response.json({ ok: true, action: {
        request_id: acceptedId, action: "git.status", status: stage, result: null,
      } }),
    }, 0);
    assert.equal(result.structuredContent.pending, true);
    assert.equal(result.structuredContent.action.status, stage);
    assert.equal(result.structuredContent.request_id, acceptedId);
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
        return Response.json({ ok: true, request_id: acceptedId });
      },
      getAction: async () => {
        if (failure === "throw") throw new Error("db unreachable");
        if (failure === "invalid") return Response.json({ ok: true, action: { invalid: true } });
        return Response.json({ ok: false }, { status: Number(failure) });
      },
    }, 0);
    assert.equal(createCount, 1);
    assert.equal(result.structuredContent.request_id, acceptedId);
    if (failure === "401") {
      assert.equal(result.structuredContent.ok, false);
      assert.equal(Object.hasOwn(result.structuredContent, "pending"), false);
      assert.equal(result.structuredContent.monitoring_state, "unknown");
      assert.equal(result.structuredContent.error, "action_status_access_denied");
      assert.match(result.structuredContent.message, /Do not resubmit/);
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

test("pending Product action status uses deadline-bounded slower reads without caching auth", () => {
  const sample = (budget: number, old = false) => {
    let elapsed = 0, round = 0, reads = 0;
    const delays: number[] = [];
    while (true) {
      reads++;
      if (elapsed >= budget) break;
      const remaining = budget - elapsed;
      const delay = old
        ? Math.min(remaining, 250 * (2 ** Math.min(round, 3)), 1500)
        : canonicalProductStatusPollDelayMs(remaining, round);
      delays.push(delay);
      elapsed += delay;
      round++;
    }
    return { reads, delays, elapsed };
  };
  assert.equal(canonicalProductStatusPollDelayMs(0, 9), 0);
  assert.equal(canonicalProductStatusPollDelayMs(-1, 0), 0);
  assert.deepEqual([0, 1, 2, 3, 4, 5].map(round =>
    canonicalProductStatusPollDelayMs(20000, round)), [250, 500, 1000, 2000, 2500, 2500]);
  assert.equal(canonicalProductStatusPollDelayMs(77, 6), 77,
    "the final read must always reach the exact caller deadline");
  const short = sample(8000);
  const long = sample(20000);
  assert.equal(short.reads, 7);
  assert.equal(long.reads, 12);
  assert.equal(short.elapsed, 8000);
  assert.equal(long.elapsed, 20000);
  assert.equal(sample(8000, true).reads, 9);
  assert.equal(sample(20000, true).reads, 17);
  assert.equal(sample(0).reads, 1, "an immediate status lookup is still one current-authority read");
});

test("queued wait uses bounded backoff instead of a 250ms database polling loop", async () => {
  let reads = 0;
  const result = await callQueuedAction({
    session: async () => Response.json({ ok: true }),
    targets: async () => Response.json({ ok: true, targets: [] }),
    createAction: async () => Response.json({ ok: true, request_id: acceptedId }),
    getAction: async () => {
      reads++;
      return Response.json({ ok: true, action: {
        request_id: acceptedId, action: "git.status", status: "queued", result: null,
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
    createAction: async () => Response.json({ ok: true, request_id: acceptedId }),
    getAction: async () => {
      reads++;
      return Response.json({ ok: true, action: {
        request_id: acceptedId, action: "git.status",
        status: reads === 1 ? "queued" : "succeeded", result: { ok: true },
      } });
    },
  }, 2000);
  assert.equal(reads, 2);
  assert.equal(result.structuredContent.pending, false);
  assert.equal(result.structuredContent.action.status, "succeeded");
});


test("fresh queued enqueue waits for the attested completion hint before its first SQL status read", async () => {
  const device="dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  let available=false,reads=0,signals=0;
  const result=await callQueuedAction({
    session:async()=>Response.json({ok:true}),
    targets:async()=>Response.json({ok:true,targets:[]}),
    createAction:async()=>Response.json({ok:true,request_id:acceptedId,status:"queued",replayed:false}),
    verifiedActionDeviceId:device,
    waitForCompletion:async(receivedDevice,id,remainingMs)=>{
      assert.equal(receivedDevice,device);
      assert.equal(id,acceptedId);
      assert.ok(remainingMs>0 && remainingMs<=500,
        "first advisory wait must consume at most one quarter of the requested budget");
      assert.equal(reads,0,"signal must precede the redundant first SQL status read");
      signals++;
      available=true;
      return "signalled";
    },
    getAction:async()=>{
      reads++;
      return Response.json({ok:true,action:{
        request_id:acceptedId,device_id:device,action:"git.status",
        status:available?"succeeded":"queued",result:available?{ok:true}:null,
      }});
    },
  },2000);
  assert.equal(signals,1);
  assert.equal(reads,1,"a fast completion must consume one current-authority status read, not two");
  assert.equal(result.structuredContent.action.status,"succeeded");
  assert.equal(result.structuredContent.pending,false);
});

test("unavailable completion channel preserves a fresh SQL read with no guessed result",async()=>{
  const device="dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  let reads=0,signals=0;
  const result=await callQueuedAction({
    session:async()=>Response.json({ok:true}),
    targets:async()=>Response.json({ok:true,targets:[]}),
    createAction:async()=>Response.json({ok:true,request_id:acceptedId,status:"queued"}),
    verifiedActionDeviceId:device,
    waitForCompletion:async()=>{signals++;return "unavailable";},
    getAction:async()=>{
      reads++;
      return Response.json({ok:true,action:{
        request_id:acceptedId,device_id:device,action:"git.status",
        status:"succeeded",result:{ok:true},
      }});
    },
  },1000);
  assert.equal(signals,1);
  assert.equal(reads,1);
  assert.equal(result.structuredContent.action.status,"succeeded");
});

test("stale completion hint cannot repeat DO wake or manufacture a finished status",async()=>{
  const device="dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  let reads=0,signals=0;
  const result=await callQueuedAction({
    session:async()=>Response.json({ok:true}),
    targets:async()=>Response.json({ok:true,targets:[]}),
    createAction:async()=>Response.json({ok:true,request_id:acceptedId,status:"queued"}),
    verifiedActionDeviceId:device,
    waitForCompletion:async()=>{signals++;return "signalled";},
    getAction:async()=>{
      reads++;
      return Response.json({ok:true,action:{
        request_id:acceptedId,device_id:device,action:"git.status",
        status:"queued",result:null,
      }});
    },
  },25);
  assert.equal(signals,1,"replayed completion signal cannot drive a busy DO loop");
  assert.ok(reads>=1 && reads<5);
  assert.equal(result.structuredContent.pending,true);
  assert.equal(result.structuredContent.action.status,"queued");
});

test("direct status ID stays SQL-first even when a verified action device is available",async()=>{
  let reads=0,signals=0;
  const device="dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  const response=await handleOrdaxMcp(new Request("https://ordax.example/mcp",{
    method:"POST",headers:{"content-type":"application/json"},
    body:JSON.stringify({jsonrpc:"2.0",id:47,method:"tools/call",
      params:{name:"ordax_action_status",arguments:{request_id:acceptedId,wait_for_completion_ms:1000}}}),
  }),{
    session:async()=>Response.json({ok:true}),
    targets:async()=>Response.json({ok:true,targets:[]}),
    createAction:async()=>{assert.fail("status must never enqueue");return Response.json({});},
    verifiedActionDeviceId:device,
    waitForCompletion:async()=>{
      assert.equal(reads,1,"unverified status UUID must be authorized by SQL before any DO wait");
      signals++;
      return "signalled";
    },
    getAction:async()=>{
      reads++;
      return Response.json({ok:true,action:{request_id:acceptedId,device_id:device,
        action:"git.status",status:reads===1?"queued":"succeeded",
        result:reads===1?null:{ok:true}}});
    },
  });
  const result=(await response.json() as any).result.structuredContent;
  assert.equal(signals,1);
  assert.equal(reads,2);
  assert.equal(result.action.status,"succeeded");
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

const previewBase64 = Buffer.from([0xff, 0xd8, 0xff, 0xd9]).toString("base64");
const previewData = {
  mime_type: "image/jpeg", size_bytes: 4, sha256: "a".repeat(64),
  base64: previewBase64, image_count: 2, unique_image_count: 1,
  items: [{ image_id: "I001", tile_id: "I001", project_artifact_path: "a.jpg" },
    { image_id: "I002", tile_id: "I001", project_artifact_path: "b.jpg" }],
};

async function imageStatusReceipt(data: Record<string, unknown>, actionName = "artifact.preview",
  status = "succeeded", outcomeOk = true) {
  const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 17, method: "tools/call", params: {
      name: "ordax_action_status", arguments: { request_id: acceptedId },
    } }),
  }), {
    session: async () => Response.json({ ok: true }),
    targets: async () => Response.json({ ok: true, targets: [] }),
    createAction: async () => Response.json({ ok: true, request_id: acceptedId }),
    getAction: async () => Response.json({ ok: true, action: {
      request_id: acceptedId, action: actionName, status,
      result: { ok: outcomeOk, summary: "preview", data },
    } }),
  });
  const envelope = await response.json();
  return envelope.result;
}

test("completed artifact preview emits native MCP image block without duplicating binary in text or structured data", async () => {
  const receipt = await imageStatusReceipt(previewData) as any;
  assert.equal(receipt.content.length, 2);
  assert.equal(receipt.content[1].type, "image");
  assert.equal(receipt.content[1].mimeType, "image/jpeg");
  assert.equal(receipt.content[1].data, previewBase64);
  assert.equal(receipt.structuredContent.pending, false);
  assert.equal(receipt.structuredContent.request_id, acceptedId);
  assert.equal(receipt.structuredContent.action.name, "artifact.preview");
  assert.equal(receipt.structuredContent.action.result.data.base64, undefined);
  assert.equal(receipt.structuredContent.action.result.data.image_count, 2);
  assert.equal(receipt.structuredContent.action.result.data.items[1].tile_id, "I001");
  assert.equal(receipt.content[0].text.includes(previewBase64), false);
  assert.equal(JSON.stringify(receipt.structuredContent).includes(previewBase64), false);
});

test("image content projection fails closed for unrelated actions, failed outcomes and invalid binary budgets", async () => {
  for (const [data, action, status, ok] of [
    [previewData, "computer.terminal_exec", "succeeded", true],
    [previewData, "artifact.preview", "failed", false],
    [{ ...previewData, mime_type: "application/json" }, "artifact.preview", "succeeded", true],
    [{ ...previewData, size_bytes: 262145 }, "artifact.preview", "succeeded", true],
    [{ ...previewData, size_bytes: 2 }, "artifact.preview", "succeeded", true],
    [{ ...previewData, base64: "NOT-BASE64" }, "artifact.preview", "succeeded", true],
  ] as const) {
    const receipt = await imageStatusReceipt(data, action, status, ok) as any;
    assert.equal(receipt.content.length, 1);
    assert.equal(receipt.content[0].type, "text");
    assert.equal(receipt.structuredContent.action.result.data.base64, data.base64);
  }
});

test("artifact preview schema advertises bounded image batches without changing grants", async () => {
  const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 19, method: "tools/list", params: {} }),
  }), {
    session: async () => Response.json({ ok: true }),
    targets: async () => Response.json({ ok: true, targets: [] }),
    createAction: async () => Response.json({ ok: true, request_id: acceptedId }),
    getAction: async () => Response.json({ ok: true }),
  });
  const envelope = await response.json() as any;
  const tool = envelope.result.tools.find((item: any) => item.name === "artifact_preview");
  assert.ok(tool, "existing project-scoped artifact tool must remain in generic catalog");
  assert.equal(tool.inputSchema.properties.project_artifact_paths.minItems, 1);
  assert.equal(tool.inputSchema.properties.project_artifact_paths.maxItems, 100);
  assert.equal(tool.inputSchema.required.includes("project"), true);
});

// An explicitly requested screenshot is already authorized by its device
// screenshot grant. Reuse the native image projection, without extra grants.
test("opt-in computer screenshot emits one native image and keeps full-resolution metadata", async () => {
  const receipt = await imageStatusReceipt({
    ...previewData, scope: "device", mode: "desktop", width: 1920, height: 1080,
    source_size_bytes: 748321, thumbnail_size: [960, 540],
  }, "computer.screenshot") as any;
  assert.equal(receipt.content.length, 2);
  assert.equal(receipt.content[1].type, "image");
  assert.equal(receipt.content[1].mimeType, "image/jpeg");
  assert.equal(receipt.structuredContent.action.name, "computer.screenshot");
  assert.equal(receipt.structuredContent.action.result.data.source_size_bytes, 748321);
  assert.equal(receipt.structuredContent.action.result.data.base64, undefined);
  assert.equal(receipt.content[0].text.includes(previewBase64), false);
});

test("opt-in browser screenshot produces native MCP image while retaining project-session metadata", async () => {
  const receipt = await imageStatusReceipt({
    ...previewData, session_id: "44444444-4444-4444-8444-444444444444",
    artifact_name: "browser-owned.png", width: 1440, height: 900,
    source_size_bytes: 102400, thumbnail_size: [960, 600],
  }, "browser.screenshot") as any;
  assert.equal(receipt.content.length, 2);
  assert.equal(receipt.content[1].type, "image");
  assert.equal(receipt.content[1].mimeType, "image/jpeg");
  assert.equal(receipt.structuredContent.action.name, "browser.screenshot");
  assert.equal(receipt.structuredContent.action.result.data.artifact_name, "browser-owned.png");
  assert.equal(receipt.structuredContent.action.result.data.source_size_bytes, 102400);
  assert.equal(receipt.structuredContent.action.result.data.base64, undefined);
  assert.equal(receipt.content[0].text.includes(previewBase64), false);
});

test("browser screenshot defaults to original PNG metadata without an image content block", async () => {
  const receipt = await imageStatusReceipt({
    session_id: "44444444-4444-4444-8444-444444444444",
    artifact_name: "browser-owned.png", width: 1440, height: 900, size_bytes: 102400,
  }, "browser.screenshot") as any;
  assert.equal(receipt.content.length, 1);
  assert.equal(receipt.structuredContent.action.result.data.size_bytes, 102400);
});

test("screenshot without preview remains metadata-only and cannot manufacture an image block", async () => {
  const receipt = await imageStatusReceipt({
    scope: "device", mode: "desktop", width: 1920, height: 1080, size_bytes: 748321,
  }, "computer.screenshot") as any;
  assert.equal(receipt.content.length, 1);
  assert.equal(receipt.structuredContent.action.result.data.width, 1920);
});
