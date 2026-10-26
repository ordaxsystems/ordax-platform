import assert from "node:assert/strict";
import test from "node:test";
import { createCanonicalProductMcpReadHandlers } from "../cloudflare/src/product_mcp_reads.ts";
import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";
import { env, owner, otherOwner, client, otherClient, device, token, withIssuer, request, catalog } from "./product_mcp_test_fixtures.mts";

const allowDiscovery = async (_env: unknown, ownerUserId: string, clientId: string) => ({
  ok: true, ownerUserId, clientId, devices_granted: 0,
});

test("signed owner and exact OAuth client materialize discovery then reach canonical targets", async () => {
  await withIssuer(async () => {
    const calls: unknown[] = [];
    const grants: unknown[] = [];
    const handlers = createCanonicalProductMcpReadHandlers(env, {
      ensureDiscovery: async (receivedEnv, ownerUserId, clientId) => {
        assert.equal(receivedEnv, env);
        grants.push({ ownerUserId, clientId });
        return { ok: true, devices_granted: 1 };
      },
      listTargets: async (receivedEnv, identity) => {
        assert.equal(receivedEnv, env);
        calls.push(identity);
        return catalog();
      },
    });
    for (const signedClient of [client, otherClient]) {
      const response = await handlers.targets(request(await token({ client_id: signedClient }),
        "/v3/product/targets?owner_user_id=" + otherOwner + "&client_id=" + otherClient));
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("cache-control"), "no-store");
      const body = await response.json();
      assert.deepEqual(body.targets.map((item: any) => [item.name, item.online]), [["Meu desktop", true], ["Notebook", false]]);
      assert.equal(body.targets[1].last_seen_at, "2026-10-09T12:00:00.000Z");
      assert.equal(JSON.stringify(body).includes("private-device-token"), false);
      assert.equal(JSON.stringify(body).includes("internal-group"), false);
    }
    assert.deepEqual(grants, [
      { ownerUserId: owner, clientId: client },
      { ownerUserId: owner, clientId: otherClient },
    ]);
    assert.deepEqual(calls, [
      { ownerUserId: owner, clientKind: "product-mcp", clientId: client },
      { ownerUserId: owner, clientKind: "product-mcp", clientId: otherClient },
    ]);
  });
});

test("session identifies OAuth owner without interpreting login as a device grant", async () => {
  await withIssuer(async () => {
    const handlers = createCanonicalProductMcpReadHandlers(env, {
      ensureDiscovery: async () => { assert.fail("session must not grant discovery"); },
      listTargets: async () => { assert.fail("session must not read grants"); },
    });
    const response = await handlers.session(request(await token(), "/v3/product/session"));
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
    const body = await response.json();
    assert.equal(body.session.subject_id, owner);
    assert.equal(body.session.client_id, client);
    assert.equal(body.session.client_kind, "product-mcp");
    assert.equal("targets" in body, false);
    assert.equal("grants" in body, false);
  });
});

test("plain user login, invalid OAuth role and expired token cannot materialize target authority", async () => {
  await withIssuer(async () => {
    const handlers = createCanonicalProductMcpReadHandlers(env, {
      ensureDiscovery: async () => { assert.fail("unauthorized grant call"); },
      listTargets: async () => { assert.fail("unauthorized RPC call"); },
    });
    for (const [claims, status] of [
      [{ client_id: undefined, user_metadata: { client_id: client } }, 403],
      [{ role: "anon" }, 403],
      [{ exp: Math.floor(Date.now() / 1000) - 3600 }, 401],
    ] as const) {
      const req = request(await token(claims));
      assert.equal((await handlers.session(req)).status, status);
      assert.equal((await handlers.targets(req)).status, status);
    }
    assert.equal((await handlers.targets(new Request("https://ordax.example/v3/product/targets"))).status, 401);
  });
});

test("revoked OAuth consent fails closed before target enumeration", async () => {
  await withIssuer(async () => {
    const handlers = createCanonicalProductMcpReadHandlers(env, {
      ensureDiscovery: async () => ({ ok: false, error: "product_mcp_oauth_consent_required" }),
      listTargets: async () => { assert.fail("revoked consent must not enumerate targets"); },
    });
    const denied = await handlers.targets(request(await token()));
    assert.equal(denied.status, 403);
    assert.deepEqual(await denied.json(), { ok: false, error: "product_mcp_oauth_consent_required" });
  });
});

test("each discovery re-materializes minimal authority then re-reads target eligibility", async () => {
  await withIssuer(async () => {
    let calls = 0;
    let grants = 0;
    const handlers = createCanonicalProductMcpReadHandlers(env, {
      ensureDiscovery: async () => { grants++; return { ok: true, devices_granted: 0 }; },
      listTargets: async () => {
        calls++;
        if (calls === 1) return catalog();
        if (calls === 2) return { ok: true, targets: [] };
        return { ok: false, error: "product_owner_auth_ineligible", private_detail: "never-export" };
      },
    });
    const req = request(await token());
    assert.equal((await (await handlers.targets(req)).json()).targets.length, 2);
    assert.deepEqual(await (await handlers.targets(req)).json(), { ok: true, targets: [] });
    const denied = await handlers.targets(req);
    assert.equal(denied.status, 403);
    assert.deepEqual(await denied.json(), { ok: false, error: "product_owner_auth_ineligible" });
    assert.equal(calls, 3);
    assert.equal(grants, 3);
  });
});

test("unconfigured PostgreSQL and transport failure cannot fall back to legacy authority or leak secrets", async () => {
  await withIssuer(async () => {
    const req = request(await token());
    const unconfigured = await createCanonicalProductMcpReadHandlers(env).targets(req);
    assert.equal(unconfigured.status, 503);
    assert.deepEqual(await unconfigured.json(), { ok: false, error: "product_postgres_unconfigured" });
    const unavailable = await createCanonicalProductMcpReadHandlers(env, {
      ensureDiscovery: allowDiscovery as any,
      listTargets: async () => { throw new Error("postgres://private-secret@internal-db SQL private details"); },
    }).targets(req);
    assert.equal(unavailable.status, 503);
    assert.deepEqual(await unavailable.json(), { ok: false, error: "product_targets_unavailable" });
    assert.equal(unavailable.headers.get("cache-control"), "no-store");
  });
});

test("malformed canonical catalogs fail rather than fabricating an empty available registry", async () => {
  await withIssuer(async () => {
    for (const result of [null, {}, { ok: true }, { ok: true, targets: {} },
      { ok: true, targets: [{ device_id: "legacy:device" }] },
      { ok: true, targets: [{ device_id: device }, { device_id: device.toUpperCase() }] },
      { ok: false, error: "private-server-details" },
    ]) {
      const handlers = createCanonicalProductMcpReadHandlers(env, {
        ensureDiscovery: allowDiscovery as any,
        listTargets: async () => result as any,
      });
      const response = await handlers.targets(request(await token()));
      assert.equal(response.status, 502);
      assert.deepEqual(await response.json(), { ok: false, error: "product_postgres_invalid_response" });
    }
  });
});

test("MCP request uses signed session for read-only discovery and never enqueues work", async () => {
  await withIssuer(async () => {
    let reads = 0;
    let grants = 0;
    const handlers = createCanonicalProductMcpReadHandlers(env, {
      ensureDiscovery: async (_, ownerUserId, clientId) => {
        grants++;
        assert.equal(ownerUserId, owner);
        assert.equal(clientId, client);
        return { ok: true, devices_granted: 1 };
      },
      listTargets: async (_, identity) => {
        reads++;
        assert.deepEqual(identity, { ownerUserId: owner, clientKind: "product-mcp", clientId: client });
        return catalog();
      },
    });
    const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
      method: "POST", headers: { authorization: "Bearer " + await token(), "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: {
        name: "ordax_targets", arguments: { owner_user_id: otherOwner, client_id: otherClient },
      } }),
    }), {
      ...handlers,
      createAction: async () => { assert.fail("discovery must not enqueue an action"); },
      getAction: async () => { assert.fail("discovery must not inspect an action"); },
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.result.isError, false);
    assert.equal(body.result.structuredContent.targets[1].online, false);
    assert.equal(reads, 1);
    assert.equal(grants, 1);
    assert.equal(JSON.stringify(body).includes("private-device-token"), false);
  });
});

test("signed client-specific catalogs never borrow another OAuth client's device candidate",async()=>{
  await withIssuer(async()=>{
    const desktop=device,notebook="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    const discovery={profile_key:"mcp-discovery",space_id:null,project_id:null,valid_until:null,
      capabilities:[{capability:"product.target.read",access_mode:"read"}]};
    const action={profile_key:"computer-observe",space_id:null,project_id:null,valid_until:null,
      capabilities:[{capability:"computer.windows",access_mode:"read"}]};
    const handlers=createCanonicalProductMcpReadHandlers(env,{
      ensureDiscovery:async()=>({ok:true,devices_granted:0}),
      listTargets:async(_,identity)=>({ok:true,targets:[
        {device_id:desktop,online:true,grant_groups:[discovery,...(identity.clientId===client?[action]:[])]},
        {device_id:notebook,online:false,grant_groups:[discovery,...(identity.clientId===otherClient?[action]:[])]},
      ]}),
    });
    for(const [signedClient,expectedDevice] of [[client,desktop],[otherClient,notebook]]) {
      const response=await handlers.targets(request(await token({client_id:signedClient}),
        "/v3/product/targets?client_id="+(signedClient===client?otherClient:client)));
      assert.equal(response.status,200);
      const hint=(await response.json()).client_device_routing;
      assert.equal(hint.state,"single_action_grant_candidate");
      assert.equal(hint.candidate_device_id,expectedDevice);
      assert.equal(hint.attested,false);
    }
  });
});
