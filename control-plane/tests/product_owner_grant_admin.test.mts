import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  handleProductOwnerGrantAdmin, parseOwnerWorkspaceResourceRevocation,
} from "../cloudflare/src/product_owner_grant_admin.ts";
import {
  OWNER_MCP_GRANT_PROFILES,
  productCapabilityAccessMode,
} from "../cloudflare/src/product_owner_grant_profiles.ts";
import { env, token, withIssuer, client } from "./product_mcp_test_fixtures.mts";
import {
  COMPUTER_DEVICE_ACTIONS,
  OBSERVE_COMPUTER_CONTROL_MODE,
  TEXT_EDIT_COMPUTER_CONTROL_MODE,
  PROJECT_BROWSER_ACTIONS,
} from "../cloudflare/src/product_action_scope.ts";

const HERE=path.dirname(fileURLToPath(import.meta.url));

test("owner grant profiles are explicit and observation remains least privilege", () => {
  const full=OWNER_MCP_GRANT_PROFILES["full-computer-control"];
  assert.equal(full.scope,"device");
  assert.deepEqual(full.capabilities.map((item)=>item.capability), [...COMPUTER_DEVICE_ACTIONS].sort());
  assert.equal(productCapabilityAccessMode("computer.screenshot"),"read");
  assert.equal(productCapabilityAccessMode("computer.click"),"write");

  const observe=OWNER_MCP_GRANT_PROFILES[OBSERVE_COMPUTER_CONTROL_MODE];
  assert.equal(observe.scope,"device");
  assert.deepEqual(observe.capabilities, [
    {capability:"computer.access_status",accessMode:"read"},
    {capability:"computer.active_window",accessMode:"read"},
    {capability:"computer.processes",accessMode:"read"},
    {capability:"computer.screen_info",accessMode:"read"},
    {capability:"computer.windows",accessMode:"read"},
  ]);
  assert.equal(observe.capabilities.some((item)=>[
    "computer.click","computer.screenshot","computer.terminate_process","computer.type",
  ].includes(item.capability)),false);

  const textEdit=OWNER_MCP_GRANT_PROFILES[TEXT_EDIT_COMPUTER_CONTROL_MODE];
  assert.equal(textEdit.scope,"device");
  assert.deepEqual(textEdit.capabilities, [
    {capability:"computer.directory_list",accessMode:"read"},
    {capability:"computer.file_stat",accessMode:"read"},
    {capability:"computer.text_patch",accessMode:"write"},
    {capability:"computer.text_read",accessMode:"read"},
    {capability:"computer.text_write",accessMode:"write"},
    {capability:"computer.transfer_abort",accessMode:"write"},
    {capability:"computer.transfer_begin",accessMode:"write"},
    {capability:"computer.transfer_chunk",accessMode:"write"},
    {capability:"computer.transfer_commit",accessMode:"write"},
    {capability:"computer.transfer_status",accessMode:"read"},
  ]);
  for (const excluded of [
    "computer.path_remove", "computer.path_move", "computer.terminate_process",
    "computer.clipboard_read", "computer.click", "computer.screenshot",
  ]) {
    assert.equal(textEdit.capabilities.some(item => item.capability===excluded), false);
  }

  const browser=OWNER_MCP_GRANT_PROFILES["project-browser-automation"];
  assert.equal(browser.scope,"project");
  assert.deepEqual(browser.capabilities.map((item)=>item.capability), [...PROJECT_BROWSER_ACTIONS].sort());
  assert.equal(productCapabilityAccessMode("browser.snapshot"),"read");
  assert.equal(productCapabilityAccessMode("browser.navigate"),"write");
  const workspace=OWNER_MCP_GRANT_PROFILES["project-workspace-read"];
  assert.equal(workspace.scope,"project");
  assert.deepEqual(workspace.capabilities,[{
    capability:"workspace.project_snapshot",accessMode:"read",
  }]);
  assert.equal(productCapabilityAccessMode("workspace.project_snapshot"),"read");
  assert.equal(workspace.capabilities.some(item=>item.accessMode==="write"),false);
  assert.equal(workspace.capabilities.some(item=>item.capability.startsWith("computer.")),false);
});

test("owner grant admin fails closed before database access without signed owner session", async () => {
  const env={PRODUCT_AUTH_ISSUER:"https://issuer.example/auth/v1",PRODUCT_AUTH_AUDIENCE:"authenticated",PRODUCT_AUTH_JWKS_URL:"https://issuer.example/auth/v1/.well-known/jwks.json"} as any;
  const get=await handleProductOwnerGrantAdmin(new Request(
    "https://mcp.example/v3/owner/remote-authority?device_id=11111111-1111-4111-8111-111111111111",
  ),env);
  assert.equal(get.status,401);
  const post=await handleProductOwnerGrantAdmin(new Request(
    "https://mcp.example/v3/owner/remote-grant-groups",
    {method:"POST",headers:{"content-type":"application/json"},body:"{}"},
  ),env);
  assert.equal(post.status,401);
});

test("all Owner grant and consent routes reject delegated OAuth clients before any mutation", async () => {
  await withIssuer(async () => {
    const pinnedOwnerClient = "202fd3e1-b058-4531-8750-82c57e4b6ca0";
    const configured = {
      ...env,
      PRODUCT_OWNER_OAUTH_CLIENT_ID: pinnedOwnerClient,
      CENTRAL_OWNER_SELECTION_ENABLED: "enabled",
      CENTRAL_OWNER_TARGET_PREFLIGHT_ENABLED: "enabled",
      WORKSPACE_RESOURCE_VERIFIER_ENABLED: "enabled",
      WORKSPACE_RESOURCE_ISSUANCE_ENABLED: "enabled",
    } as any;
    const device = "11111111-1111-4111-8111-111111111111";
    const group = "22222222-2222-4222-8222-222222222222";
    const challenge = "33333333-3333-4333-8333-333333333333";
    const origin = "https://mcp.ordax.com.br";
    const cases = [
      {url: "/v3/owner/remote-authority?device_id="+device, method: "GET"},
      {url: "/v3/owner/remote-grant-groups", method: "POST", body: {}},
      {url: "/v3/owner/remote-grant-groups/"+group+"?client_id="+client, method: "DELETE"},
      {url: "/v3/owner/central-session-targets?client_id="+client, method: "GET"},
      {url: "/v3/owner/central-session-selections?client_id="+client, method: "GET"},
      {url: "/v3/owner/central-session-selections", method: "POST",
       body: {client_id:client, challenge_id:challenge, device_id:device}},
      {url: "/v3/owner/workspace-resources/approvals", method: "POST", body: {}},
      {url: "/v3/owner/workspace-resources/resource_aaaaaaaa?client_id="+client, method: "DELETE"},
    ] as const;
    const delegatedToken = await token(); // Signed but NOT Owner-authorized.
    for (const c of cases) {
      const request = new Request(origin+c.url, {
        method: c.method,
        headers: { authorization: "Bearer "+delegatedToken,
          ...("body" in c ? {"content-type":"application/json"} : {}) },
        ...("body" in c ? {body: JSON.stringify(c.body)} : {}),
      });
      const response = await handleProductOwnerGrantAdmin(request, configured);
      assert.equal(response.status, 403, c.url);
      assert.deepEqual(await response.json(), {ok:false,error:"owner_primary_session_required"}, c.url);
    }
    // A signed native Owner's OAuth client, or normal first-party account
    // session without client_id, may reach validation without this denial.
    for (const authorized of [await token({client_id: pinnedOwnerClient}), await token({client_id:null})]) {
      const response = await handleProductOwnerGrantAdmin(new Request(origin+"/v3/owner/remote-grant-groups", {
        method: "POST",headers: {authorization:"Bearer "+authorized,"content-type":"application/json"},
        body: JSON.stringify({}),
      }), configured);
      assert.equal(response.status, 400);
      assert.deepEqual(await response.json(), {ok:false,error:"owner_grant_invalid"});
    }
    // Misconfigured pin must not silently accept an OAuth client.
    const denied = await handleProductOwnerGrantAdmin(new Request(origin+"/v3/owner/remote-grant-groups", {
      method:"POST",headers:{authorization:"Bearer "+await token({client_id:pinnedOwnerClient}),
        "content-type":"application/json"},body:"{}",
    }), {...env} as any);
    assert.equal(denied.status,403);
  });
});

test("Owner authority query boundaries reject duplicate, unexpected and ignored identifiers", async () => {
  await withIssuer(async () => {
    const firstParty = await token({client_id: null});
    const device = "11111111-1111-4111-8111-111111111111";
    const group = "22222222-2222-4222-8222-222222222222";
    const origin = "https://mcp.ordax.com.br";
    const cases = [
      {url: "/v3/owner/remote-authority", method: "GET", error: "device_id_invalid"},
      {url: "/v3/owner/remote-authority?device_id="+device+"&device_id="+device, method: "GET", error: "device_id_invalid"},
      {url: "/v3/owner/remote-authority?device_id="+device+"&owner_user_id="+device, method: "GET", error: "device_id_invalid"},
      {url: "/v3/owner/remote-authority?device_id="+device+"&space_id="+device, method: "GET", error: "device_id_invalid"},
      {url: "/v3/owner/remote-grant-groups?client_id="+client, method: "POST", error: "owner_grant_invalid"},
      {url: "/v3/owner/remote-grant-groups?space_id="+device, method: "POST", error: "owner_grant_invalid"},
      {url: "/v3/owner/remote-grant-groups/"+group+"?client_id="+client+"&client_id="+client, method: "DELETE", error: "owner_grant_revoke_invalid"},
      {url: "/v3/owner/remote-grant-groups/"+group+"?client_id="+client+"&space_id="+device, method: "DELETE", error: "owner_grant_revoke_invalid"},
      {url: "/v3/owner/remote-grant-groups/"+group+"?client_id="+client+"&owner_user_id="+device, method: "DELETE", error: "owner_grant_revoke_invalid"},
      {url: "/v3/owner/remote-grant-groups/"+group+"?client_id="+client+"&%63lient_id="+client, method: "DELETE", error: "owner_grant_revoke_invalid"},
    ] as const;
    for (const input of cases) {
      const response = await handleProductOwnerGrantAdmin(new Request(origin + input.url, {
        method: input.method,
        headers: {
          authorization: "Bearer " + firstParty,
          ...(input.method === "POST" ? {"content-type":"application/json"} : {}),
        },
        ...(input.method === "POST" ? {body:"{}"} : {}),
      }), env);
      assert.equal(response.status, 400, input.url);
      assert.deepEqual(await response.json(), {ok:false,error:input.error}, input.url);
    }
  });
});

test("owner grant source contains no device-link or pairing authority", () => {
  const source=fs.readFileSync(path.resolve(HERE,"../cloudflare/src/product_owner_grant_admin.ts"),"utf8")
    +fs.readFileSync(path.resolve(HERE,"../cloudflare/src/product_owner_grant_profiles.ts"),"utf8");
  for (const forbidden of ["device-link","pairing_secret","claim_device_pairing","ORDAX_OPERATOR_TOKEN","D1Database"])
    assert.equal(source.includes(forbidden),false,forbidden);
  for (const required of ["replaceOwnerMcpGrantGroup","revokeOwnerMcpGrantGroup","ownerMcpGrantProfile"])
    assert.equal(source.includes(required),true,required);
});

test("Owner workspace revocation only accepts exact opaque resource and consented client identifiers", async () => {
  const resource="resource_"+"a".repeat(32);
  const client="11111111-1111-4111-8111-111111111111";
  const root="https://mcp.example/v3/owner/workspace-resources/";
  const parse=(suffix: string) => parseOwnerWorkspaceResourceRevocation(new URL(root+suffix));
  assert.deepEqual(parse(resource+"?client_id="+client),{clientId:client,resourceId:resource});
  for(const query of [
    resource,
    resource+"?client_id=invalid",
    resource+"?client_id="+client+"&client_id="+client,
    resource+"?client_id="+client+"&owner_user_id="+client,
    resource+"?client_id="+client+"&path=private",
    "resource_"+ "a".repeat(7)+"?client_id="+client,
    "resource_"+ "a".repeat(161)+"?client_id="+client,
    "path%2Fprivate?client_id="+client,
    "../private?client_id="+client,
    resource+"/extra?client_id="+client,
  ]) assert.equal(parse(query),null,query);
  assert.equal(parseOwnerWorkspaceResourceRevocation(new URL(
    "https://mcp.example/v3/owner/remote-authority?client_id="+client
  )),null);

  const env={
    PRODUCT_AUTH_ISSUER:"https://issuer.example/auth/v1",
    PRODUCT_AUTH_AUDIENCE:"authenticated",
    PRODUCT_AUTH_JWKS_URL:"https://issuer.example/auth/v1/.well-known/jwks.json",
  } as any;
  const unauth=await handleProductOwnerGrantAdmin(new Request(
    root+resource+"?client_id="+client,{method:"DELETE"},
  ),env);
  assert.equal(unauth.status,401);
  assert.deepEqual(await unauth.json(),{ok:false,error:"product_auth_required"});

  const source=fs.readFileSync(path.resolve(HERE,"../cloudflare/src/product_owner_grant_admin.ts"),"utf8");
  const store=fs.readFileSync(path.resolve(HERE,"../cloudflare/src/product_postgres_store.ts"),"utf8");
  assert.match(source,/WORKSPACE_RESOURCE_VERIFIER_ENABLED !== "enabled"/);
  assert.match(source,/revokeProjectWorkspaceResource\(env/);
  assert.match(store,/ordax_revoke_project_workspace_resource_v1/);
  assert.ok(!source.includes("issueProjectWorkspaceResource"));
});

test("Owner grant request never turns missing or blank scope/expiry into global permanent authority", async () => {
  await withIssuer(async () => {
    const firstParty = await token({ client_id: null });
    const device = "11111111-1111-4111-8111-111111111111";
    const space = "22222222-2222-4222-8222-222222222222";
    const project = "33333333-3333-4333-8333-333333333333";
    const validExpiry = "2026-12-01T12:00:00.000Z";
    const canonicalDeviceGrant = {
      client_id: client, device_id: device, profile_key: OBSERVE_COMPUTER_CONTROL_MODE,
      space_id: null, project_id: null, valid_until: null,
    };
    const calls: Array<Record<string, unknown>> = [];
    const deps = { replaceGrantGroup: async (_env: any, input: any) => {
      calls.push(input);
      return { ok: true };
    } };
    const post = async (body: Record<string, unknown>) => handleProductOwnerGrantAdmin(
      new Request("https://mcp.ordax.com.br/v3/owner/remote-grant-groups", {
        method: "POST",
        headers: {
          authorization: "Bearer " + firstParty,
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
      }),
      env, deps,
    );

    // The old parser silently converted *all* three missing/blank values to
    // null, unintentionally authorizing a global or unlimited-lifetime grant.
    for (const key of ["space_id", "project_id", "valid_until"] as const) {
      const omitted = { ...canonicalDeviceGrant };
      delete (omitted as any)[key];
      const missing = await post(omitted);
      assert.equal(missing.status, 400, "missing " + key);
      assert.deepEqual(await missing.json(), { ok: false, error: "owner_grant_invalid" });

      const blank = await post({ ...canonicalDeviceGrant, [key]: "" });
      assert.equal(blank.status, 400, "blank " + key);
      assert.deepEqual(await blank.json(), { ok: false, error: "owner_grant_invalid" });
    }
    assert.equal(calls.length, 0, "invalid requests never reach the grant writer");

    // JSON null is the only intentional unscoped/indefinite value. Nothing
    // in the HTTP handler invents or transforms a grant without the Owner.
    const explicit = await post(canonicalDeviceGrant);
    assert.equal(explicit.status, 200);
    assert.equal((await explicit.json()).ok, true);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].ownerUserId, "11111111-1111-4111-8111-111111111111");
    assert.equal(calls[0].clientId, client);
    assert.equal(calls[0].spaceId, null);
    assert.equal(calls[0].projectId, null);
    assert.equal(calls[0].validUntil, null);

    // An explicitly scoped and time-limited grant remains supported, without
    // losing the Space, project or expiration at the PostgreSQL boundary.
    const projectGrant = await post({
      client_id: client, device_id: device, profile_key: "project-native-process",
      space_id: space, project_id: project, valid_until: validExpiry,
    });
    assert.equal(projectGrant.status, 200);
    assert.equal(calls.length, 2);
    assert.equal(calls[1].spaceId, space);
    assert.equal(calls[1].projectId, project);
    assert.equal(calls[1].validUntil, validExpiry);
  });
});
