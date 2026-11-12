import assert from "node:assert/strict";
import test from "node:test";
import { handleOrdaxMcp } from "../cloudflare/src/mcp_http.ts";
import { OWNER_MCP_GRANT_PROFILES } from "../cloudflare/src/product_owner_grant_profiles.ts";

async function listTargets(targets: unknown[], authenticated = true) {
  let created = 0;
  const response = await handleOrdaxMcp(new Request("https://ordax.example/mcp", {
    method: "POST", headers: { "content-type": "application/json", authorization: "Bearer fixture" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "ordax_targets", arguments: {} } }),
  }), {
    session: async () => Response.json({ ok: authenticated }, { status: authenticated ? 200 : 401 }),
    targets: async request => {
      assert.equal(request.headers.get("authorization"), "Bearer fixture");
      return Response.json({ ok: true, targets });
    },
    createAction: async () => { created++; return Response.json({ ok: false }); },
    getAction: async () => Response.json({ ok: false }),
  });
  assert.equal(created, 0);
  return { status: response.status, body: await response.json() };
}

test("canonical target identity, offline presence and authorized grant groups remain visible to the plugin", async () => {
  const { body } = await listTargets([{
    device_id: "desktop-1", device_name: "Desktop principal", online: false,
    last_seen_at: "2026-10-09T12:00:00Z", device_kind: "desktop", channel: "stable",
    private_token: "must-not-leak", raw_path: "C:/private",
    grant_groups: [{ grant_group_id: "internal", profile_key: "project-read", space_id: "space-1", project_id: "project-1", valid_until: null,
      capabilities: [{ capability: "workspace.text_read", access_mode: "read", secret: "never" }] }],
  }]);
  const result = body.result.structuredContent;
  assert.equal(body.result.isError, false);
  assert.equal(result.targets[0].name, "Desktop principal"); assert.equal(result.targets[0].device_name, "Desktop principal");
  assert.equal(result.targets[0].online, false); assert.equal(result.targets[0].last_seen_at, "2026-10-09T12:00:00.000Z");
  assert.deepEqual(result.targets[0].grant_groups[0], {
    profile_key: "project-read", space_id: "space-1", project_id: "project-1", valid_until: null,
    capabilities: [{ capability: "workspace.text_read", access_mode: "read" }],
  });
  assert.ok(!JSON.stringify(result).includes("must-not-leak")); assert.ok(!JSON.stringify(result).includes("C:/private"));
  assert.ok(!JSON.stringify(result).includes("internal")); assert.ok(!JSON.stringify(result).includes("never"));
});

test("retired D1 target fields cannot restore obsolete grants, names or fake connectivity", async () => {
  const { body } = await listTargets([{ device_id: "legacy", name: "Legado", last_seen_at: "2026-10-09T12:00:00Z", grants: [{ space_id: "space", actions: ["git.status"], projects: ["demo"] }] }]);
  const target = body.result.structuredContent.targets[0];
  assert.equal(target.name, "ORDAX device"); assert.equal(target.online, null);
  assert.equal(Object.hasOwn(target, "grants"), false);
  assert.deepEqual(target.grant_groups, []);
  assert.ok(!JSON.stringify(body).includes("git.status"));
  assert.ok(!JSON.stringify(body).includes("Legado"));
});

test("invalid presence, scope data and unbounded groups cannot become capabilities", async () => {
  const { body } = await listTargets([null, { device_id: "../escape" }, {
    device_id: "valid", online: "true", last_seen_at: "invalid",
    grant_groups: Array(140).fill({ profile_key: "x".repeat(129), capabilities: [null, { capability: "computer.click", access_mode: "admin" }] }),
  }]);
  const targets = body.result.structuredContent.targets;
  assert.equal(targets.length, 1); assert.equal(targets[0].online, null); assert.equal(targets[0].last_seen_at, null);
  assert.equal(targets[0].grant_groups.length, 128); assert.equal(targets[0].grant_groups[0].profile_key, null);
  assert.deepEqual(targets[0].grant_groups[0].capabilities, []);
});

test("mixed desktop and mobile discovery exposes metadata without executing or granting file access", async () => {
  const { body } = await listTargets([
    { device_id: "owned-mobile", device_name: "Telefone", device_kind: "mobile", online: true,
      grant_groups: [], files: ["private-phone-file"], camera: true, execute: true },
    { device_id: "owned-desktop", device_name: "Estação", device_kind: "desktop", online: false,
      grant_groups: [] },
  ]);
  const targets = body.result.structuredContent.targets;
  assert.equal(targets.length, 2);
  assert.equal(targets[0].device_id, "owned-mobile");
  assert.equal(targets[0].device_kind, "mobile");
  assert.equal(targets[0].online, true);
  assert.equal(Object.hasOwn(targets[0], "grants"), false);
  assert.deepEqual(targets[0].grant_groups, []);
  assert.equal(targets[1].device_kind, "desktop");
  assert.equal(targets[1].online, false);
  for (const field of ["files", "camera", "execute"]) assert.equal(Object.hasOwn(targets[0], field), false);
  assert.ok(!JSON.stringify(body).includes("private-phone-file"));
});

test("unauthenticated discovery remains unavailable", async () => {
  const result = await listTargets([{ device_id: "private-device" }], false);
  assert.equal(result.status, 401); assert.ok(!JSON.stringify(result.body).includes("private-device"));
});

test("client-scoped target routing reports only non-discovery device grants, never dispatches",async()=>{
  const desktop="dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  const notebook="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
  const discover={profile_key:"mcp-discovery",space_id:null,project_id:null,
    valid_until:null,capabilities:[{capability:"product.target.read",access_mode:"read"}]};
  const action={profile_key:"full-computer-control",space_id:null,project_id:null,
    valid_until:null,capabilities:[{capability:"computer.windows",access_mode:"read"}]};
  const {body}=await listTargets([
    {device_id:desktop,online:true,grant_groups:[discover]},
    {device_id:notebook,online:false,grant_groups:[discover,action]}
  ]);
  const result=body.result.structuredContent;
  assert.equal(result.client_device_routing.state,"single_action_grant_candidate");
  assert.equal(result.client_device_routing.candidate_device_id,notebook);
  assert.equal(result.client_device_routing.reported_online,false);
  assert.equal(result.client_device_routing.attested,false);
  assert.equal(result.client_device_routing.dispatch_authorized,false);
  assert.ok(!JSON.stringify(result).includes("authorized_device_id"));
});

test("routing never promotes discovery, expired, project or incomplete grants",async()=>{
  const desktop="dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  const discovery={profile_key:"mcp-discovery",space_id:null,project_id:null,valid_until:null,
    capabilities:[{capability:"product.target.read",access_mode:"read"}]};
  const denied=[
    discovery,
    {profile_key:"project-native-process",space_id:"space",project_id:"project",valid_until:null,
      capabilities:[{capability:"process.start",access_mode:"write"}]},
    {profile_key:"computer-observe",space_id:null,project_id:null,
      valid_until:"2020-01-01T00:00:00Z",capabilities:[{capability:"computer.windows",access_mode:"read"}]},
  ];
  const onlyDiscovery=(await listTargets([{device_id:desktop,online:true,grant_groups:denied}]))
    .body.result.structuredContent;
  assert.deepEqual(onlyDiscovery.client_device_routing,{
    state:"no_device_action_grant",owner_action:"authorize_in_ordax_owner_permissions",
    basis:"current_oauth_client_target_catalog",attested:false,dispatch_authorized:false
  });
  const partial=(await listTargets([{device_id:desktop,grant_groups:Array(128).fill(discovery)}]))
    .body.result.structuredContent;
  assert.equal("client_device_routing" in partial,false);
  const missingGroups=(await listTargets([{device_id:desktop}])).body.result.structuredContent;
  assert.equal("client_device_routing" in missingGroups,false);
});

test("existing full-control Owner grant exposes newly missing transfer rights without automatic expansion", async () => {
  const desktop = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  const canonical = OWNER_MCP_GRANT_PROFILES["full-computer-control"];
  assert.ok(canonical);
  const oldCapabilities = canonical.capabilities
    .filter(item => !item.capability.startsWith("computer.transfer_"))
    .map(item => ({ capability: item.capability, access_mode: item.accessMode }));
  const { body } = await listTargets([{
    device_id: desktop, online: true, grant_groups: [{
      profile_key: "full-computer-control", space_id: null, project_id: null,
      valid_until: null, capabilities: oldCapabilities,
    }],
  }]);
  const group = body.result.structuredContent.targets[0].grant_groups[0];
  assert.equal(group.capabilities.length, oldCapabilities.length);
  assert.equal(group.profile_alignment.state, "owner_reauthorization_required");
  assert.equal(group.profile_alignment.owner_action, "reauthorize_existing_profile_in_ordax_owner");
  assert.equal(group.profile_alignment.authorization_required, true);
  assert.equal(group.profile_alignment.attested, false);
  assert.deepEqual(group.profile_alignment.missing_capabilities, [
    { capability: "computer.transfer_abort", access_mode: "write" },
    { capability: "computer.transfer_begin", access_mode: "write" },
    { capability: "computer.transfer_chunk", access_mode: "write" },
    { capability: "computer.transfer_commit", access_mode: "write" },
    { capability: "computer.transfer_status", access_mode: "read" },
  ]);
  assert.equal(group.capabilities.some((item: { capability: string }) =>
    item.capability.startsWith("computer.transfer_")), false);
  assert.equal(body.result.structuredContent.client_device_routing.attested, false);
  assert.equal(body.result.structuredContent.client_device_routing.dispatch_authorized, false);
});

test("aligned grants are quiet and expired or non-device grants never claim current profile drift", async () => {
  const canonical = OWNER_MCP_GRANT_PROFILES["full-computer-control"];
  const capabilities = canonical.capabilities.map(item => ({
    capability: item.capability, access_mode: item.accessMode,
  }));
  const group = (overrides: Record<string, unknown>) => ({
    profile_key: "full-computer-control", space_id: null, project_id: null,
    valid_until: null, capabilities, ...overrides,
  });
  const { body } = await listTargets([{
    device_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    grant_groups: [
      group({}),
      group({ capabilities: [], valid_until: "2020-01-01T00:00:00Z" }),
      group({ capabilities: [], space_id: "space-one", project_id: "project-one" }),
      group({ capabilities: undefined }),
      group({ capabilities: Array(129).fill({ capability: "computer.windows", access_mode: "read" }) }),
    ],
  }]);
  for (const result of body.result.structuredContent.targets[0].grant_groups) {
    assert.equal("profile_alignment" in result, false);
  }
});

test("multiple action targets remain ambiguous, never automatically selected",async()=>{
  const action={profile_key:"computer-observe",space_id:null,project_id:null,
    valid_until:null,capabilities:[{capability:"computer.windows",access_mode:"read"}]};
  const targets=["dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"].map(device_id=>({
    device_id,online:true,grant_groups:[action]
  }));
  const result=(await listTargets(targets)).body.result.structuredContent;
  assert.equal(result.client_device_routing.state,"multiple_action_grant_candidates");
  assert.equal(result.client_device_routing.owner_action,"review_oauth_client_device_grants");
  assert.equal("candidate_device_id" in result.client_device_routing,false);
});
