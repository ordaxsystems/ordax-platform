import assert from "node:assert/strict";
import test from "node:test";
import { PROJECT_ARTIFACT_ACTIONS } from "../cloudflare/src/product_action_scope.ts";
import { OWNER_MCP_GRANT_PROFILES } from "../cloudflare/src/product_owner_grant_profiles.ts";
import { validAttestedProjectActionArguments, catalogAllowsAttestedProjectAction } from "../cloudflare/src/product_mcp_attested_project_action.ts";
import { PRODUCT_MCP_DIRECT_TOOLS } from "../cloudflare/src/product_mcp_entry.ts";

const device = "11111111-1111-4111-8111-111111111111";
const space = "22222222-2222-4222-8222-222222222222";
const project = "33333333-3333-4333-8333-333333333333";
const scope = { spaceId: space, projectId: project, repositoryFullName: "ordaxsystems/ordax-os" };
const group = { profile_key: "project-artifact-read", space_id: space, project_id: project,
  valid_until: null, capabilities: [
    { capability: "artifact.preview", access_mode: "read" },
    { capability: "artifacts.list", access_mode: "read" },
  ] };
const catalog = { ok: true, targets: [{ device_id: device, grant_groups: [group] }] };

test("artifact read actions have a narrow project grant and direct catalog tools", () => {
  assert.deepEqual([...PROJECT_ARTIFACT_ACTIONS].sort(), ["artifact.preview", "artifacts.list"]);
  assert.equal(OWNER_MCP_GRANT_PROFILES["project-artifact-read"].scope, "project");
  assert.deepEqual(OWNER_MCP_GRANT_PROFILES["project-artifact-read"].capabilities.map(c => c.accessMode), ["read", "read"]);
  assert.equal(PRODUCT_MCP_DIRECT_TOOLS.has("artifact_preview"), true);
  assert.equal(PRODUCT_MCP_DIRECT_TOOLS.has("artifacts_list"), true);
});
test("artifact parameters are bounded before enqueue", () => {
  assert.equal(validAttestedProjectActionArguments("artifacts.list", { max_items: 100 }), true);
  assert.equal(validAttestedProjectActionArguments("artifacts.list", { max_items: 101 }), false);
  assert.equal(validAttestedProjectActionArguments("artifact.preview", { project_artifact_paths: ["a.png"] }), true);
  assert.equal(validAttestedProjectActionArguments("artifact.preview", { project_artifact_paths: Array(101).fill("a.png") }), false);
  assert.equal(validAttestedProjectActionArguments("artifact.preview", { project_artifact_paths: ["a.png"], project_artifact_path: "b.png" }), false);
  assert.equal(validAttestedProjectActionArguments("artifact.preview", { project_artifact_paths: ["a.png"], thumbnail: true }), false);
  assert.equal(validAttestedProjectActionArguments("artifact.preview", { max_bytes: 262145 }), false);
  assert.equal(validAttestedProjectActionArguments("artifact.preview", { artifact_name: "a.jpg", project_artifact_path: "b.jpg" }), false);
  assert.equal(validAttestedProjectActionArguments("artifact.preview", { artifact_name: "a.jpg" }), true);
  assert.equal(validAttestedProjectActionArguments("artifact.preview", { quality: 93 }), false);
});
test("browser screenshot preview requires an explicit boolean without changing project-bound grants", () => {
  const session_id = "44444444-4444-4444-8444-444444444444";
  assert.equal(validAttestedProjectActionArguments("browser.screenshot", { session_id }), true);
  assert.equal(validAttestedProjectActionArguments("browser.screenshot", { session_id, include_preview: true }), true);
  assert.equal(validAttestedProjectActionArguments("browser.screenshot", { session_id, include_preview: false }), true);
  assert.equal(validAttestedProjectActionArguments("browser.screenshot", { session_id, include_preview: "true" }), false);
  assert.equal(validAttestedProjectActionArguments("browser.screenshot", { session_id, include_preview: 1 }), false);
});

test("artifact grant does not inherit authority from other profiles or projects", () => {
  assert.equal(catalogAllowsAttestedProjectAction(catalog, device, scope, "artifact.preview"), true);
  assert.equal(catalogAllowsAttestedProjectAction(catalog, device, scope, "artifacts.list"), true);
  assert.equal(catalogAllowsAttestedProjectAction(catalog, device, { ...scope, projectId: space }, "artifact.preview"), false);
  assert.equal(catalogAllowsAttestedProjectAction({ok:true,targets:[{device_id:device,
    grant_groups:[{...group,profile_key:"project-workspace-read"}]}]},device,scope,"artifact.preview"),false);
  assert.equal(catalogAllowsAttestedProjectAction({ok:true,targets:[{device_id:device,
    grant_groups:[{...group,valid_until:"2020-01-01T00:00:00Z"}]}]},device,scope,"artifact.preview"),false);
  assert.equal(catalogAllowsAttestedProjectAction(catalog, device, scope, "terminal.exec"), false);
});

test("local service preview requires its own project grant and bounded route arguments", () => {
  const action = "artifact.local_service_preview";
  const args = { service_id: "curation", requests: [{ route: "/thumb/42", query: { w: 256 } }] };
  assert.equal(PRODUCT_MCP_DIRECT_TOOLS.has("artifact_local_service_preview"), true);
  assert.equal(OWNER_MCP_GRANT_PROFILES["project-local-service-read"].scope, "project");
  assert.deepEqual(OWNER_MCP_GRANT_PROFILES["project-local-service-read"].capabilities,
    [{ capability: action, accessMode: "read" }]);
  assert.equal(validAttestedProjectActionArguments(action, args), true);
  for (const invalid of [
    { ...args, url: "http://127.0.0.1:8769" },
    { ...args, requests: [{ route: "http://127.0.0.1:8769/thumb/42" }] },
    { ...args, requests: [{ route: "/thumb/../secret" }] },
    { ...args, requests: [{ route: "/thumb/%2f42" }] },
    { ...args, requests: [{ route: "/thumb/42", method: "POST" }] },
    { ...args, requests: Array(9).fill(args.requests[0]) },
    { ...args, max_bytes: 262145 },
  ]) assert.equal(validAttestedProjectActionArguments(action, invalid), false);
  assert.equal(catalogAllowsAttestedProjectAction(catalog, device, scope, action), false);
  const specific = { ...group, profile_key: "project-local-service-read",
    capabilities: [{ capability: action, access_mode: "read" }] };
  const allowed = { ok: true, targets: [{ device_id: device, grant_groups: [specific] }] };
  assert.equal(catalogAllowsAttestedProjectAction(allowed, device, scope, action), true);
  assert.equal(catalogAllowsAttestedProjectAction(allowed, device, { ...scope, projectId: space }, action), false);
  assert.equal(catalogAllowsAttestedProjectAction(allowed, device, scope, "artifact.preview"), false);
});
