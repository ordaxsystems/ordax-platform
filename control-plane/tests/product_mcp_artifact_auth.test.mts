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
