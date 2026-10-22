import assert from "node:assert/strict";
import test from "node:test";

import {
  createOwnerWorkspaceResourceHandler,
  PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH,
} from "../cloudflare/src/product_workspace_resource_api.ts";

const OWNER = "11111111-1111-4111-8111-111111111111";
const ACTOR = "22222222-2222-4222-8222-222222222222";
const CLIENT = "33333333-3333-4333-8333-333333333333";
const DEVICE = "44444444-4444-4444-8444-444444444444";
const SPACE = "55555555-5555-4555-8555-555555555555";
const PROJECT = "66666666-6666-4666-8666-666666666666";
const RESOURCE = "resource_abcdefgh12345678";
const ENV = {
  PRODUCT_AUTH_ISSUER: "https://auth.example.test",
  PRODUCT_AUTH_AUDIENCE: "authenticated",
  PRODUCT_AUTH_JWKS_URL: "https://auth.example.test/.well-known/jwks.json",
  POSTGRES: { connectionString: "postgresql://localhost/example" },
};
const identity = {
  ok: true as const,
  subjectId: OWNER,
  issuer: ENV.PRODUCT_AUTH_ISSUER,
  audience: ENV.PRODUCT_AUTH_AUDIENCE,
  expiresAt: Date.now() + 60_000,
  clientId: CLIENT,
  role: "authenticated",
};
const repo = "ordaxsystems/veste-demo";
const requestFields = {
  actor_id: ACTOR,
  client_id: CLIENT,
  lab_project_id: "lab_veste",
  repository_full_name: repo,
  resource_id: RESOURCE,
  workspace_session_id: "session_veste",
};
const dbProof = {
  ok: true,
  schema: "ordax.project-workspace-resource/1",
  grant: {
    grant_id: "77777777-7777-4777-8777-777777777777",
    owner_user_id: OWNER,
    space_id: SPACE,
    project_id: PROJECT,
    lab_project_id: requestFields.lab_project_id,
    actor_id: ACTOR,
    client_id: CLIENT,
    workspace_session_id: requestFields.workspace_session_id,
    device_id: DEVICE,
    resource_id: RESOURCE,
    allowed_actions: ["read"],
    issued_by: "trusted-runtime-picker",
    issued_at: new Date(Date.now() - 60_000).toISOString(),
    valid_until: new Date(Date.now() + 60 * 60_000).toISOString(),
    revoked_at: null,
    active: true,
  },
};
const scopeResult = {
  ok: true,
  repository_full_name: repo,
  repository_id: 101,
  space_id: SPACE,
  project_id: PROJECT,
};

const post = (path: string, body: unknown) => new Request("https://mcp.example" + path, {
  method: "POST",
  headers: { authorization: "Bearer owner-token", "content-type": "application/json" },
  body: JSON.stringify(body),
});

test("registration binds a Runtime resource to signed Owner client, authenticated Device and canonical project", async () => {
  let captured: unknown;
  let deviceAuthCalls = 0;
  const handler = createOwnerWorkspaceResourceHandler(ENV, {
    authenticateOwner: async () => identity,
    authenticateDevice: async () => { deviceAuthCalls++; return { ok: true, deviceId: DEVICE }; },
    resolveScope: async (_env, ownerId, deviceId, repository) => {
      assert.equal(ownerId, OWNER);
      assert.equal(deviceId, DEVICE);
      assert.equal(repository, repo);
      return scopeResult;
    },
    register: async (_env, input) => { captured = input; return dbProof; },
  });

  const response = await handler(post(PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH, requestFields));
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.deepEqual(captured, {
    ownerUserId: OWNER,
    actorId: ACTOR,
    clientId: CLIENT,
    workspaceSessionId: requestFields.workspace_session_id,
    labProjectId: requestFields.lab_project_id,
    deviceId: DEVICE,
    resourceId: RESOURCE,
    spaceId: SPACE,
    projectId: PROJECT,
  });
  assert.equal(deviceAuthCalls, 1);
  assert.equal(body.grant.resource_id, RESOURCE);
  assert.deepEqual(body.grant.allowed_actions, ["read"]);
  assert.equal(JSON.stringify(body).includes("root"), false);
  assert.equal(JSON.stringify(body).includes("path"), false);
});

test("registration rejects caller scope, raw paths, a different OAuth client and unauthenticated devices", async () => {
  let registerCalls = 0;
  const handler = createOwnerWorkspaceResourceHandler(ENV, {
    authenticateOwner: async () => identity,
    authenticateDevice: async () => ({ ok: false, response: Response.json({ error: "device_auth_required" }, { status: 401 }) }),
    resolveScope: async () => scopeResult,
    register: async () => { registerCalls++; return dbProof; },
  });
  const rawPath = await handler(post(PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH,
    { ...requestFields, path: "C:\\Users\\private" }));
  assert.equal(rawPath.status, 400);
  const forgedScope = await handler(post(PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH,
    { ...requestFields, project_id: PROJECT, space_id: SPACE }));
  assert.equal(forgedScope.status, 400);
  const differentClient = await handler(post(PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH,
    { ...requestFields, client_id: "88888888-8888-4888-8888-888888888888" }));
  assert.equal(differentClient.status, 400);
  const unauthenticatedDevice = await handler(post(PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH, requestFields));
  assert.equal(unauthenticatedDevice.status, 401);
  assert.equal(registerCalls, 0);
});

test("registration rejects a proof for a different canonical project", async () => {
  const handler = createOwnerWorkspaceResourceHandler(ENV, {
    authenticateOwner: async () => identity,
    authenticateDevice: async () => ({ ok: true, deviceId: DEVICE }),
    resolveScope: async () => scopeResult,
    register: async () => ({
      ...dbProof,
      grant: { ...dbProof.grant, project_id: "99999999-9999-4999-8999-999999999999" },
    }),
  });
  const response = await handler(post(PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH, requestFields));
  assert.equal(response.status, 502);
  assert.deepEqual(await response.json(), { ok: false, error: "workspace_authority_invalid" });
});

test("resource revocation is Owner and signed OAuth client scoped, without revoking the parent grant", async () => {
  let deviceAuthCalls = 0;
  let revokeInput: unknown;
  const handler = createOwnerWorkspaceResourceHandler(ENV, {
    authenticateOwner: async () => identity,
    authenticateDevice: async () => { deviceAuthCalls++; return { ok: true, deviceId: DEVICE }; },
    revoke: async (_env, ownerId, clientId, resourceId) => {
      revokeInput = { ownerId, clientId, resourceId };
      return { ok: true };
    },
  });
  const response = await handler(new Request(
    `https://mcp.example${PRODUCT_OWNER_WORKSPACE_RESOURCES_PATH}/${RESOURCE}?client_id=${CLIENT}`,
    { method: "DELETE", headers: { authorization: "Bearer owner-token" } },
  ));
  assert.equal(response.status, 200);
  assert.deepEqual(revokeInput, { ownerId: OWNER, clientId: CLIENT, resourceId: RESOURCE });
  assert.equal(deviceAuthCalls, 0);
  assert.deepEqual(await response.json(), { ok: true, resource_id: RESOURCE, revoked: true });
});
