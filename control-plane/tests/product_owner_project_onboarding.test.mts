import assert from "node:assert/strict";
import test from "node:test";
import {
  createOwnerProjectOnboardingHandler,
  onboardingStateResponse,
  ownerProjectCreationResponse,
} from "../cloudflare/src/product_owner_project_onboarding.ts";

const OWNER = "11111111-1111-4111-8111-111111111111";
const DEVICE = "22222222-2222-4222-8222-222222222222";
const SPACE = "33333333-3333-4333-8333-333333333333";
const PROJECT = "44444444-4444-4444-8444-444444444444";
const ENV = Object.freeze({});

const authenticated = async () => ({
  ok: true as const,
  subjectId: OWNER,
  issuer: "https://auth.example",
  audience: "ordax",
  expiresAt: 2_000_000_000,
  clientId: null,
  role: "authenticated",
});

function stateRequest(device = DEVICE) {
  return new Request(
    "https://mcp.example/v3/owner/project-onboarding?device_id=" + device,
    { headers: { authorization: "Bearer test" } },
  );
}

function createRequest(body: Record<string, unknown>) {
  return new Request("https://mcp.example/v3/owner/project-onboarding/projects", {
    method: "POST",
    headers: { authorization: "Bearer test", "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

test("Owner onboarding state exposes bounded product state without provider credentials", async () => {
  let observed: unknown[] = [];
  const handler = createOwnerProjectOnboardingHandler(ENV, {
    authenticate: authenticated,
    readState: async (_env, input) => {
      observed = [input.ownerUserId, input.deviceId];
      return {
        ok: true,
        device_id: DEVICE,
        spaces: [{ space_id: SPACE, name: "Owner", kind: "work", state: "active", secret: "drop" }],
        projects: [{
          project_id: PROJECT,
          space_id: SPACE,
          name: "OrdaX Platform",
          kind: "development",
          state: "active",
          github_connection_count: 0,
          repository_full_name: null,
          space_device_execute: false,
          project_device_bound: false,
          next_state: "needs_github_installation",
          installation_id: 999,
          external_account_id: "never-expose",
        }],
        next_state: null,
        owner_user_id: OWNER,
      };
    },
  });
  const response = await handler(stateRequest());
  assert.equal(response.status, 200);
  assert.deepEqual(observed, [OWNER, DEVICE]);
  assert.deepEqual(await response.json(), {
    ok: true,
    device_id: DEVICE,
    spaces: [{ space_id: SPACE, name: "Owner", kind: "work", state: "active" }],
    projects: [{
      project_id: PROJECT,
      space_id: SPACE,
      name: "OrdaX Platform",
      kind: "development",
      state: "active",
      github_connection_count: 0,
      repository_full_name: null,
      space_device_execute: false,
      project_device_bound: false,
      next_state: "needs_github_installation",
    }],
    next_state: null,
  });
});

test("Owner onboarding state derives root setup gates without fabricating GitHub readiness", () => {
  assert.deepEqual(onboardingStateResponse({
    ok: true, device_id: DEVICE, spaces: [], projects: [], next_state: "needs_space",
  }, DEVICE), {
    ok: true, device_id: DEVICE, spaces: [], projects: [], next_state: "needs_space",
  });
  assert.deepEqual(onboardingStateResponse({
    ok: true,
    device_id: DEVICE,
    spaces: [{ space_id: SPACE, name: "Owner", kind: "work", state: "active" }],
    projects: [],
    next_state: "needs_project",
  }, DEVICE), {
    ok: true,
    device_id: DEVICE,
    spaces: [{ space_id: SPACE, name: "Owner", kind: "work", state: "active" }],
    projects: [],
    next_state: "needs_project",
  });
});

test("Project creation requires an explicit Owner confirmation and reuses canonical project RPC", async () => {
  let observed: unknown = null;
  const handler = createOwnerProjectOnboardingHandler(ENV, {
    authenticate: authenticated,
    createProject: async (_env, input) => {
      observed = input;
      return {
        ok: true,
        project_id: PROJECT,
        space_id: SPACE,
        created_by_user_id: OWNER,
        state: "active",
        secret: "drop",
      };
    },
  });
  const response = await handler(createRequest({
    space_id: SPACE,
    name: " OrdaX Platform ",
    kind: "development",
    confirm: "create_project",
  }));
  assert.equal(response.status, 201);
  assert.deepEqual(observed, {
    ownerUserId: OWNER,
    spaceId: SPACE,
    name: "OrdaX Platform",
    kind: "development",
  });
  assert.deepEqual(await response.json(), {
    ok: true,
    project_id: PROJECT,
    space_id: SPACE,
    state: "active",
    next_state: "needs_github_installation",
  });
});

test("Project creation cannot smuggle repository identity, grants or metadata", async () => {
  let calls = 0;
  const handler = createOwnerProjectOnboardingHandler(ENV, {
    authenticate: authenticated,
    createProject: async () => {
      calls += 1;
      return { ok: true, project_id: PROJECT, space_id: SPACE, state: "active" };
    },
  });
  const base = {
    space_id: SPACE,
    name: "OrdaX Platform",
    kind: "development",
    confirm: "create_project",
  };
  for (const extra of [
    { repository_id: 123 },
    { installation_id: 456 },
    { repository_full_name: "ordaxsystems/ordax-platform" },
    { metadata: { trusted: true } },
    { grant_profile: "project-native-terminal" },
    { device_id: DEVICE },
  ]) {
    const response = await handler(createRequest({ ...base, ...extra }));
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { ok: false, error: "owner_project_create_invalid" });
  }
  assert.equal(calls, 0);
});

test("Owner onboarding rejects malformed or duplicate query identity before SQL", async () => {
  let calls = 0;
  const handler = createOwnerProjectOnboardingHandler(ENV, {
    authenticate: authenticated,
    readState: async () => {
      calls += 1;
      return { ok: true, device_id: DEVICE, spaces: [], projects: [], next_state: "needs_space" };
    },
  });
  for (const url of [
    "https://mcp.example/v3/owner/project-onboarding",
    "https://mcp.example/v3/owner/project-onboarding?device_id=bad",
    "https://mcp.example/v3/owner/project-onboarding?device_id=" + DEVICE + "&device_id=" + DEVICE,
    "https://mcp.example/v3/owner/project-onboarding?device_id=" + DEVICE + "&project_id=" + PROJECT,
  ]) {
    const response = await handler(new Request(url, { headers: { authorization: "Bearer test" } }));
    assert.equal(response.status, 400);
  }
  assert.equal(calls, 0);
});

test("Delegated OAuth clients cannot use Owner onboarding", async () => {
  const pinned = "202fd3e1-b058-4531-8750-82c57e4b6ca0";
  let calls = 0;
  const handler = createOwnerProjectOnboardingHandler({
    ...ENV, PRODUCT_OWNER_OAUTH_CLIENT_ID: pinned,
  }, {
    authenticate: async () => ({ ...(await authenticated()), clientId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }),
    readState: async () => {
      calls += 1;
      throw Error("must not reach SQL");
    },
  });
  const response = await handler(stateRequest());
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { ok: false, error: "owner_primary_session_required" });
  assert.equal(calls, 0);
});

test("SQL envelopes are sanitized and fail closed on drift", () => {
  assert.deepEqual(ownerProjectCreationResponse({
    ok: true, project_id: PROJECT, space_id: SPACE, state: "active",
    created_by_user_id: OWNER, token: "drop",
  }, SPACE), {
    ok: true, project_id: PROJECT, space_id: SPACE, state: "active",
    next_state: "needs_github_installation",
  });

  for (const invalid of [
    { ok: true, project_id: "bad", space_id: SPACE, state: "active" },
    { ok: true, project_id: PROJECT, space_id: "bad", state: "active" },
    { ok: true, project_id: PROJECT, space_id: SPACE, state: "archived" },
    { ok: false, error: "POSTGRES_PASSWORD=never" },
  ]) {
    assert.throws(() => ownerProjectCreationResponse(invalid as any, SPACE), /product_postgres_invalid_response/);
  }
});
