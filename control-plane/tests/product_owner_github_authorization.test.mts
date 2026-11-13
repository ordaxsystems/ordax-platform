import assert from "node:assert/strict";
import test from "node:test";
import {
  collectVerifiedGithubRepositories,
  createOwnerGithubAuthorizationHandler,
  PRODUCT_GITHUB_AUTHORIZATION_CALLBACK_URL,
} from "../cloudflare/src/product_owner_github_authorization.ts";

const OWNER = "11111111-1111-4111-8111-111111111111";
const PROJECT = "22222222-2222-4222-8222-222222222222";
const CHALLENGE = "33333333-3333-4333-8333-333333333333";
const CONNECTION = "44444444-4444-4444-8444-444444444444";
const NOW = Date.parse("2026-11-13T22:45:00.000Z");
const EXPIRES = "2026-11-13T22:55:00.000Z";

const ENV = Object.freeze({
  PRODUCT_GITHUB_APP_CLIENT_ID: "Iv1.1234567890abcdef",
  PRODUCT_GITHUB_APP_CLIENT_SECRET: "client-secret-123456789012345678901234",
  PRODUCT_GITHUB_APP_PKCE_SECRET: "pkce-secret-12345678901234567890123456",
  PRODUCT_GITHUB_APP_INSTALL_URL: "https://github.com/apps/ordax/installations/new",
});

const authenticated = async () => ({
  ok: true,
  subjectId: OWNER,
  issuer: "https://auth.example",
  audience: "ordax",
  expiresAt: 2_000_000_000,
  clientId: null,
  role: "authenticated",
});

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function request(path, method = "GET", body = undefined) {
  return new Request("https://mcp.example" + path, {
    method,
    headers: body === undefined ? { authorization: "Bearer test" } : {
      authorization: "Bearer test",
      "content-type": "application/json",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

test("Owner challenge stores only state hash and returns canonical OAuth+PKCE URL", async () => {
  let stored = null;
  const handler = createOwnerGithubAuthorizationHandler(ENV, {
    authenticate: authenticated,
    now: () => NOW,
    randomUuid: () => CHALLENGE,
    randomBytes: size => new Uint8Array(size).fill(7),
    createChallenge: async (_env, input) => {
      stored = input;
      return {
        ok: true,
        challenge_id: CHALLENGE,
        project_id: PROJECT,
        // Exercise equivalent PostgreSQL timestamptz formatting.
        expires_at: "2026-11-13T22:55:00+00:00",
      };
    },
  });

  const response = await handler(request(
    "/v3/owner/github/authorization-challenges",
    "POST",
    { project_id: PROJECT, confirm: "connect_github" },
  ));
  assert.equal(response.status, 201);
  const body = await response.json();
  assert.equal(body.challenge_id, CHALLENGE);
  assert.equal(body.project_id, PROJECT);
  assert.equal(body.install_url, ENV.PRODUCT_GITHUB_APP_INSTALL_URL);
  assert.equal(body.expires_at, EXPIRES);

  const authorize = new URL(body.authorization_url);
  assert.equal(authorize.origin + authorize.pathname, "https://github.com/login/oauth/authorize");
  assert.equal(authorize.searchParams.get("client_id"), ENV.PRODUCT_GITHUB_APP_CLIENT_ID);
  assert.equal(authorize.searchParams.get("redirect_uri"), PRODUCT_GITHUB_AUTHORIZATION_CALLBACK_URL);
  assert.equal(authorize.searchParams.get("code_challenge_method"), "S256");
  assert.equal(authorize.searchParams.get("allow_signup"), "false");
  assert.equal(authorize.searchParams.get("prompt"), "select_account");
  assert.match(authorize.searchParams.get("code_challenge") ?? "", /^[A-Za-z0-9_-]{43}$/);

  const state = authorize.searchParams.get("state");
  assert.match(state ?? "", new RegExp("^" + CHALLENGE + "\\.[A-Za-z0-9_-]{43}$"));
  assert.deepEqual(stored, {
    ownerUserId: OWNER,
    projectId: PROJECT,
    challengeId: CHALLENGE,
    stateSha256: stored.stateSha256,
    expiresAt: EXPIRES,
  });
  assert.match(stored.stateSha256, /^[0-9a-f]{64}$/);
  assert.notEqual(stored.stateSha256, state);
  assert.ok(!JSON.stringify(body).includes(ENV.PRODUCT_GITHUB_APP_CLIENT_SECRET));
  assert.ok(!JSON.stringify(body).includes(ENV.PRODUCT_GITHUB_APP_PKCE_SECRET));
});

test("Challenge is fail-closed when GitHub App config or exact project request is missing", async () => {
  let calls = 0;
  const missing = createOwnerGithubAuthorizationHandler({}, {
    authenticate: authenticated,
    createChallenge: async () => {
      calls += 1;
      throw Error("must not reach database");
    },
  });
  const unavailable = await missing(request(
    "/v3/owner/github/authorization-challenges", "POST",
    { project_id: PROJECT, confirm: "connect_github" },
  ));
  assert.equal(unavailable.status, 503);
  assert.deepEqual(await unavailable.json(), { ok: false, error: "github_app_unconfigured" });
  assert.equal(calls, 0);

  const handler = createOwnerGithubAuthorizationHandler(ENV, {
    authenticate: authenticated,
    createChallenge: async () => {
      calls += 1;
      throw Error("must not reach database");
    },
  });
  for (const body of [
    { project_id: PROJECT, confirm: "yes" },
    { project_id: "bad", confirm: "connect_github" },
    { project_id: PROJECT, confirm: "connect_github", repository_id: "1" },
    { project_id: PROJECT, confirm: "connect_github", installation_id: "1" },
  ]) {
    const response = await handler(request(
      "/v3/owner/github/authorization-challenges", "POST", body,
    ));
    assert.equal(response.status, 400);
  }
  assert.equal(calls, 0);
});

test("Completion exchanges one code, verifies GitHub user/installations/repos and stores no token", async () => {
  const state = CHALLENGE + "." + "A".repeat(43);
  const calls = [];
  let completed = null;
  const fetcher = async (url, init = {}) => {
    calls.push({ url: String(url), init });
    if (url === "https://github.com/login/oauth/access_token") {
      const params = new URLSearchParams(String(init.body));
      assert.equal(params.get("client_id"), ENV.PRODUCT_GITHUB_APP_CLIENT_ID);
      assert.equal(params.get("client_secret"), ENV.PRODUCT_GITHUB_APP_CLIENT_SECRET);
      assert.equal(params.get("code"), "oauth-code-123456");
      assert.equal(params.get("redirect_uri"), PRODUCT_GITHUB_AUTHORIZATION_CALLBACK_URL);
      assert.match(params.get("code_verifier") ?? "", /^[A-Za-z0-9_-]{43}$/);
      return jsonResponse({ access_token: "ghu_example_token_12345678901234567890", token_type: "bearer" });
    }
    assert.equal(init.headers.get("authorization"), "Bearer ghu_example_token_12345678901234567890");
    if (url === "https://api.github.com/user") {
      return jsonResponse({ id: 7001, login: "owner-user" });
    }
    if (url === "https://api.github.com/user/installations?per_page=100&page=1") {
      return jsonResponse({
        total_count: 1,
        installations: [{ id: 8001, account: { id: 9001, login: "ordaxsystems" } }],
      });
    }
    if (url === "https://api.github.com/user/installations/8001/repositories?per_page=100&page=1") {
      return jsonResponse({
        total_count: 2,
        repositories: [
          { id: 10001, full_name: "ordaxsystems/ordax-platform", default_branch: "main" },
          { id: 10002, full_name: "ordaxsystems/ordax-runtime", default_branch: "main" },
        ],
      });
    }
    throw Error("unexpected fetch " + url);
  };

  const handler = createOwnerGithubAuthorizationHandler(ENV, {
    authenticate: authenticated,
    fetcher,
    beginCompletion: async (_env, input) => ({
      ok: true,
      challenge_id: input.challengeId,
      project_id: PROJECT,
      expires_at: EXPIRES,
    }),
    completeAuthorization: async (_env, input) => {
      completed = input;
      return {
        ok: true,
        challenge_id: input.challengeId,
        project_id: PROJECT,
        candidate_count: input.candidates.length,
        expires_at: EXPIRES,
      };
    },
  });

  const response = await handler(request(
    "/v3/owner/github/authorization-completions",
    "POST",
    { code: "oauth-code-123456", state },
  ));
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    ok: true,
    challenge_id: CHALLENGE,
    project_id: PROJECT,
    candidate_count: 2,
    next_state: "needs_repository_selection",
    install_url: ENV.PRODUCT_GITHUB_APP_INSTALL_URL,
    expires_at: EXPIRES,
  });
  assert.equal(calls.length, 4);
  assert.deepEqual(completed, {
    ownerUserId: OWNER,
    challengeId: CHALLENGE,
    githubUserId: "7001",
    githubUserLogin: "owner-user",
    candidates: [
      {
        installation_id: "8001",
        installation_account_id: "9001",
        installation_account_login: "ordaxsystems",
        repository_id: "10001",
        repository_full_name: "ordaxsystems/ordax-platform",
        default_branch: "main",
      },
      {
        installation_id: "8001",
        installation_account_id: "9001",
        installation_account_login: "ordaxsystems",
        repository_id: "10002",
        repository_full_name: "ordaxsystems/ordax-runtime",
        default_branch: "main",
      },
    ],
  });
  assert.ok(!JSON.stringify(completed).includes("ghu_example_token"));
});

test("Completion consumes state before provider exchange and never retries an uncertain OAuth code", async () => {
  const state = CHALLENGE + "." + "B".repeat(43);
  let beginCalls = 0;
  let providerCalls = 0;
  let completeCalls = 0;
  const handler = createOwnerGithubAuthorizationHandler(ENV, {
    authenticate: authenticated,
    beginCompletion: async () => {
      beginCalls += 1;
      return { ok: true, challenge_id: CHALLENGE, project_id: PROJECT, expires_at: EXPIRES };
    },
    completeAuthorization: async () => {
      completeCalls += 1;
      throw Error("must not complete");
    },
    fetcher: async () => {
      providerCalls += 1;
      return jsonResponse({ error: "temporary" }, 503);
    },
  });
  const response = await handler(request(
    "/v3/owner/github/authorization-completions",
    "POST",
    { code: "oauth-code-uncertain", state },
  ));
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { ok: false, error: "github_authorization_unconfirmed" });
  assert.equal(beginCalls, 1);
  assert.equal(providerCalls, 1);
  assert.equal(completeCalls, 0);

  let blockedFetches = 0;
  const replay = createOwnerGithubAuthorizationHandler(ENV, {
    authenticate: authenticated,
    beginCompletion: async () => ({
      ok: false, error: "github_authorization_challenge_invalid",
    }),
    fetcher: async () => {
      blockedFetches += 1;
      throw Error("must not fetch");
    },
  });
  const replayResponse = await replay(request(
    "/v3/owner/github/authorization-completions",
    "POST",
    { code: "oauth-code-uncertain", state },
  ));
  assert.equal(replayResponse.status, 409);
  assert.equal(blockedFetches, 0);
});

test("Provider catalog rejects spoofed, duplicate or oversized repository authority", async () => {
  const token = "ghu_example_token_12345678901234567890";
  const base = async (repoBody) => collectVerifiedGithubRepositories(token, async url => {
    if (url === "https://api.github.com/user") return jsonResponse({ id: 1, login: "owner" });
    if (url === "https://api.github.com/user/installations?per_page=100&page=1") {
      return jsonResponse({ total_count: 1, installations: [{ id: 2, account: { id: 3, login: "org" } }] });
    }
    return jsonResponse(repoBody);
  });

  await assert.rejects(base({
    total_count: 1,
    repositories: [{ id: 4, full_name: "not-a-repository", default_branch: "main" }],
  }), /github_repository_catalog_invalid/);

  await assert.rejects(base({
    total_count: 2,
    repositories: [
      { id: 4, full_name: "org/a", default_branch: "main" },
      { id: 4, full_name: "org/a", default_branch: "main" },
    ],
  }), /github_repository_catalog_invalid/);

  await assert.rejects(collectVerifiedGithubRepositories(token, async url => {
    if (url === "https://api.github.com/user") return jsonResponse({ id: 1, login: "owner" });
    return jsonResponse({
      total_count: 26,
      installations: Array.from({ length: 26 }, (_, index) => ({
        id: index + 1,
        account: { id: 100 + index, login: "org" + index },
      })),
    });
  }), /github_installation_catalog_invalid/);
});

test("Candidate read exposes repository choice but never installation identity", async () => {
  const handler = createOwnerGithubAuthorizationHandler(ENV, {
    authenticate: authenticated,
    readCandidates: async () => ({
      ok: true,
      challenge_id: CHALLENGE,
      project_id: PROJECT,
      repositories: [{
        repository_id: "10001",
        repository_full_name: "ordaxsystems/ordax-platform",
        default_branch: "main",
        installation_account_login: "ordaxsystems",
        installation_id: "should-drop",
        secret: "should-drop",
      }],
      expires_at: EXPIRES,
      github_user_id: "should-drop",
    }),
  });
  const response = await handler(request(
    "/v3/owner/github/repository-candidates?challenge_id=" + CHALLENGE,
  ));
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(body, {
    ok: true,
    challenge_id: CHALLENGE,
    project_id: PROJECT,
    repositories: [{
      repository_id: "10001",
      repository_full_name: "ordaxsystems/ordax-platform",
      default_branch: "main",
      installation_account_login: "ordaxsystems",
    }],
    expires_at: EXPIRES,
  });
  assert.ok(!JSON.stringify(body).includes("installation_id"));
  assert.ok(!JSON.stringify(body).includes("github_user_id"));
});

test("Repository selection accepts only a verified repository id and explicit confirmation", async () => {
  let calls = 0;
  const handler = createOwnerGithubAuthorizationHandler(ENV, {
    authenticate: authenticated,
    selectRepository: async (_env, input) => {
      calls += 1;
      assert.deepEqual(input, {
        ownerUserId: OWNER,
        challengeId: CHALLENGE,
        repositoryId: "10001",
      });
      return {
        ok: true,
        connection_id: CONNECTION,
        project_id: PROJECT,
        repository_id: "10001",
        repository_full_name: "ordaxsystems/ordax-platform",
        default_branch: "main",
        state: "active",
        next_state: "needs_device_binding",
        installation_id: "drop",
      };
    },
  });

  const response = await handler(request(
    "/v3/owner/github/repository-selections",
    "POST",
    { challenge_id: CHALLENGE, repository_id: "10001", confirm: "select_repository" },
  ));
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    ok: true,
    challenge_id: CHALLENGE,
    connection_id: CONNECTION,
    project_id: PROJECT,
    repository_id: "10001",
    repository_full_name: "ordaxsystems/ordax-platform",
    default_branch: "main",
    state: "active",
    next_state: "needs_device_binding",
  });
  assert.equal(calls, 1);

  for (const extra of [
    { installation_id: "8001" },
    { repository_full_name: "ordaxsystems/ordax-platform" },
    { grant_profile: "project-native-terminal" },
    { device_id: "55555555-5555-4555-8555-555555555555" },
  ]) {
    const invalid = await handler(request(
      "/v3/owner/github/repository-selections",
      "POST",
      {
        challenge_id: CHALLENGE,
        repository_id: "10001",
        confirm: "select_repository",
        ...extra,
      },
    ));
    assert.equal(invalid.status, 400);
  }
  assert.equal(calls, 1);
});

test("Delegated OAuth client cannot start or complete Owner GitHub authorization", async () => {
  let calls = 0;
  const handler = createOwnerGithubAuthorizationHandler({
    ...ENV,
    PRODUCT_OWNER_OAUTH_CLIENT_ID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  }, {
    authenticate: async () => ({
      ...(await authenticated()),
      clientId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    }),
    createChallenge: async () => {
      calls += 1;
      throw Error("must not reach database");
    },
  });
  const response = await handler(request(
    "/v3/owner/github/authorization-challenges",
    "POST",
    { project_id: PROJECT, confirm: "connect_github" },
  ));
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { ok: false, error: "owner_primary_session_required" });
  assert.equal(calls, 0);
});
