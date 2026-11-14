import { readBoundedJsonObject } from "./request_json.ts";
import {
  authenticateProductRequest,
  authorizeProductOwnerIdentity,
  type ProductAuthEnv,
  type ProductIdentity,
} from "./product_auth.ts";
import {
  beginOwnerGithubAuthorizationCompletion,
  completeOwnerGithubAuthorization,
  createOwnerGithubAuthorizationChallenge,
  ProductPostgresError,
  readOwnerGithubRepositoryCandidates,
  selectOwnerGithubRepository,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { hasExactQueryParameters } from "./request_query.ts";

type Json = Record<string, unknown>;
type GithubFetch = typeof fetch;

export interface ProductGithubAppEnv {
  PRODUCT_GITHUB_APP_CLIENT_ID?: string;
  PRODUCT_GITHUB_APP_CLIENT_SECRET?: string;
  PRODUCT_GITHUB_APP_PKCE_SECRET?: string;
  PRODUCT_GITHUB_APP_INSTALL_URL?: string;
}

type Env = ProductAuthEnv & ProductPostgresEnv & ProductGithubAppEnv;

type Dependencies = Readonly<{
  authenticate?: (request: Request, env: ProductAuthEnv) => Promise<ProductIdentity>;
  createChallenge?: typeof createOwnerGithubAuthorizationChallenge;
  beginCompletion?: typeof beginOwnerGithubAuthorizationCompletion;
  completeAuthorization?: typeof completeOwnerGithubAuthorization;
  readCandidates?: typeof readOwnerGithubRepositoryCandidates;
  selectRepository?: typeof selectOwnerGithubRepository;
  fetcher?: GithubFetch;
  now?: () => number;
  randomUuid?: () => string;
  randomBytes?: (size: number) => Uint8Array;
}>;

export const PRODUCT_OWNER_GITHUB_AUTHORIZATION_CHALLENGES_PATH =
  "/v3/owner/github/authorization-challenges";
export const PRODUCT_OWNER_GITHUB_AUTHORIZATION_COMPLETIONS_PATH =
  "/v3/owner/github/authorization-completions";
export const PRODUCT_OWNER_GITHUB_REPOSITORY_CANDIDATES_PATH =
  "/v3/owner/github/repository-candidates";
export const PRODUCT_OWNER_GITHUB_REPOSITORY_SELECTIONS_PATH =
  "/v3/owner/github/repository-selections";

export const PRODUCT_GITHUB_AUTHORIZATION_CALLBACK_URL =
  "https://ordax.com.br/account/mcp/github/callback";

const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token";
const GITHUB_API_ORIGIN = "https://api.github.com";
const GITHUB_API_VERSION = "2026-03-10";
const GITHUB_USER_AGENT = "OrdaX-Platform-GitHub-App";
const CHALLENGE_TTL_MS = 10 * 60 * 1000;
const MAX_INSTALLATIONS = 25;
const MAX_REPOSITORIES = 500;
const MAX_PROVIDER_JSON = 1024 * 1024;
const DECIMAL_ID = /^[1-9][0-9]{0,18}$/;
const GITHUB_LOGIN = /^[A-Za-z0-9-]{1,100}$/;
const REPOSITORY_FULL_NAME = /^[^\s/]+\/[^\s/]+$/;
const CLIENT_ID = /^[A-Za-z0-9_.-]{8,160}$/;
const SECRET = /^[^\s\u0000-\u001f\u007f]{20,512}$/;
const INSTALL_URL = /^https:\/\/github\.com\/apps\/[A-Za-z0-9-]+\/installations\/new$/;
const STATE = /^([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})$/;
const OAUTH_CODE = /^[^\s\u0000-\u001f\u007f]{8,1024}$/;

const json = (body: unknown, status = 200) => Response.json(body, {
  status,
  headers: {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  },
});

function exactObjectKeys(value: unknown, keys: readonly string[]): value is Json {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value as Json).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function configuredGithubApp(env: ProductGithubAppEnv) {
  const clientId = (env.PRODUCT_GITHUB_APP_CLIENT_ID ?? "").trim();
  const clientSecret = (env.PRODUCT_GITHUB_APP_CLIENT_SECRET ?? "").trim();
  const pkceSecret = (env.PRODUCT_GITHUB_APP_PKCE_SECRET ?? "").trim();
  const installUrl = (env.PRODUCT_GITHUB_APP_INSTALL_URL ?? "").trim();
  if (!CLIENT_ID.test(clientId) || !SECRET.test(clientSecret)
      || !SECRET.test(pkceSecret) || !INSTALL_URL.test(installUrl)) {
    return null;
  }
  return { clientId, clientSecret, pkceSecret, installUrl };
}

type GithubAppConfig = NonNullable<ReturnType<typeof configuredGithubApp>>;

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map(value => value.toString(16).padStart(2, "0")).join("");
}

async function sha256Bytes(value: string): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return new Uint8Array(digest);
}

async function stateSha256(value: string): Promise<string> {
  return bytesToHex(await sha256Bytes(value));
}

async function deriveCodeVerifier(
  pkceSecret: string,
  challengeId: string,
  ownerUserId: string,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(pkceSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(
      "ordax-github-pkce-v1:" + challengeId + ":" + ownerUserId,
    ),
  );
  return base64Url(new Uint8Array(signature));
}

function providerHeaders(accessToken?: string): Headers {
  const headers = new Headers({
    "accept": "application/vnd.github+json",
    "user-agent": GITHUB_USER_AGENT,
    "x-github-api-version": GITHUB_API_VERSION,
  });
  if (accessToken) headers.set("authorization", "Bearer " + accessToken);
  return headers;
}

async function providerJson(
  fetcher: GithubFetch,
  url: string,
  init: RequestInit,
  maxBytes = MAX_PROVIDER_JSON,
): Promise<Json> {
  const response = await fetcher(url, {
    ...init,
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok || response.status < 200 || response.status >= 300) {
    throw new Error("github_provider_unavailable");
  }
  const value = await readBoundedJsonObject(response, maxBytes);
  if (!value) throw new Error("github_provider_invalid_response");
  return value;
}

function safeProviderId(value: unknown): string | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0
    ? String(value) : null;
}

function safeGithubLogin(value: unknown): string | null {
  return typeof value === "string" && GITHUB_LOGIN.test(value) ? value : null;
}

function safeRepositoryFullName(value: unknown): string | null {
  return typeof value === "string"
      && value.length >= 3 && value.length <= 200
      && REPOSITORY_FULL_NAME.test(value)
    ? value : null;
}

function safeDefaultBranch(value: unknown): string | null | undefined {
  if (value === null) return null;
  if (typeof value !== "string" || value.length < 1 || value.length > 255
      || /[\u0000-\u001f\u007f]/.test(value)) return undefined;
  return value;
}

export type VerifiedGithubRepositoryCandidate = Readonly<{
  installation_id: string;
  installation_account_id: string;
  installation_account_login: string;
  repository_id: string;
  repository_full_name: string;
  default_branch: string | null;
}>;

async function exchangeGithubAuthorizationCode(
  config: GithubAppConfig,
  code: string,
  codeVerifier: string,
  fetcher: GithubFetch,
): Promise<string> {
  const body = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code,
    redirect_uri: PRODUCT_GITHUB_AUTHORIZATION_CALLBACK_URL,
    code_verifier: codeVerifier,
  });
  const response = await providerJson(fetcher, GITHUB_TOKEN_URL, {
    method: "POST",
    headers: new Headers({
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
      "user-agent": GITHUB_USER_AGENT,
    }),
    body,
  }, 32 * 1024);
  const token = response.access_token;
  const tokenType = response.token_type;
  if (typeof token !== "string" || token.length < 20 || token.length > 16_384
      || /[\s\u0000-\u001f\u007f]/.test(token)
      || typeof tokenType !== "string" || tokenType.toLowerCase() !== "bearer") {
    throw new Error("github_authorization_token_invalid");
  }
  return token;
}

export async function collectVerifiedGithubRepositories(
  accessToken: string,
  fetcher: GithubFetch = fetch,
): Promise<{
  githubUserId: string;
  githubUserLogin: string;
  candidates: VerifiedGithubRepositoryCandidate[];
}> {
  const headers = providerHeaders(accessToken);
  const user = await providerJson(fetcher, GITHUB_API_ORIGIN + "/user", {
    method: "GET",
    headers,
  }, 64 * 1024);
  const githubUserId = safeProviderId(user.id);
  const githubUserLogin = safeGithubLogin(user.login);
  if (!githubUserId || !githubUserLogin) {
    throw new Error("github_user_identity_invalid");
  }

  const installations = await providerJson(
    fetcher,
    GITHUB_API_ORIGIN + "/user/installations?per_page=100&page=1",
    { method: "GET", headers },
  );
  const totalInstallations = installations.total_count;
  const rows = installations.installations;
  if (!Number.isSafeInteger(totalInstallations) || (totalInstallations as number) < 0
      || (totalInstallations as number) > MAX_INSTALLATIONS
      || !Array.isArray(rows) || rows.length !== totalInstallations) {
    throw new Error("github_installation_catalog_invalid");
  }

  const candidates: VerifiedGithubRepositoryCandidate[] = [];
  const repositoryIds = new Set<string>();
  for (const installation of rows) {
    if (!installation || typeof installation !== "object" || Array.isArray(installation)) {
      throw new Error("github_installation_catalog_invalid");
    }
    const record = installation as Json;
    const installationId = safeProviderId(record.id);
    const account = record.account;
    if (!installationId || !account || typeof account !== "object" || Array.isArray(account)) {
      throw new Error("github_installation_catalog_invalid");
    }
    const accountRecord = account as Json;
    const accountId = safeProviderId(accountRecord.id);
    const accountLogin = safeGithubLogin(accountRecord.login);
    if (!accountId || !accountLogin) throw new Error("github_installation_catalog_invalid");

    let page = 1;
    let expectedTotal: number | null = null;
    let installationCount = 0;
    while (true) {
      const catalog = await providerJson(
        fetcher,
        GITHUB_API_ORIGIN + "/user/installations/" + installationId
          + "/repositories?per_page=100&page=" + page,
        { method: "GET", headers },
      );
      const total = catalog.total_count;
      const repositories = catalog.repositories;
      if (!Number.isSafeInteger(total) || (total as number) < 0
          || (total as number) > MAX_REPOSITORIES || !Array.isArray(repositories)
          || repositories.length > 100) {
        throw new Error("github_repository_catalog_invalid");
      }
      if (expectedTotal === null) expectedTotal = total as number;
      if (expectedTotal !== total) throw new Error("github_repository_catalog_changed");

      for (const repository of repositories) {
        if (!repository || typeof repository !== "object" || Array.isArray(repository)) {
          throw new Error("github_repository_catalog_invalid");
        }
        const row = repository as Json;
        const repositoryId = safeProviderId(row.id);
        const fullName = safeRepositoryFullName(row.full_name);
        const defaultBranch = safeDefaultBranch(row.default_branch);
        if (!repositoryId || !fullName || defaultBranch === undefined
            || repositoryIds.has(repositoryId)) {
          throw new Error("github_repository_catalog_invalid");
        }
        repositoryIds.add(repositoryId);
        candidates.push({
          installation_id: installationId,
          installation_account_id: accountId,
          installation_account_login: accountLogin,
          repository_id: repositoryId,
          repository_full_name: fullName,
          default_branch: defaultBranch,
        });
        installationCount += 1;
        if (candidates.length > MAX_REPOSITORIES) {
          throw new Error("github_repository_catalog_too_large");
        }
      }

      if (installationCount >= (expectedTotal ?? 0)) break;
      if (repositories.length === 0 || page >= 5) {
        throw new Error("github_repository_catalog_incomplete");
      }
      page += 1;
    }
  }

  return { githubUserId, githubUserLogin, candidates };
}

async function buildAuthorizationChallenge(
  config: GithubAppConfig,
  ownerUserId: string,
  projectId: string,
  now: number,
  randomUuid: () => string,
  randomBytes: (size: number) => Uint8Array,
) {
  const challengeId = randomUuid().toLowerCase();
  if (!isCanonicalUuid(challengeId)) throw new Error("github_challenge_entropy_invalid");
  const nonce = randomBytes(32);
  if (!(nonce instanceof Uint8Array) || nonce.byteLength !== 32) {
    throw new Error("github_challenge_entropy_invalid");
  }
  const state = challengeId + "." + base64Url(nonce);
  const stateHash = await stateSha256(state);
  const codeVerifier = await deriveCodeVerifier(
    config.pkceSecret, challengeId, ownerUserId,
  );
  const codeChallenge = base64Url(await sha256Bytes(codeVerifier));
  const expiresAt = new Date(now + CHALLENGE_TTL_MS).toISOString();

  const authorize = new URL(GITHUB_AUTHORIZE_URL);
  authorize.searchParams.set("client_id", config.clientId);
  authorize.searchParams.set("redirect_uri", PRODUCT_GITHUB_AUTHORIZATION_CALLBACK_URL);
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("code_challenge", codeChallenge);
  authorize.searchParams.set("code_challenge_method", "S256");
  authorize.searchParams.set("allow_signup", "false");
  authorize.searchParams.set("prompt", "select_account");

  return {
    challengeId,
    projectId,
    state,
    stateHash,
    codeVerifier,
    expiresAt,
    authorizationUrl: authorize.toString(),
  };
}

function postgresError(error: unknown): Response {
  if (error instanceof ProductPostgresError) {
    return json({ ok: false, error: error.code }, error.status);
  }
  return json({ ok: false, error: "product_postgres_unavailable" }, 503);
}

function publicAuthorityError(raw: Json, allowed: ReadonlySet<string>): Json {
  if (raw.ok === false && typeof raw.error === "string" && allowed.has(raw.error)) {
    return { ok: false, error: raw.error };
  }
  throw new Error("product_postgres_invalid_response");
}

const CHALLENGE_ERRORS = new Set([
  "github_authorization_challenge_invalid",
  "product_owner_auth_ineligible",
  "project_not_found_or_inactive",
  "space_admin_required",
  "project_github_connection_exists",
  "github_authorization_challenge_conflict",
]);
const COMPLETION_ERRORS = new Set([
  "github_authorization_completion_invalid",
  "product_owner_auth_ineligible",
  "github_authorization_challenge_invalid",
  "github_authorization_result_invalid",
  "github_repository_candidates_invalid",
  "github_repository_candidates_duplicate",
]);
const CANDIDATE_ERRORS = new Set([
  "github_repository_candidates_unavailable",
]);
const SELECTION_ERRORS = new Set([
  "github_repository_selection_invalid",
  "github_authorization_challenge_invalid",
  "project_github_connection_exists",
  "github_repository_not_verified",
  "github_repository_authority_revoked",
]);

function statusForError(error: unknown): number {
  if (error === "project_not_found_or_inactive") return 404;
  if (error === "space_admin_required" || error === "product_owner_auth_ineligible") return 403;
  if (error === "project_github_connection_exists"
      || error === "github_repository_authority_revoked") return 409;
  if (error === "github_authorization_challenge_conflict") return 409;
  if (error === "github_authorization_challenge_invalid"
      || error === "github_repository_candidates_unavailable") return 409;
  if (error === "github_repository_not_verified") return 400;
  return 400;
}

function challengeResponse(
  raw: Json,
  expectedChallengeId: string,
  expectedProjectId: string,
  expiresAt: string,
  authorizationUrl: string,
  installUrl: string,
): Json {
  if (raw.ok === false) return publicAuthorityError(raw, CHALLENGE_ERRORS);
  if (raw.ok !== true || raw.challenge_id !== expectedChallengeId
      || raw.project_id !== expectedProjectId
      || typeof raw.expires_at !== "string"
      || !Number.isFinite(Date.parse(raw.expires_at))
      || Date.parse(raw.expires_at) !== Date.parse(expiresAt)) {
    throw new Error("product_postgres_invalid_response");
  }
  return {
    ok: true,
    challenge_id: expectedChallengeId,
    project_id: expectedProjectId,
    authorization_url: authorizationUrl,
    install_url: installUrl,
    expires_at: expiresAt,
  };
}

function completionResponse(
  raw: Json,
  expectedChallengeId: string,
  expectedCandidateCount: number,
  installUrl: string,
): Json {
  if (raw.ok === false) return publicAuthorityError(raw, COMPLETION_ERRORS);
  if (raw.ok !== true || raw.challenge_id !== expectedChallengeId
      || !isCanonicalUuid(raw.project_id)
      || raw.candidate_count !== expectedCandidateCount
      || typeof raw.expires_at !== "string"
      || !Number.isFinite(Date.parse(raw.expires_at))) {
    throw new Error("product_postgres_invalid_response");
  }
  return {
    ok: true,
    challenge_id: expectedChallengeId,
    project_id: raw.project_id,
    candidate_count: expectedCandidateCount,
    next_state: expectedCandidateCount > 0
      ? "needs_repository_selection" : "needs_github_installation",
    install_url: installUrl,
    expires_at: raw.expires_at,
  };
}

function candidatesResponse(raw: Json, expectedChallengeId: string): Json {
  if (raw.ok === false) return publicAuthorityError(raw, CANDIDATE_ERRORS);
  if (raw.ok !== true || raw.challenge_id !== expectedChallengeId
      || !isCanonicalUuid(raw.project_id)
      || !Array.isArray(raw.repositories) || raw.repositories.length > MAX_REPOSITORIES
      || typeof raw.expires_at !== "string"
      || !Number.isFinite(Date.parse(raw.expires_at))) {
    throw new Error("product_postgres_invalid_response");
  }
  const ids = new Set<string>();
  const repositories = raw.repositories.map(value => {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("product_postgres_invalid_response");
    }
    const row = value as Json;
    const repositoryId = row.repository_id;
    const fullName = safeRepositoryFullName(row.repository_full_name);
    const accountLogin = safeGithubLogin(row.installation_account_login);
    const branch = safeDefaultBranch(row.default_branch);
    if (typeof repositoryId !== "string" || !DECIMAL_ID.test(repositoryId)
        || ids.has(repositoryId) || !fullName || !accountLogin
        || branch === undefined) {
      throw new Error("product_postgres_invalid_response");
    }
    ids.add(repositoryId);
    return {
      repository_id: repositoryId,
      repository_full_name: fullName,
      default_branch: branch,
      installation_account_login: accountLogin,
    };
  });
  return {
    ok: true,
    challenge_id: expectedChallengeId,
    project_id: raw.project_id,
    repositories,
    expires_at: raw.expires_at,
  };
}

function selectionResponse(
  raw: Json,
  expectedChallengeId: string,
  expectedRepositoryId: string,
): Json {
  if (raw.ok === false) return publicAuthorityError(raw, SELECTION_ERRORS);
  const fullName = safeRepositoryFullName(raw.repository_full_name);
  const branch = safeDefaultBranch(raw.default_branch);
  if (raw.ok !== true || !isCanonicalUuid(raw.connection_id)
      || !isCanonicalUuid(raw.project_id)
      || raw.repository_id !== expectedRepositoryId
      || !fullName || branch === undefined
      || raw.state !== "active" || raw.next_state !== "needs_device_binding") {
    throw new Error("product_postgres_invalid_response");
  }
  return {
    ok: true,
    challenge_id: expectedChallengeId,
    connection_id: raw.connection_id,
    project_id: raw.project_id,
    repository_id: expectedRepositoryId,
    repository_full_name: fullName,
    default_branch: branch,
    state: "active",
    next_state: "needs_device_binding",
  };
}

export function createOwnerGithubAuthorizationHandler(env: Env, deps: Dependencies = {}) {
  const authenticate = deps.authenticate ?? authenticateProductRequest;
  const createChallenge = deps.createChallenge ?? createOwnerGithubAuthorizationChallenge;
  const beginCompletion = deps.beginCompletion ?? beginOwnerGithubAuthorizationCompletion;
  const completeAuthorization = deps.completeAuthorization ?? completeOwnerGithubAuthorization;
  const readCandidates = deps.readCandidates ?? readOwnerGithubRepositoryCandidates;
  const selectRepository = deps.selectRepository ?? selectOwnerGithubRepository;
  const fetcher = deps.fetcher ?? fetch;
  const now = deps.now ?? Date.now;
  const randomUuid = deps.randomUuid ?? (() => crypto.randomUUID());
  const randomBytes = deps.randomBytes ?? ((size: number) => {
    const value = new Uint8Array(size);
    crypto.getRandomValues(value);
    return value;
  });

  return async function handleOwnerGithubAuthorization(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const knownPath = [
      PRODUCT_OWNER_GITHUB_AUTHORIZATION_CHALLENGES_PATH,
      PRODUCT_OWNER_GITHUB_AUTHORIZATION_COMPLETIONS_PATH,
      PRODUCT_OWNER_GITHUB_REPOSITORY_CANDIDATES_PATH,
      PRODUCT_OWNER_GITHUB_REPOSITORY_SELECTIONS_PATH,
    ].includes(url.pathname);
    if (!knownPath) return json({ ok: false, error: "not_found" }, 404);

    const identity = authorizeProductOwnerIdentity(await authenticate(request, env), env);
    if (!identity.ok) return json({ ok: false, error: identity.error }, identity.status);

    const config = configuredGithubApp(env);
    if (!config) return json({ ok: false, error: "github_app_unconfigured" }, 503);

    if (url.pathname === PRODUCT_OWNER_GITHUB_AUTHORIZATION_CHALLENGES_PATH) {
      if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
      if (url.search !== "") return json({ ok: false, error: "github_authorization_request_invalid" }, 400);
      const body = await readBoundedJsonObject(request, 4096);
      if (!exactObjectKeys(body, ["project_id", "confirm"])
          || typeof body.project_id !== "string" || !isCanonicalUuid(body.project_id)
          || body.confirm !== "connect_github") {
        return json({ ok: false, error: "github_authorization_request_invalid" }, 400);
      }

      let challenge;
      try {
        challenge = await buildAuthorizationChallenge(
          config,
          identity.ownerUserId,
          body.project_id,
          now(),
          randomUuid,
          randomBytes,
        );
        const raw = await createChallenge(env, {
          ownerUserId: identity.ownerUserId,
          projectId: body.project_id,
          challengeId: challenge.challengeId,
          stateSha256: challenge.stateHash,
          expiresAt: challenge.expiresAt,
        });
        const result = challengeResponse(
          raw,
          challenge.challengeId,
          body.project_id,
          challenge.expiresAt,
          challenge.authorizationUrl,
          config.installUrl,
        );
        return json(result, result.ok === true ? 201 : statusForError(result.error));
      } catch (error) {
        if (error instanceof Error && error.message === "product_postgres_invalid_response") {
          return json({ ok: false, error: "product_postgres_invalid_response" }, 503);
        }
        return postgresError(error);
      }
    }

    if (url.pathname === PRODUCT_OWNER_GITHUB_AUTHORIZATION_COMPLETIONS_PATH) {
      if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
      if (url.search !== "") return json({ ok: false, error: "github_authorization_completion_invalid" }, 400);
      const body = await readBoundedJsonObject(request, 4096);
      if (!exactObjectKeys(body, ["code", "state"])
          || typeof body.code !== "string" || !OAUTH_CODE.test(body.code)
          || typeof body.state !== "string" || !STATE.test(body.state)) {
        return json({ ok: false, error: "github_authorization_completion_invalid" }, 400);
      }
      const match = STATE.exec(body.state);
      if (!match) return json({ ok: false, error: "github_authorization_completion_invalid" }, 400);
      const challengeId = match[1].toLowerCase();

      try {
        const hash = await stateSha256(body.state);
        const begun = await beginCompletion(env, {
          ownerUserId: identity.ownerUserId,
          challengeId,
          stateSha256: hash,
        });
        if (begun.ok === false) {
          const result = publicAuthorityError(begun, COMPLETION_ERRORS);
          return json(result, statusForError(result.error));
        }
        if (begun.ok !== true || begun.challenge_id !== challengeId
            || !isCanonicalUuid(begun.project_id)
            || typeof begun.expires_at !== "string"
            || !Number.isFinite(Date.parse(begun.expires_at))) {
          return json({ ok: false, error: "product_postgres_invalid_response" }, 503);
        }

        const codeVerifier = await deriveCodeVerifier(
          config.pkceSecret, challengeId, identity.ownerUserId,
        );
        const accessToken = await exchangeGithubAuthorizationCode(
          config, body.code, codeVerifier, fetcher,
        );
        const verified = await collectVerifiedGithubRepositories(accessToken, fetcher);
        const completed = await completeAuthorization(env, {
          ownerUserId: identity.ownerUserId,
          challengeId,
          githubUserId: verified.githubUserId,
          githubUserLogin: verified.githubUserLogin,
          candidates: verified.candidates,
        });
        const result = completionResponse(
          completed, challengeId, verified.candidates.length, config.installUrl,
        );
        return json(result, result.ok === true ? 200 : statusForError(result.error));
      } catch (error) {
        if (error instanceof ProductPostgresError) return postgresError(error);
        if (error instanceof Error && error.message === "product_postgres_invalid_response") {
          return json({ ok: false, error: "product_postgres_invalid_response" }, 503);
        }
        // The OAuth code is one-shot and beginCompletion consumes the state.
        // Never replay or report provider/SQL uncertainty as success.
        return json({ ok: false, error: "github_authorization_unconfirmed" }, 503);
      }
    }

    if (url.pathname === PRODUCT_OWNER_GITHUB_REPOSITORY_CANDIDATES_PATH) {
      if (request.method !== "GET") return json({ ok: false, error: "method_not_allowed" }, 405);
      if (!hasExactQueryParameters(url, ["challenge_id"])) {
        return json({ ok: false, error: "github_repository_candidates_invalid" }, 400);
      }
      const challengeId = (url.searchParams.get("challenge_id") ?? "").toLowerCase();
      if (!isCanonicalUuid(challengeId)) {
        return json({ ok: false, error: "github_repository_candidates_invalid" }, 400);
      }
      try {
        const raw = await readCandidates(env, {
          ownerUserId: identity.ownerUserId,
          challengeId,
        });
        const result = candidatesResponse(raw, challengeId);
        return json(result, result.ok === true ? 200 : statusForError(result.error));
      } catch (error) {
        if (error instanceof Error && error.message === "product_postgres_invalid_response") {
          return json({ ok: false, error: "product_postgres_invalid_response" }, 503);
        }
        return postgresError(error);
      }
    }

    if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
    if (url.search !== "") return json({ ok: false, error: "github_repository_selection_invalid" }, 400);
    const body = await readBoundedJsonObject(request, 4096);
    if (!exactObjectKeys(body, ["challenge_id", "repository_id", "confirm"])
        || typeof body.challenge_id !== "string" || !isCanonicalUuid(body.challenge_id)
        || typeof body.repository_id !== "string" || !DECIMAL_ID.test(body.repository_id)
        || body.confirm !== "select_repository") {
      return json({ ok: false, error: "github_repository_selection_invalid" }, 400);
    }

    try {
      const raw = await selectRepository(env, {
        ownerUserId: identity.ownerUserId,
        challengeId: body.challenge_id.toLowerCase(),
        repositoryId: body.repository_id,
      });
      const result = selectionResponse(
        raw, body.challenge_id.toLowerCase(), body.repository_id,
      );
      return json(result, result.ok === true ? 200 : statusForError(result.error));
    } catch (error) {
      if (error instanceof Error && error.message === "product_postgres_invalid_response") {
        return json({ ok: false, error: "product_postgres_invalid_response" }, 503);
      }
      return postgresError(error);
    }
  };
}

export function handleProductOwnerGithubAuthorization(
  request: Request,
  env: Env,
): Promise<Response> {
  return createOwnerGithubAuthorizationHandler(env)(request);
}
