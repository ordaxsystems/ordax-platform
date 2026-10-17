import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  canonicalGithubRepositoryFullName,
  createOwnerProjectScopeHandler,
} from "../cloudflare/src/product_owner_project_scope.ts";

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

function request(repository = "ordaxsystems/ordax-runtime", deviceId = DEVICE) {
  const url = new URL("https://mcp.example/v3/owner/project-scope");
  url.searchParams.set("device_id", deviceId);
  url.searchParams.set("repository_full_name", repository);
  return new Request(url, { headers: { authorization: "Bearer test" } });
}

test("GitHub repository identity is canonical owner/repository only, never a URL or local slug", () => {
  assert.equal(canonicalGithubRepositoryFullName("ordaxsystems/ordax-runtime"), "ordaxsystems/ordax-runtime");
  assert.equal(canonicalGithubRepositoryFullName("  OrdaXSystems/ordax-runtime  "), "ordaxsystems/ordax-runtime");
  assert.equal(
    canonicalGithubRepositoryFullName("ORDAXSYSTEMS/ORDAX-RUNTIME"),
    canonicalGithubRepositoryFullName("ordaxsystems/ordax-runtime"),
  );
  for (const invalid of [
    "ordax-runtime",
    "https://github.com/ordaxsystems/ordax-runtime",
    "git@github.com:ordaxsystems/ordax-runtime.git",
    "ordaxsystems/one/two",
    "ordax systems/ordax-runtime",
    "ordaxsystems/",
  ]) assert.equal(canonicalGithubRepositoryFullName(invalid), null);
});

test("Owner project scope handler returns only the canonical server-resolved scope", async () => {
  let observed: unknown[] = [];
  const handler = createOwnerProjectScopeHandler(ENV, {
    authenticate: authenticated,
    resolve: async (_env, owner, device, repository) => {
      observed = [owner, device, repository];
      return {
        ok: true,
        space_id: SPACE,
        project_id: PROJECT,
        repository_id: 12345,
        repository_full_name: "ordaxsystems/ordax-runtime",
      };
    },
  });
  const response = await handler(request());
  assert.equal(response.status, 200);
  assert.deepEqual(observed, [OWNER, DEVICE, "ordaxsystems/ordax-runtime"]);
  assert.deepEqual(await response.json(), {
    ok: true,
    space_id: SPACE,
    project_id: PROJECT,
    repository_id: 12345,
    repository_full_name: "ordaxsystems/ordax-runtime",
  });
});

test("resolver remains fail-closed for no match, ambiguity and invalid model-selected identity", async () => {
  for (const [error, status] of [
    ["owner_project_scope_not_found", 404],
    ["owner_project_scope_ambiguous", 409],
    ["device_not_owned", 403],
  ] as const) {
    const handler = createOwnerProjectScopeHandler(ENV, {
      authenticate: authenticated,
      resolve: async () => ({ ok: false, error }),
    });
    const response = await handler(request());
    assert.equal(response.status, status);
    assert.equal((await response.json()).error, error);
  }

  let called = false;
  const invalid = createOwnerProjectScopeHandler(ENV, {
    authenticate: authenticated,
    resolve: async () => { called = true; return { ok: true }; },
  });
  assert.equal((await invalid(request("local-slug"))).status, 400);
  assert.equal((await invalid(request("ordaxsystems/ordax-runtime", "not-a-device"))).status, 400);
  assert.equal(called, false);
});

test("resolver endpoint is read-only and requires authenticated Product Owner identity", async () => {
  const handler = createOwnerProjectScopeHandler(ENV, {
    authenticate: authenticated,
    resolve: async () => ({ ok: false, error: "owner_project_scope_not_found" }),
  });
  assert.equal((await handler(new Request("https://mcp.example/v3/owner/project-scope", { method: "POST" }))).status, 405);

  const denied = createOwnerProjectScopeHandler(ENV, {
    authenticate: async () => ({ ok: false as const, error: "product_auth_required", status: 401 }),
  });
  assert.equal((await denied(request())).status, 401);
});

test("SQL resolver uses canonical authorization and least-privilege runtime execution", () => {
  const sql = readFileSync(new URL(
    "../supabase/migrations/20261016141000_owner_project_scope_resolver_v1.sql",
    import.meta.url,
  ), "utf8").toLowerCase();
  for (const token of [
    "security definer",
    "set search_path = ''",
    "ordax_trusted_actor_auth_eligible_v1",
    "ordax_subject_can_access_project_v1",
    "ordax_subject_can_admin_space_v1",
    "c.provider = 'github'",
    "c.state = 'active'",
    "p.state = 'active'",
    "sd.access_mode = 'execute'",
    "b.state = 'active'",
    "owner_project_scope_not_found",
    "owner_project_scope_ambiguous",
    "to ordax_edge_runtime",
  ]) assert.ok(sql.includes(token), `missing ${token}`);

  assert.ok(sql.includes("from public, anon, authenticated, service_role, ordax_edge_executor, ordax_edge_runtime"));
  assert.equal(sql.includes("grant select"), false);
  assert.equal(sql.includes("grant insert"), false);
  assert.equal(sql.includes("grant update"), false);
  assert.equal(sql.includes("grant delete"), false);
});
