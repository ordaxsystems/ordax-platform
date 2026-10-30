import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  canonicalGithubRepositoryFullName,
  createOwnerProjectScopeHandler,
  projectScopeResponse,
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

test("GitHub repository identity is owner/repository only, never a URL or local slug", () => {
  assert.equal(canonicalGithubRepositoryFullName("ordaxsystems/ordax-runtime"), "ordaxsystems/ordax-runtime");
  assert.equal(canonicalGithubRepositoryFullName("  OrdaXSystems/ordax-runtime  "), "ordaxsystems/ordax-runtime");
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

test("Owner scope response retains only vetted canonical IDs, never SQL extras", () => {
  const raw = {
    ok: true, space_id: SPACE, project_id: PROJECT, repository_id: 12345,
    repository_full_name: "OrdaXSystems/ordax-runtime",
    root: "C:\\\\secret\\\\project", token: "DO_NOT_LEAK", actor_id: OWNER,
  };
  assert.deepEqual(projectScopeResponse(raw, "ordaxsystems/ordax-runtime"), {
    ok: true, space_id: SPACE, project_id: PROJECT, repository_id: 12345,
    repository_full_name: "OrdaXSystems/ordax-runtime",
  });
  assert.deepEqual(
    projectScopeResponse({ok:false,error:"device_not_owned",root:"DO_NOT_LEAK"},
      "ordaxsystems/ordax-runtime"),
    {ok:false,error:"device_not_owned"},
  );
});

test("malformed, mismatched or unexpected SQL projection cannot claim project authority", () => {
  const value = {ok:true,space_id:SPACE,project_id:PROJECT,
    repository_id:12345,repository_full_name:"ordaxsystems/ordax-runtime"};
  const wrong = [
    {...value,space_id:"wrong"},
    {...value,project_id:"wrong"},
    {...value,repository_id:0},
    {...value,repository_id:Number.MAX_SAFE_INTEGER+1},
    {...value,repository_id:"12345"},
    {...value,repository_full_name:"other/repo"},
    {...value,repository_full_name:"C:\\\\users\\\\folder"},
    {...value,repository_full_name:"../../path"},
    {ok:true}, {ok:false,error:"internal_stack_trace"},
    null, [], 7,
  ];
  for (const row of wrong) {
    assert.throws(() => projectScopeResponse(row as any,"ordaxsystems/ordax-runtime"),
      /product_postgres_invalid_response/);
  }
});

test("Owner endpoint redacts SQL drift and resolver exception details", async () => {
  const badRows = [
    {ok:true,space_id:SPACE,project_id:PROJECT,repository_id:12345,
      repository_full_name:"another/repository",secret:"never"},
    {ok:false,error:"database_credentials=secret"},
    {ok:true,space_id:SPACE,project_id:PROJECT,repository_id:"not-a-number",
      repository_full_name:"ordaxsystems/ordax-runtime"},
  ];
  for (const raw of badRows) {
    const handler = createOwnerProjectScopeHandler(ENV, {
      authenticate: authenticated,resolve: async () => raw,
    });
    const response = await handler(request());
    assert.equal(response.status,503);
    assert.deepEqual(await response.json(),{ok:false,error:"product_postgres_invalid_response"});
  }
  const exception = createOwnerProjectScopeHandler(ENV, {
    authenticate: authenticated,
    resolve: async () => {throw Error("POSTGRES_PASSWORD=DO_NOT_LEAK");},
  });
  const response = await exception(request());
  assert.equal(response.status,503);
  const body = await response.json();
  assert.deepEqual(body,{ok:false,error:"product_postgres_unavailable"});
});
