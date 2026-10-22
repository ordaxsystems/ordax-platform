import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import { createRequire } from "node:module";
import { randomUUID } from "node:crypto";
import { validOwnerMcpUsage, PRODUCT_OWNER_MCP_USAGE_PATH } from "../cloudflare/src/product_mcp_usage_read.ts";
import { createCanonicalProductMcpGateway, isProductTrustedClientPath } from "../cloudflare/src/product_mcp_entry.ts";

const require = createRequire(new URL("../cloudflare/package.json", import.meta.url));
const { PGlite } = require("@electric-sql/pglite");
const migrations = new URL("../supabase/migrations/", import.meta.url);
const read = (file: string) => fs.readFileSync(new URL(file, migrations), "utf8");

const env = {
  PRODUCT_AUTH_ISSUER: "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1",
  PRODUCT_AUTH_AUDIENCE: "authenticated",
  PRODUCT_AUTH_JWKS_URL: "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1/.well-known/jwks.json",
  POSTGRES: { connectionString: "postgresql://localhost:6543/example" },
};
const handlers = {
  session: async () => Response.json({ ok: true }),
  targets: async () => Response.json({ ok: true, targets: [] }),
  getAction: async () => Response.json({ ok: false }, { status: 404 }),
};

test("signed owner usage endpoint never takes account IDs from a query or unauthenticated caller", async () => {
  assert.equal(isProductTrustedClientPath(PRODUCT_OWNER_MCP_USAGE_PATH), true);
  assert.equal(isProductTrustedClientPath(PRODUCT_OWNER_MCP_USAGE_PATH + "/extra"), false);
  const gateway = createCanonicalProductMcpGateway(env, handlers);
  for (const host of ["mcp.ordax.com.br", "ordax-mcp.ordaxsystems.workers.dev"]) {
    const res = await gateway(new Request(`https://${host}${PRODUCT_OWNER_MCP_USAGE_PATH}?owner_user_id=${randomUUID()}`));
    assert.equal(res.status, 401);
    assert.deepEqual(await res.json(), { ok: false, error: "product_auth_required" });
    assert.equal(res.headers.get("cache-control"), "no-store");
  }
  const post = await gateway(new Request("https://mcp.ordax.com.br" + PRODUCT_OWNER_MCP_USAGE_PATH, { method: "POST" }));
  assert.equal(post.status, 405);
  const unknown = await gateway(new Request("https://ordax-mcp.ordaxsystems.workers.dev/v3/product/usage/other"));
  assert.equal(unknown.status, 404);
});

test("usage projection refuses forged billable state and malformed aggregates", () => {
  const current = new Date();
  const month = `${current.getUTCFullYear()}-${String(current.getUTCMonth() + 1).padStart(2,"0")}-01`;
  const previous = new Date(Date.UTC(current.getUTCFullYear(), current.getUTCMonth() - 1, 1));
  const prior = `${previous.getUTCFullYear()}-${String(previous.getUTCMonth()+1).padStart(2,"0")}-01`;
  const good = {
    ok: true, schema: "ordax.product-mcp-usage/1", observed_only: true, billable: false,
    current_month: month, previous_month: prior,
    entries: [{ month, tool_name: "ordax_targets", tool_calls: 3 }],
  };
  assert.equal(validOwnerMcpUsage(good), true);
  for (const change of [
    { billable: true }, { observed_only: false }, { current_month: "today" },
    { entries: [{ ...good.entries[0], tool_calls: -1 }] },
    { entries: [{ ...good.entries[0], tool_calls: 0.5 }] },
    { entries: [...good.entries, ...good.entries] },
    { entries: [{ ...good.entries[0], tool_name: "../secret" }] },
    { entries: [{ ...good.entries[0], month: "2020-01-01" }] },
  ]) assert.equal(validOwnerMcpUsage({ ...good, ...change }), false, JSON.stringify(change));
});

test("canonical private aggregate read isolates owners; never creates purchase authority", async () => {
  const db = new PGlite();
  const [owner, other, client] = Array.from({ length: 3 }, () => randomUUID());
  const newMigration = read("20261022201500_product_mcp_usage_self_read_v1.sql");
  try {
    await db.exec(`
      create schema private; create schema auth;
      create role anon; create role authenticated; create role service_role;
      create role ordax_edge_executor; create role ordax_edge_runtime;
      grant ordax_edge_executor to ordax_edge_runtime;
      create table auth.users(id uuid primary key, deleted_at timestamptz,
        is_anonymous boolean default false, confirmed_at timestamptz default now(), banned_until timestamptz);
      create table auth.oauth_clients(id uuid primary key, client_type text default 'public', deleted_at timestamptz);
      create table auth.oauth_consents(user_id uuid, client_id uuid, revoked_at timestamptz);
      create table public.ordax_accounts(user_id uuid primary key);
    `);
    const eligibility = read("20261007212000_trusted_actor_auth_eligibility_v1.sql")
      .match(/create function private\.ordax_trusted_actor_auth_eligible_v1\([\s\S]*?\$function\$;/);
    assert.ok(eligibility);
    await db.exec(eligibility[0]);
    await db.exec(read("20261022071118_ordax_product_mcp_usage_meter_v1.sql"));
    await db.exec(newMigration);
    for (const userId of [owner, other]) {
      await db.query("insert into auth.users(id) values ($1)", [userId]);
      await db.query("insert into public.ordax_accounts(user_id) values ($1)", [userId]);
    }
    await db.query("insert into auth.oauth_clients(id) values ($1)", [client]);
    await db.query("insert into auth.oauth_consents values ($1,$2,null)", [owner,client]);
    const usageSql = "select public.ordax_get_product_mcp_usage_v1($1) as usage";
    const lookup = async (id: string | null) => (await db.query(usageSql, [id])).rows[0].usage;
    assert.equal((await lookup(owner)).entries.length, 0);
    const recorded = (await db.query(
      "select public.ordax_record_product_mcp_usage_v1($1,$2,$3,$4) as result",
      [owner,client,"ordax_targets","a".repeat(64)],
    )).rows[0].result;
    assert.equal(recorded.ok,true);
    assert.equal(recorded.recorded,true);
    const own = await lookup(owner);
    assert.equal(own.entries.length, 1);
    assert.equal(own.entries[0].tool_name,"ordax_targets");
    assert.equal(own.entries[0].tool_calls,1);
    assert.equal(own.billable,false);
    assert.equal(own.observed_only,true);
    assert.equal(validOwnerMcpUsage(own),true);
    assert.deepEqual((await lookup(other)).entries, [], "other account sees no data");
    assert.equal((await lookup(null)).error,"product_mcp_usage_owner_invalid");
    await db.query("update auth.users set deleted_at=now() where id=$1", [owner]);
    assert.equal((await lookup(owner)).error,"product_owner_auth_ineligible");
    for (const role of ["anon","authenticated","service_role"]) {
      const res=await db.query("select has_function_privilege($1,'public.ordax_get_product_mcp_usage_v1(uuid)','EXECUTE') as allowed",[role]);
      assert.equal(res.rows[0].allowed,false,role);
    }
    const positive=await db.query("select has_function_privilege('ordax_edge_executor','public.ordax_get_product_mcp_usage_v1(uuid)','EXECUTE') as allowed");
    assert.equal(positive.rows[0].allowed,true);
    await db.exec("set role ordax_edge_runtime");
    await assert.rejects(()=>db.query("select * from private.ordax_product_mcp_usage_monthly"));
    await db.exec("reset role");
  } finally { await db.close(); }
});

test("new read migration has no subscription, quota, entitlement or table grant", () => {
  const sql=read("20261022201500_product_mcp_usage_self_read_v1.sql").toLowerCase();
  for(const marker of ["security definer","set search_path = ''","ordax_trusted_actor_auth_eligible_v1","to ordax_edge_executor","from public, anon, authenticated, service_role"])
    assert.ok(sql.includes(marker),marker);
  for(const bad of ["create table","create subscription","grant select","update private.ordax_product_mcp_usage_monthly","create policy"])
    assert.equal(sql.includes(bad),false,bad);
});
