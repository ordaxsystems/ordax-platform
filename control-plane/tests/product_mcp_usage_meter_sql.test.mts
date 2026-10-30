import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import { randomUUID } from "node:crypto";
import { productMcpUsageMeterEnabled } from "../cloudflare/src/product_postgres_store.ts";

const require = createRequire(new URL("../cloudflare/package.json", import.meta.url));
const { PGlite } = require("@electric-sql/pglite");
const migrations = new URL("../supabase/migrations/", import.meta.url);
const read = (name: string) => fs.readFileSync(new URL(name, migrations), "utf8");
const migrationName = "20261022071118_ordax_product_mcp_usage_meter_v1.sql";

test("shadow metering requires an explicit mode and a provisioned high-entropy key", () => {
  assert.equal(productMcpUsageMeterEnabled({}), false);
  assert.equal(productMcpUsageMeterEnabled({ MCP_USAGE_METER_MODE: "shadow" }), false);
  assert.equal(productMcpUsageMeterEnabled({
    MCP_USAGE_METER_MODE: "shadow", MCP_USAGE_FINGERPRINT_KEY: "too-short",
  }), false);
  assert.equal(productMcpUsageMeterEnabled({
    MCP_USAGE_METER_MODE: "off", MCP_USAGE_FINGERPRINT_KEY: "fixture-only-random-secret-key-with-32-bytes",
  }), false);
  assert.equal(productMcpUsageMeterEnabled({
    MCP_USAGE_METER_MODE: "shadow", MCP_USAGE_FINGERPRINT_KEY: "fixture-only-random-secret-key-with-32-bytes",
  }), true);
});

test("Product MCP usage is idempotent, consent-bound, private and pruned without billing enforcement", async () => {
  const db = new PGlite();
  const [owner, client, retryClient, otherOwner] = Array.from({ length: 4 }, () => randomUUID());
  const recordSql = "select public.ordax_record_product_mcp_usage_v1($1,$2,$3,$4) as result";
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
    assert.ok(eligibility, "canonical account eligibility function found");
    await db.exec(eligibility[0]);
    await db.exec(read(migrationName));

    for (const userId of [owner, otherOwner]) {
      await db.query("insert into auth.users(id) values($1)", [userId]);
      await db.query("insert into public.ordax_accounts values($1)", [userId]);
    }
    for (const clientId of [client, retryClient]) {
      await db.query("insert into auth.oauth_clients(id) values($1)", [clientId]);
      await db.query("insert into auth.oauth_consents values($1,$2,null)", [owner, clientId]);
    }

    const fingerprint = "a".repeat(64);
    const call = async (userId = owner, clientId = client, toolName = "ordax_targets", digest = fingerprint) =>
      (await db.query(recordSql, [userId, clientId, toolName, digest])).rows[0].result;
    const first = await call();
    assert.equal(first.ok, true);
    assert.equal(first.recorded, true);
    assert.equal(first.tool_calls, 1);
    const replay = await call();
    assert.equal(replay.recorded, false);
    assert.equal(replay.tool_calls, 1);
    const otherClient = await call(owner, retryClient);
    assert.equal(otherClient.recorded, true, "deduplication is scoped to OAuth client");
    assert.equal(otherClient.tool_calls, 2);
    const otherTool = await call(owner, client, "ordax_profile", "b".repeat(64));
    assert.equal(otherTool.tool_calls, 1, "aggregates remain separated by tool");

    assert.equal((await call(otherOwner)).ok, false, "unconsented client cannot meter another account");
    await db.exec("update auth.oauth_consents set revoked_at=now() where client_id='" + client + "'");
    assert.equal((await call(owner, client, "ordax_targets", "c".repeat(64))).error, "product_mcp_oauth_consent_required");
    await db.exec("update auth.oauth_consents set revoked_at=null where client_id='" + client + "'");
    await db.exec("update auth.oauth_clients set deleted_at=now() where id='" + client + "'");
    assert.equal((await call(owner, client, "ordax_targets", "d".repeat(64))).error, "product_mcp_oauth_consent_required");
    assert.equal((await call(owner, retryClient, "invalid tool", "e".repeat(64))).error, "product_mcp_usage_input_invalid");

    const prune = async () => (await db.query("select public.ordax_prune_product_mcp_usage_v1() as result")).rows[0].result;
    await db.exec(`
      insert into private.ordax_product_mcp_usage_monthly(owner_user_id,usage_month,tool_name,tool_calls)
      values ('${owner}', (date_trunc('month', now()) - interval '2 months')::date, 'old_tool', 9),
             ('${owner}', (date_trunc('month', now()) - interval '1 month')::date, 'previous_tool', 3);
      insert into private.ordax_product_mcp_usage_dedup(owner_user_id,client_id,usage_month,tool_name,request_fingerprint,recorded_at)
      values ('${owner}','${retryClient}',(date_trunc('month', now()) - interval '2 months')::date,'old_tool','${"f".repeat(64)}',now()-interval '25 hours');
    `);
    const pruned = await prune();
    assert.equal(pruned.ok, true);
    assert.equal(pruned.fingerprints_deleted, 1);
    assert.equal(pruned.monthly_rows_deleted, 1);
    const retained = await db.query(
      "select usage_month,tool_name from private.ordax_product_mcp_usage_monthly where owner_user_id=$1 order by usage_month,tool_name",
      [owner],
    );
    assert.equal(retained.rows.some((row: any) => row.tool_name === "old_tool"), false);
    assert.equal(retained.rows.some((row: any) => row.tool_name === "previous_tool"), true);

    for (const signature of [
      "public.ordax_record_product_mcp_usage_v1(uuid,uuid,text,text)",
      "public.ordax_prune_product_mcp_usage_v1()",
    ]) {
      for (const role of ["anon", "authenticated", "service_role", "ordax_edge_executor"]) {
        const allowed = (await db.query("select has_function_privilege($1,$2,'EXECUTE') as allowed", [role, signature])).rows[0].allowed;
        assert.equal(allowed, role === "ordax_edge_executor", `${role}: ${signature}`);
      }
      assert.equal((await db.query("select has_function_privilege('ordax_edge_runtime',$1,'EXECUTE') as allowed", [signature])).rows[0].allowed, true);
    }
    for (const relation of [
      "private.ordax_product_mcp_usage_monthly", "private.ordax_product_mcp_usage_dedup",
    ]) {
      for (const role of ["anon", "authenticated", "service_role", "ordax_edge_executor", "ordax_edge_runtime"]) {
        const allowed = (await db.query("select has_table_privilege($1,$2,'SELECT') as allowed", [role, relation])).rows[0].allowed;
        assert.equal(allowed, false, `${role}: ${relation}`);
      }
    }
    await db.exec("set role ordax_edge_runtime");
    assert.equal((await db.query(recordSql, [owner, retryClient, "ordax_targets", "9".repeat(64)])).rows[0].result.ok, true);
    await assert.rejects(() => db.query("select * from private.ordax_product_mcp_usage_monthly"));
    await db.exec("reset role");

    const month = (await db.query("select max(usage_month)::text as month from private.ordax_product_mcp_usage_monthly where owner_user_id=$1", [owner])).rows[0].month;
    assert.equal(typeof first.usage_month, "string");
    assert.equal(first.usage_month.slice(8), "01");
    assert.ok(month);
  } finally { await db.close(); }
});

test("usage-meter SQL contains no billing, quota, or request-argument storage", () => {
  const sql = read(migrationName).toLowerCase().replace(/\s+/g, " ");
  for (const required of [
    "security definer", "set search_path = ''", "ordax_trusted_actor_auth_eligible_v1",
    "oauth_consents", "client_type::text = 'public'", "enable row level security",
    "force row level security", "on conflict (owner_user_id, client_id, usage_month, request_fingerprint) do nothing",
    "interval '24 hours'", "to ordax_edge_executor",
  ]) assert.ok(sql.includes(required), required);
  for (const forbidden of ["p_arguments", "p_prompt", "create table public.ordax_subscriptions", "quota_limit", "billing_charge"]) {
    assert.equal(sql.includes(forbidden), false, forbidden);
  }
});
