import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import { createRequire } from "node:module";
import { randomUUID } from "node:crypto";

const require = createRequire(new URL("../cloudflare/package.json", import.meta.url));
const { PGlite } = require("@electric-sql/pglite");
const migration = fs.readFileSync(new URL(
  "../supabase/migrations/20261101204500_product_mcp_target_discovery_idempotent_v1.sql",
  import.meta.url,
), "utf8");

test("target-discovery RPC reuses exact active grants, repairs drift and revokes on OAuth consent loss", async () => {
  const db = new PGlite();
  const owner = randomUUID();
  const client = randomUUID();
  const otherClient = randomUUID();
  const device1 = randomUUID();
  const device2 = randomUUID();
  const device3 = randomUUID();
  try {
    // Local-only authority fixture: the production ensure RPC is tested
    // unchanged; only its existing lower-level grant writer is simulated.
    await db.exec(`
      create schema auth; create schema private;
      create role anon;
      create role authenticated;
      create role service_role;
      create role ordax_edge_executor;
      create table auth.oauth_clients(
        id uuid primary key, deleted_at timestamptz, client_type text not null
      );
      create table auth.oauth_consents(
        client_id uuid not null, user_id uuid not null, revoked_at timestamptz
      );
      create table public.ordax_product_devices(
        device_id uuid primary key, owner_user_id uuid not null, state text not null
      );
      create table public.ordax_remote_capability_grants(
        grant_id uuid primary key default gen_random_uuid(),
        owner_user_id uuid not null,
        device_id uuid not null,
        client_kind text not null,
        client_id text not null,
        profile_key text not null,
        space_id uuid,
        project_id uuid,
        state text not null,
        scope_kind text not null,
        capability text not null,
        access_mode text not null,
        valid_until timestamptz,
        approved_by_user_id uuid
      );
      create table public.discovery_authorize_calls(
        owner_user_id uuid not null, device_id uuid not null, client_id uuid not null
      );
      create table public.test_owner_eligibility(
        owner_user_id uuid primary key, eligible boolean not null
      );
      create or replace function private.ordax_trusted_actor_auth_eligible_v1(
        p_owner_user_id uuid
      ) returns boolean language sql stable security definer set search_path = ''
      as $owner$
        select coalesce((
          select e.eligible from public.test_owner_eligibility e
          where e.owner_user_id = p_owner_user_id
        ),false);
      $owner$;
      create or replace function public.ordax_authorize_product_mcp_target_discovery_v1(
        p_owner_user_id uuid, p_device_id uuid, p_oauth_client_id uuid
      ) returns jsonb
      language plpgsql
      as $writer$
      begin
        insert into public.discovery_authorize_calls
          values (p_owner_user_id, p_device_id, p_oauth_client_id);
        update public.ordax_remote_capability_grants
           set state = 'revoked'
         where owner_user_id = p_owner_user_id
           and device_id = p_device_id
           and client_id = p_oauth_client_id::text
           and profile_key = 'mcp-discovery'
           and client_kind = 'product-mcp'
           and state = 'active'
           and space_id is null and project_id is null;
        insert into public.ordax_remote_capability_grants (
          owner_user_id, device_id, client_kind, client_id, profile_key,
          space_id, project_id, state, scope_kind, capability, access_mode,
          valid_until, approved_by_user_id
        ) values (
          p_owner_user_id, p_device_id, 'product-mcp', p_oauth_client_id::text,
          'mcp-discovery', null, null, 'active', 'device',
          'product.target.read', 'read', null, p_owner_user_id
        );
        return jsonb_build_object('ok', true);
      end;
      $writer$;
    `);
    await db.exec(migration);
    await db.query("insert into public.test_owner_eligibility values($1,true)", [owner]);
    for (const oauthId of [client, otherClient]) {
      await db.query("insert into auth.oauth_clients values($1,null,'public')", [oauthId]);
    }
    await db.query("insert into auth.oauth_consents values($1,$2,null)", [client, owner]);
    for (const deviceId of [device1, device2]) {
      await db.query(
        "insert into public.ordax_product_devices values($1,$2,'active')",
        [deviceId, owner],
      );
    }
    const ensure = async (clientId = client) => (await db.query(
      "select public.ordax_ensure_product_mcp_target_discovery_v1($1,$2) as result",
      [owner, clientId],
    )).rows[0].result;
    const calls = async () => Number((await db.query(
      "select count(*)::integer as n from public.discovery_authorize_calls",
    )).rows[0].n);
    const rows = async () => (await db.query(
      "select grant_id::text as id, device_id::text as device, state, capability " +
      "from public.ordax_remote_capability_grants order by device_id, grant_id",
    )).rows;

    // First OAuth-consented discovery installs precisely one read-only grant
    // per active device. Subsequent calls cannot revoke/reinsert them.
    assert.equal((await ensure()).devices_granted, 2);
    assert.equal(await calls(), 2);
    const original = await rows();
    assert.equal(original.length, 2);
    assert.equal(original.every((row: any) => row.state === "active"), true);
    for (let repeat = 0; repeat < 3; repeat++) {
      assert.equal((await ensure()).devices_granted, 2);
      assert.equal(await calls(), 2);
      assert.deepEqual(await rows(), original, "no grant ID rotation or ledger growth");
    }

    // A newly registered active device receives exactly one new grant.
    await db.query(
      "insert into public.ordax_product_devices values($1,$2,'active')",
      [device3, owner],
    );
    assert.equal((await ensure()).devices_granted, 3);
    assert.equal(await calls(), 3);
    assert.equal((await rows()).length, 3);
    assert.equal((await ensure()).devices_granted, 3);
    assert.equal(await calls(), 3);

    // A corrupted/extra capability in the same active discovery group must
    // NEVER make an existing exact grant a sufficient reason to skip repair.
    await db.query(`
      insert into public.ordax_remote_capability_grants (
        owner_user_id, device_id, client_kind, client_id, profile_key,
        state, scope_kind, capability, access_mode, approved_by_user_id
      ) values ($1, $2, 'product-mcp', $3, 'mcp-discovery',
        'active', 'device', 'computer.terminal_exec', 'write', $1)
    `, [owner, device1, client]);
    assert.equal((await ensure()).devices_granted, 3);
    assert.equal(await calls(), 4, "repair exactly one malformed grant group");
    const grants = await rows();
    assert.equal(grants.filter((row: any) => row.state === "active").length, 3);
    assert.equal(grants.filter((row: any) =>
      row.state === "active" && row.capability !== "product.target.read").length, 0);
    assert.equal((await ensure()).devices_granted, 3);
    assert.equal(await calls(), 4, "a repaired group remains stable");

    // Removing consent must fail closed even if the read-only grant exists.
    await db.query(
      "update auth.oauth_consents set revoked_at = now() where user_id = $1 and client_id = $2",
      [owner, client],
    );
    const revoked = await ensure();
    assert.equal(revoked.ok, false);
    assert.equal(revoked.error, "product_mcp_oauth_consent_required");
    assert.equal(await calls(), 4);
    const unconsented = await ensure(otherClient);
    assert.equal(unconsented.ok, false);
    assert.equal(unconsented.error, "product_mcp_oauth_consent_required");
    assert.equal(await calls(), 4);

    // A reused read grant is never a way to bypass a newly disabled Owner.
    // The old writer checked this via replace_remote_grant_group on every
    // call; the optimized ensure must preserve the same fail-closed decision.
    await db.query(
      "update auth.oauth_consents set revoked_at = null where user_id = $1 and client_id = $2",
      [owner, client],
    );
    await db.query(
      "update public.test_owner_eligibility set eligible=false where owner_user_id=$1",
      [owner],
    );
    const disabledOwner = await ensure();
    assert.equal(disabledOwner.ok, false);
    assert.equal(disabledOwner.error, "product_owner_auth_ineligible");
    assert.equal(await calls(), 4, "suspended Owner must not rotate or reuse grants");
  } finally {
    await db.close();
  }
});

test("canonical auto-discovery keeps one PostgreSQL owner/client lock and exact ACL", () => {
  for (const expected of [
    "pg_catalog.pg_advisory_xact_lock",
    "p_owner_user_id::text || '|' || p_oauth_client_id::text",
    "consent.revoked_at is null",
    "private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)",
    "c.deleted_at is null",
    "c.client_type::text = 'public'",
    "g.profile_key = 'mcp-discovery'",
    "g.state = 'active'",
    "v_active_count <> 1 or v_exact_count <> 1",
    "public.ordax_authorize_product_mcp_target_discovery_v1(",
    "revoke all on function public.ordax_ensure_product_mcp_target_discovery_v1(uuid, uuid)",
    "to ordax_edge_executor",
  ]) assert.ok(migration.includes(expected), expected);
  assert.equal(migration.includes("create table"), false);
  assert.equal(migration.includes("drop table"), false);
});
