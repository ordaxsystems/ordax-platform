import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import { randomUUID } from "node:crypto";

const require = createRequire(new URL("../cloudflare/package.json", import.meta.url));
const { PGlite } = require("@electric-sql/pglite");
const migrations = new URL("../supabase/migrations/", import.meta.url);
const read = (name: string) => fs.readFileSync(new URL(name, migrations), "utf8");

test("canonical presence expires without a shutdown write and offline sessions never select another PC", async () => {
  const db = new PGlite();
  const [owner, client, desktop, laptop, otherOwner] = Array.from({ length: 5 }, () => randomUUID());
  try {
    await db.exec(`
      create schema private; create schema auth; create schema extensions;
      create role anon; create role authenticated; create role service_role; create role ordax_edge_executor;
      create function extensions.gen_random_uuid() returns uuid language sql as $$ select gen_random_uuid() $$;
      create table auth.users(id uuid primary key,deleted_at timestamptz,is_anonymous boolean default false,
        confirmed_at timestamptz default now(),banned_until timestamptz);
      create table public.ordax_accounts(user_id uuid primary key);
      create table public.ordax_product_devices(device_id uuid primary key,owner_user_id uuid,
        display_name text,device_kind text,channel text,state text);
      create table public.ordax_device_presence(device_id uuid primary key,online boolean,last_seen_at timestamptz);
      create table public.ordax_remote_capability_grants(grant_group_id uuid default gen_random_uuid(),
        owner_user_id uuid,device_id uuid,client_kind text,client_id text,capability text,access_mode text,
        state text,space_id uuid,project_id uuid,scope_kind text,valid_until timestamptz,profile_key text);
      create table private.ordax_central_conversation_bindings(owner_user_id uuid,client_id text,
        session_sha256 text,device_id uuid,space_id uuid,project_id uuid,state text,expires_at timestamptz,request_id uuid);
      create table private.ordax_central_device_session_challenges(challenge_id uuid,owner_user_id uuid,
        client_id text,device_id uuid,session_sha256 text,state text,expires_at timestamptz,binding_expires_at timestamptz);
    `);
    await db.exec(read("20261007212000_trusted_actor_auth_eligibility_v1.sql")
      .match(/create function private\.ordax_trusted_actor_auth_eligible_v1\([\s\S]*?\$function\$;/)![0]);
    await db.exec(read("20261021032000_central_session_operational_device_selection_v1.sql")
      .match(/create or replace function private\.ordax_central_device_grant_eligible_v1\([\s\S]*?\$\$;/)![0]);
    const migration = read("20261022014630_product_presence_freshness_v1.sql");
    await db.exec(migration);
    await db.exec(migration); // replay preserves behavior and ACLs
    await db.query("insert into auth.users(id) values ($1)", [owner]);
    await db.query("insert into public.ordax_accounts values ($1)", [owner]);
    for (const [id, name] of [[desktop, "Desktop"], [laptop, "Laptop"]]) {
      await db.query("insert into public.ordax_product_devices values ($1,$2,$3,'desktop','development','active')", [id, owner, name]);
      await db.query(`insert into public.ordax_remote_capability_grants(owner_user_id,device_id,client_kind,
        client_id,capability,access_mode,state,scope_kind,profile_key)
        values ($1,$2,'product-mcp',$3,'product.target.read','read','active','device','mcp-discovery')`, [owner, id, client]);
    }
    await db.query("insert into public.ordax_device_presence values ($1,true,now()),($2,true,now()-interval '18 hours')", [desktop, laptop]);
    await db.query(`insert into public.ordax_remote_capability_grants(owner_user_id,device_id,client_kind,
      client_id,capability,access_mode,state,scope_kind,profile_key)
      values ($1,$2,'product-mcp',$3,'computer.terminal_exec','write','active','device','device-native-terminal')`, [owner, laptop, client]);
    const catalog = async (subject = owner, oauthClient = client) =>
      (await db.query("select public.ordax_list_product_targets_v1($1,'product-mcp',$2) as result", [subject, oauthClient])).rows[0].result;
    const open = async () => (await db.query("select public.ordax_open_central_device_session_v1($1,$2,$3) as result", [owner, client, "a".repeat(64)])).rows[0].result;
    let targets = (await catalog()).targets;
    assert.equal(targets.length, 2);
    assert.equal(targets.find((t: any) => t.device_id === desktop).online, true);
    assert.equal(targets.find((t: any) => t.device_id === laptop).online, false);
    assert.ok(targets.find((t: any) => t.device_id === laptop).last_seen_at);
    assert.deepEqual(await open(), { ok: false, error: "central_device_offline" });
    assert.equal((await db.query("select count(*)::int as n from private.ordax_central_device_session_challenges")).rows[0].n, 0);
    assert.deepEqual(await catalog(otherOwner), { ok: false, error: "product_owner_auth_ineligible" });
    assert.deepEqual((await catalog(owner, randomUUID())).targets, []);

    // Five-minute coalescing remains live; missing/future/exactly-expired
    // timestamps and explicit shutdown never manufacture connectivity.
    const now = "2026-10-22T00:00:00Z";
    for (const [online, seen, expected] of [
      [true, "2026-10-21T23:54:30Z", true], [true, "2026-10-21T23:54:00Z", false],
      [true, null, false], [true, "2026-10-22T00:00:01Z", false],
      [false, now, false], [null, now, false],
    ]) {
      const row = (await db.query("select private.ordax_product_presence_online_v1($1,$2,$3) as online", [online, seen, now])).rows[0];
      assert.equal(row.online, expected, JSON.stringify([online, seen]));
    }
    await db.query("update public.ordax_device_presence set last_seen_at=now() where device_id=$1", [laptop]);
    assert.equal((await open()).status, "pending");
    const challenge = (await db.query("select device_id from private.ordax_central_device_session_challenges")).rows[0];
    assert.equal(challenge.device_id, laptop);
    // A fresh heartbeat is availability, not a confirmed execution session.
    assert.equal((await db.query("select count(*)::int as n from private.ordax_central_conversation_bindings")).rows[0].n, 0);
    await db.query("update public.ordax_device_presence set online=false where device_id=$1", [laptop]);
    assert.equal((await open()).error, "central_device_offline");
    // Two operational grants remain ambiguous even when just one PC is online.
    await db.query(`insert into public.ordax_remote_capability_grants(owner_user_id,device_id,client_kind,
      client_id,capability,access_mode,state,scope_kind,profile_key)
      values ($1,$2,'product-mcp',$3,'computer.terminal_exec','write','active','device','device-native-terminal')`, [owner, desktop, client]);
    assert.equal((await open()).error, "central_device_target_ambiguous");
    await db.exec("update public.ordax_remote_capability_grants set state='revoked' where capability<>'product.target.read'");
    assert.equal((await open()).error, "central_device_target_missing");
    targets = (await catalog()).targets;
    assert.equal(targets.length, 2); // offline devices remain discoverable
    for (const signature of [
      "public.ordax_list_product_targets_v1(uuid,text,text)",
      "public.ordax_open_central_device_session_v1(uuid,text,text)",
      "private.ordax_product_presence_online_v1(boolean,timestamptz,timestamptz)",
    ]) {
      for (const role of ["anon", "authenticated", "service_role"]) {
        const r = await db.query("select has_function_privilege($1,$2,'EXECUTE') as allowed", [role, signature]);
        assert.equal(r.rows[0].allowed, false, `${role} ${signature}`);
      }
    }
  } finally { await db.close(); }
});
