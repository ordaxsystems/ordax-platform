import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { OWNER_MCP_GRANT_PROFILES } from "../cloudflare/src/product_owner_grant_profiles.ts";

const require = createRequire(new URL("../cloudflare/package.json", import.meta.url));
const { PGlite } = require("@electric-sql/pglite");
const migration = fs.readFileSync(
  new URL("../supabase/migrations/20261113235000_owner_project_device_binding_authority_v1.sql", import.meta.url),
  "utf8",
);

const EXPECTED_PROJECT_CAPABILITIES = [
  "agent.project_briefing",
  "browser.click",
  "browser.list",
  "browser.navigate",
  "browser.screenshot",
  "browser.snapshot",
  "browser.start",
  "browser.status",
  "browser.stop",
  "browser.type",
  "continuity.get",
  "continuity.update",
  "handoff.create",
  "handoff.get",
  "process.list",
  "process.logs",
  "process.start",
  "process.status",
  "process.stop",
  "process.write_stdin",
  "terminal.exec",
  "workspace.project_snapshot",
];

test("Project binding capability ceiling exactly matches canonical project grant profiles", () => {
  const canonical = [...new Set(
    Object.values(OWNER_MCP_GRANT_PROFILES)
      .filter(profile => profile.scope === "project")
      .flatMap(profile => profile.capabilities.map(item => item.capability)),
  )].sort();
  assert.deepEqual(canonical, EXPECTED_PROJECT_CAPABILITIES);

  const match = migration.match(
    /v_allowed_capabilities text\[\] := array\[([\s\S]*?)\]::text\[\];/,
  );
  assert.ok(match, "migration capability ceiling missing");
  const sqlCapabilities = [...match[1].matchAll(/'([^']+)'/g)].map(item => item[1]).sort();
  assert.deepEqual(sqlCapabilities, canonical,
    "binding ceiling must not add or omit a canonical Project capability");

  assert.doesNotMatch(migration, /insert\s+into\s+public\.ordax_remote_capability_grants/i,
    "binding must never mint Product grants");
  assert.match(migration, /p_local_project_ref !~ '\^project-\[1-9\]\[0-9\]\*\$'/);
  assert.doesNotMatch(migration, /local_project_path|filesystem_path|workspace_path/i);
});

test("Owner request plus enrolled Device confirmation creates exactly one canonical binding and no grant", async () => {
  const db = new PGlite();
  const owner = randomUUID(), other = randomUUID();
  const device = randomUUID(), otherDevice = randomUUID();
  const space = randomUUID(), project = randomUUID(), project2 = randomUUID();
  const connection = randomUUID(), connection2 = randomUUID();
  const intent1 = randomUUID(), intent2 = randomUUID(), intent3 = randomUUID();
  const repositoryId = "123456789";
  const expectedExpiry = new Date(Date.now() + 4 * 60 * 1000).toISOString();

  const createIntent = async (
    intentId: string,
    projectId = project,
    deviceId = device,
    userId = owner,
  ) => (await db.query(
    "select public.ordax_owner_create_project_device_binding_intent_v1($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::timestamptz) as result",
    [userId, projectId, deviceId, intentId, expectedExpiry],
  )).rows[0].result as any;

  const readIntents = async (deviceId = device) => (await db.query(
    "select public.ordax_device_read_project_binding_intents_v1($1::uuid) as result",
    [deviceId],
  )).rows[0].result as any;

  const confirm = async (
    intentId: string,
    localProjectRef: string,
    deviceId = device,
  ) => (await db.query(
    "select public.ordax_device_confirm_project_binding_v1($1::uuid,$2::uuid,$3::text) as result",
    [deviceId, intentId, localProjectRef],
  )).rows[0].result as any;

  try {
    await db.exec(`
      create schema private;
      create schema auth;
      create role anon;
      create role authenticated;
      create role service_role;
      create role ordax_edge_executor;
      create role ordax_edge_runtime;
      create role ordax_space_executor;
      create role ordax_project_executor;
      create role ordax_owner_project_onboarding_executor;
      grant usage on schema public to ordax_edge_runtime, ordax_owner_project_onboarding_executor;

      create table auth.users(id uuid primary key);
      create table public.ordax_spaces(
        space_id uuid primary key,
        owner_user_id uuid not null references auth.users(id),
        state text not null
      );
      create table public.ordax_projects(
        project_id uuid primary key,
        space_id uuid not null references public.ordax_spaces(space_id),
        state text not null,
        unique(project_id,space_id)
      );
      create table public.ordax_product_devices(
        device_id uuid primary key,
        owner_user_id uuid not null references auth.users(id),
        state text not null
      );
      create table public.ordax_project_connections(
        connection_id uuid primary key,
        space_id uuid not null,
        owner_user_id uuid not null,
        provider text not null,
        repository_id bigint,
        repository_full_name text,
        state text not null,
        project_id uuid not null
      );
      create table public.ordax_space_devices(
        space_id uuid not null,
        device_id uuid not null,
        access_mode text not null default 'observe',
        state text not null default 'active',
        granted_by_user_id uuid not null,
        created_at timestamptz not null default clock_timestamp(),
        updated_at timestamptz not null default clock_timestamp(),
        primary key(space_id,device_id)
      );
      create table public.ordax_device_project_bindings(
        binding_id uuid primary key default gen_random_uuid(),
        project_id uuid not null,
        device_id uuid not null,
        local_project_ref text not null,
        state text not null default 'active',
        allowed_capabilities text[] not null default '{}'::text[],
        created_at timestamptz not null default clock_timestamp(),
        updated_at timestamptz not null default clock_timestamp(),
        unique(project_id,device_id,local_project_ref)
      );
      create table public.ordax_remote_capability_grants(
        grant_id uuid primary key default gen_random_uuid()
      );

      create function private.ordax_trusted_actor_auth_eligible_v1(p_user_id uuid)
      returns boolean language sql stable security definer set search_path=''
      as $$ select exists(select 1 from auth.users u where u.id=p_user_id) $$;

      create function private.ordax_subject_can_admin_space_v1(
        p_user_id uuid, p_space_id uuid
      ) returns boolean language sql stable security definer set search_path=''
      as $$ select exists(
        select 1 from public.ordax_spaces s
        where s.space_id=p_space_id and s.owner_user_id=p_user_id and s.state='active'
      ) $$;
    `);

    await db.exec(migration);

    await db.query("insert into auth.users(id) values($1),($2)", [owner, other]);
    await db.query(
      "insert into public.ordax_spaces(space_id,owner_user_id,state) values($1,$2,'active')",
      [space, owner],
    );
    await db.query(
      "insert into public.ordax_projects(project_id,space_id,state) values($1,$3,'active'),($2,$3,'active')",
      [project, project2, space],
    );
    await db.query(
      "insert into public.ordax_product_devices(device_id,owner_user_id,state) values($1,$3,'active'),($2,$4,'active')",
      [device, otherDevice, owner, other],
    );
    await db.query(
      `insert into public.ordax_project_connections(
        connection_id,space_id,owner_user_id,provider,repository_id,repository_full_name,state,project_id
      ) values
        ($1,$3,$4,'github',$5,'OrdaXSystems/OrdaX-Platform','active',$6),
        ($2,$3,$4,'github',$7,'ordaxsystems/second-project','active',$8)`,
      [connection, connection2, space, owner, repositoryId, project, "223456789", project2],
    );

    assert.equal((await createIntent(intent1, project, device, other)).error, "device_not_owned");
    assert.equal((await createIntent(intent1, project, otherDevice, owner)).error, "device_not_owned");

    const created = await createIntent(intent1);
    assert.equal(created.ok, true);
    assert.equal(created.intent_id, intent1);
    assert.equal(created.project_id, project);
    assert.equal(created.device_id, device);
    assert.equal(created.next_state, "awaiting_device_confirmation");
    assert.equal(created.repository_id, undefined);
    assert.equal(created.connection_id, undefined);

    const pending = await readIntents();
    assert.equal(pending.ok, true);
    assert.equal(pending.intents.length, 1);
    assert.deepEqual(
      Object.keys(pending.intents[0]).sort(),
      ["expires_at","intent_id","project_id","repository_full_name","space_id"],
    );
    assert.equal(pending.intents[0].repository_full_name, "ordaxsystems/ordax-platform");
    assert.equal((await readIntents(otherDevice)).intents.length, 0);

    assert.equal((await confirm(intent1, "../project")).error,
      "project_device_binding_confirmation_invalid");
    assert.equal((await confirm(intent1, "project-1", otherDevice)).error,
      "project_device_binding_intent_not_active");

    await db.query(
      "update public.ordax_project_connections set repository_full_name='ordaxsystems/changed' where connection_id=$1",
      [connection],
    );
    assert.equal((await confirm(intent1, "project-1")).error, "github_repository_changed");
    await db.query(
      "update public.ordax_project_connections set repository_full_name='OrdaXSystems/OrdaX-Platform' where connection_id=$1",
      [connection],
    );

    const bound = await confirm(intent1, "project-1");
    assert.equal(bound.ok, true);
    assert.equal(bound.project_id, project);
    assert.equal(bound.device_id, device);
    assert.equal(bound.next_state, "ready_without_grants");

    const spaceDevice = (await db.query(
      "select access_mode,state,granted_by_user_id from public.ordax_space_devices where space_id=$1 and device_id=$2",
      [space,device],
    )).rows[0] as any;
    assert.deepEqual(spaceDevice, {
      access_mode: "execute", state: "active", granted_by_user_id: owner,
    });

    const binding = (await db.query(
      "select binding_id,local_project_ref,state,allowed_capabilities from public.ordax_device_project_bindings where project_id=$1 and device_id=$2",
      [project,device],
    )).rows[0] as any;
    assert.equal(binding.binding_id, bound.binding_id);
    assert.equal(binding.local_project_ref, "project-1");
    assert.equal(binding.state, "active");
    assert.deepEqual([...binding.allowed_capabilities].sort(), EXPECTED_PROJECT_CAPABILITIES);
    assert.equal((await db.query(
      "select count(*)::int as total from public.ordax_remote_capability_grants",
    )).rows[0].total, 0, "binding creates no Product grant");

    assert.equal((await confirm(intent1, "project-1")).error,
      "project_device_binding_intent_not_active");
    assert.equal((await createIntent(randomUUID())).error, "project_device_already_bound");
    await assert.rejects(() => db.query(
      `insert into public.ordax_device_project_bindings(
        project_id,device_id,local_project_ref,state,allowed_capabilities
      ) values($1,$2,'project-99','active','{}'::text[])`,
      [project,device],
    ), "partial unique index prevents an ambiguous second active binding");

    const firstSecond = await createIntent(intent2, project2);
    assert.equal(firstSecond.ok, true);
    const superseding = await createIntent(intent3, project2);
    assert.equal(superseding.ok, true);
    assert.equal((await confirm(intent2, "project-2")).error,
      "project_device_binding_intent_not_active",
      "superseded intent cannot bind later");
    const pendingSecond = await readIntents();
    assert.equal(pendingSecond.intents.filter((x:any) => x.project_id === project2).length, 1);
    assert.equal(pendingSecond.intents.find((x:any) => x.project_id === project2)?.intent_id, intent3);

    const signatures = [
      "public.ordax_owner_create_project_device_binding_intent_v1(uuid,uuid,uuid,uuid,timestamp with time zone)",
      "public.ordax_device_read_project_binding_intents_v1(uuid)",
      "public.ordax_device_confirm_project_binding_v1(uuid,uuid,text)",
    ];
    for (const sig of signatures) {
      for (const role of ["anon","authenticated","service_role","ordax_edge_executor"]) {
        const allowed = (await db.query(
          "select has_function_privilege($1,$2,'EXECUTE') as allowed",
          [role,sig],
        )).rows[0].allowed;
        assert.equal(allowed, false, role + " " + sig);
      }
    }
    assert.equal((await db.query(
      "select has_function_privilege('ordax_owner_project_onboarding_executor',$1,'EXECUTE') as allowed",
      [signatures[0]],
    )).rows[0].allowed, true);
    assert.equal((await db.query(
      "select has_function_privilege('ordax_edge_runtime',$1,'EXECUTE') as allowed",
      [signatures[1]],
    )).rows[0].allowed, true);
    assert.equal((await db.query(
      "select has_function_privilege('ordax_edge_runtime',$1,'EXECUTE') as allowed",
      [signatures[2]],
    )).rows[0].allowed, true);

    for (const role of [
      "anon","authenticated","service_role",
      "ordax_owner_project_onboarding_executor","ordax_edge_runtime",
    ]) {
      for (const privilege of ["SELECT","INSERT","UPDATE","DELETE"]) {
        const allowed = (await db.query(
          "select has_table_privilege($1,'private.ordax_owner_project_device_binding_intents',$2) as allowed",
          [role,privilege],
        )).rows[0].allowed;
        assert.equal(allowed, false, role + " direct " + privilege);
      }
    }
  } finally {
    await db.close();
  }
});
