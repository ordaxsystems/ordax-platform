import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { projectWorkspaceGrantProjection } from "../cloudflare/src/project_workspace_grant_contract.ts";

const require = createRequire(new URL("../cloudflare/package.json", import.meta.url));
const { PGlite } = require("@electric-sql/pglite");
const base = new URL("../supabase/migrations/", import.meta.url);
const read = (name: string) => fs.readFileSync(new URL(name, base), "utf8");
const migration = "20261022060000_project_workspace_resource_authority_v1.sql";

test("Workspace verifier binds live Product scope and revocation without a new grant authority", async () => {
  const db = new PGlite();
  const [owner, actor, client, device, space, project, binding, grant, other] =
    Array.from({ length: 9 }, () => randomUUID());
  const resource = "resource_" + randomUUID().replaceAll("-", "");
  const args = [owner, actor, client, "session_one", "lab_one", device, resource];
  const verify = async (values=args) => (await db.query(
    "select public.ordax_verify_project_workspace_resource_v1($1,$2,$3,$4,$5,$6,$7) as result",
    values
  )).rows[0].result;
  try {
    await db.exec("create schema private;create schema auth;" +
      "create role anon;create role authenticated;create role service_role;" +
      "create role ordax_edge_executor;create role ordax_edge_runtime;");
    await db.exec([
      "create table auth.users(id uuid primary key,deleted_at timestamptz,is_anonymous boolean default false,confirmed_at timestamptz default now(),banned_until timestamptz);",
      "create table auth.oauth_clients(id uuid primary key,deleted_at timestamptz);",
      "create table auth.oauth_consents(user_id uuid,client_id uuid,revoked_at timestamptz);",
      "create table public.ordax_accounts(user_id uuid primary key);",
      "create table public.ordax_spaces(space_id uuid primary key,owner_user_id uuid,state text);",
      "create table public.ordax_space_members(space_id uuid,user_id uuid,state text,role text);",
      "create table public.ordax_projects(project_id uuid primary key,space_id uuid,state text,unique(project_id,space_id));",
      "create table public.ordax_product_devices(device_id uuid primary key,owner_user_id uuid,state text);",
      "create table public.ordax_space_devices(space_id uuid,device_id uuid,state text,access_mode text);",
      "create table public.ordax_device_project_bindings(project_id uuid,device_id uuid,state text,allowed_capabilities text[]);",
      "create table public.ordax_remote_capability_grants(grant_id uuid primary key,owner_user_id uuid,space_id uuid,project_id uuid,device_id uuid,client_kind text,client_id text,scope_kind text,profile_key text,capability text,access_mode text,approved_by_user_id uuid,state text,valid_until timestamptz);"
    ].join("\n"));
    const eligible = read("20261007212000_trusted_actor_auth_eligibility_v1.sql")
      .match(/create function private\.ordax_trusted_actor_auth_eligible_v1\([\s\S]*?\$function\$;/);
    assert.ok(eligible);
    await db.exec(eligible[0]);
    const subject = read("20261007192500_subject_authorization_ssot_v1.sql");
    for(const name of ["ordax_subject_can_access_space_v1","ordax_subject_can_admin_space_v1",
                       "ordax_subject_can_access_project_v1"]){
      const pattern = new RegExp("create function private\\." + name + "\\([\\s\\S]*?\\$function\\$;");
      const match = subject.match(pattern);
      assert.ok(match,name);
      await db.exec(match[0]);
    }
    await db.exec(read(migration));
    await db.query("insert into auth.users(id) values($1)",[owner]);
    await db.query("insert into public.ordax_accounts values($1)",[owner]);
    await db.query("insert into auth.oauth_clients(id) values($1)",[client]);
    await db.query("insert into auth.oauth_consents values($1,$2,null)",[owner,client]);
    await db.query("insert into public.ordax_spaces values($1,$2,'active')",[space,owner]);
    await db.query("insert into public.ordax_projects values($1,$2,'active')",[project,space]);
    await db.query("insert into public.ordax_product_devices values($1,$2,'active')",[device,owner]);
    await db.query("insert into public.ordax_space_devices values($1,$2,'active','execute')",[space,device]);
    await db.query("insert into public.ordax_device_project_bindings values($1,$2,'active',$3)",
      [project,device,["workspace.project_snapshot"]]);
    await db.query("insert into public.ordax_remote_capability_grants values($1,$2,$3,$4,$5,'product-mcp',$6,'project','project-workspace-read','workspace.project_snapshot','read',$2,'active',now()+interval '2 hours')",
      [grant,owner,space,project,device,client]);
    await db.query("insert into private.ordax_lab_project_authorities(binding_id,owner_user_id,client_id,lab_project_id,space_id,project_id) values($1,$2,$3,'lab_one',$4,$5)",
      [binding,owner,client,space,project]);
    await db.query("insert into private.ordax_workspace_resource_bindings(resource_id,lab_binding_id,grant_id,actor_id,workspace_session_id,device_id,issued_by,issued_at,expires_at) values($1,$2,$3,$4,'session_one',$5,'trusted-runtime-picker',now()-interval '1 minute',now()+interval '1 hour')",
      [resource,binding,grant,actor,device]);

    const valid = await verify();
    assert.equal(valid.ok,true);
    assert.equal(valid.schema,"ordax.project-workspace-resource/1");
    assert.equal(valid.grant.grant_id,grant);
    assert.equal(valid.grant.resource_id,resource);
    assert.equal(valid.grant.client_id,client);
    assert.deepEqual(valid.grant.allowed_actions,["read"]);
    const scope = {ownerUserId:owner,spaceId:space,projectId:project,labProjectId:"lab_one",
      actorId:actor,clientId:client,workspaceSessionId:"session_one",deviceId:device,resourceId:resource};
    assert.equal(projectWorkspaceGrantProjection(valid.grant,scope,Date.now())?.authorized,true);
    assert.ok(!JSON.stringify(valid).includes("C:\\"));
    assert.ok(!JSON.stringify(valid).includes("root"));

    for(let i=0;i<args.length;i++){
      const altered=[...args];
      altered[i]=i===3?"another_session":i===4?"another_lab":
        i===6?"resource_"+randomUUID().replaceAll("-",""):other;
      assert.equal((await verify(altered)).ok,false,"identity "+i);
    }

    const denials = [
      "update auth.oauth_consents set revoked_at=now()",
      "update auth.oauth_clients set deleted_at=now()",
      "update auth.users set banned_until=now()+interval '1 hour'",
      "update public.ordax_product_devices set state='revoked'",
      "update public.ordax_spaces set state='archived'",
      "update public.ordax_projects set state='archived'",
      "update public.ordax_space_devices set state='revoked'",
      "update public.ordax_space_devices set access_mode='observe'",
      "update public.ordax_device_project_bindings set state='revoked'",
      "update public.ordax_device_project_bindings set allowed_capabilities=array['other']",
      "update public.ordax_remote_capability_grants set state='revoked'",
      "update public.ordax_remote_capability_grants set profile_key='full-computer-control'",
      "update public.ordax_remote_capability_grants set scope_kind='device'",
      "update public.ordax_remote_capability_grants set capability='computer.text_read'",
      "update public.ordax_remote_capability_grants set access_mode='write'",
      "update public.ordax_remote_capability_grants set client_id='other-client'",
      "update public.ordax_remote_capability_grants set valid_until=now()+interval '30 minutes'",
      "update private.ordax_workspace_resource_bindings set revoked_at=now()",
      "update private.ordax_lab_project_authorities set revoked_at=now()",
    ];
    for(const statement of denials){
      await db.exec("begin");
      try{ await db.exec(statement); assert.equal((await verify()).ok,false,statement); }
      finally{ await db.exec("rollback"); }
    }

    const signature="public.ordax_verify_project_workspace_resource_v1(uuid,uuid,uuid,text,text,uuid,text)";
    for(const role of ["anon","authenticated","service_role","ordax_edge_executor"]){
      const result=await db.query("select has_function_privilege($1,$2,'EXECUTE') as permitted",
        [role,signature]);
      assert.equal(result.rows[0].permitted,false,role);
    }
    assert.equal((await db.query("select has_function_privilege('ordax_edge_runtime',$1,'EXECUTE') as permitted",
      [signature])).rows[0].permitted,true);
    for(const relation of ["private.ordax_lab_project_authorities",
                            "private.ordax_workspace_resource_bindings"]){
      for(const role of ["anon","authenticated","service_role","ordax_edge_executor","ordax_edge_runtime"]){
        const testAccess=await db.query("select has_table_privilege($1,$2,'INSERT') as permitted",
          [role,relation]);
        assert.equal(testAccess.rows[0].permitted,false,role+" "+relation);
      }
    }
    await db.exec("set role ordax_edge_runtime");
    assert.equal((await verify()).ok,true);
    await db.exec("reset role");
    await assert.rejects(() => db.query(
      "insert into private.ordax_lab_project_authorities(binding_id,owner_user_id,client_id,lab_project_id,space_id,project_id) values($1,$2,$3,'lab_one',$4,$5)",
      [randomUUID(),owner,client,space,project]));
  } finally { await db.close(); }
});

test("New schema has no issuance RPC, write grants or duplicate capability ledger",()=>{
  const sql=read(migration).toLowerCase();
  for(const required of [
    "references public.ordax_remote_capability_grants(grant_id)",
    "ordax_trusted_actor_auth_eligible_v1",
    "ordax_subject_can_admin_space_v1",
    "ordax_subject_can_access_project_v1",
    "oauth_consents",
    "g.profile_key='project-workspace-read'",
    "g.capability='workspace.project_snapshot'",
    "r.revoked_at is null",
    "g.state='active'",
    "force row level security",
    "to ordax_edge_runtime"
  ])assert.ok(sql.includes(required),required);
  for(const forbidden of ["create function public.ordax_issue_","grant insert on","grant update on",
    "grant delete on","create policy"]){
    assert.equal(sql.includes(forbidden),false,forbidden);
  }
});
