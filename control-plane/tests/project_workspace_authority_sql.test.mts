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
// This candidate is intentionally NOT in canonical migrations or its applied registry.
const proposal = () => fs.readFileSync(new URL(
  "../supabase/proposals/project_workspace_resource_authority_v1.sql",
  import.meta.url,
), "utf8");

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
    await db.exec(proposal());
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

    // Owner + Device two-phase issuance: no SQL path, JWT, or second ledger.
    const approve = async (values:unknown[]) => (await db.query(
      "select public.ordax_approve_project_workspace_resource_v1($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) as approved",
      values)).rows[0].approved as boolean;
    const commit = async (values:unknown[]) => (await db.query(
      "select public.ordax_commit_project_workspace_resource_v1($1,$2,$3,$4,$5,$6) as committed",
      values)).rows[0].committed as boolean;
    const candidate="resource_"+randomUUID().replaceAll("-","");
    const intent=randomUUID();
    const ownerDecision=[owner,client,"lab_one",space,project,device,actor,
                         "session_one",candidate,intent];
    const deviceCommit=[device,intent,actor,client,"session_one",candidate];
    assert.equal(await approve([other,...ownerDecision.slice(1)]),false,"Owner mismatch");
    assert.equal(await approve([owner,other,...ownerDecision.slice(2)]),false,"OAuth client mismatch");
    assert.equal(await approve([owner,client,"lab_one",space,other,...ownerDecision.slice(5)]),
                 false,"Product project mismatch");
    assert.equal(await approve([owner,client,"lab_one",space,project,other,
                               ...ownerDecision.slice(6)]),false,"foreign Device");
    assert.equal(await approve(ownerDecision),true,"authenticated Owner approves pending");
    assert.equal(await approve(ownerDecision),false,"approval cannot replay");
    assert.equal((await verify([owner,actor,client,"session_one","lab_one",device,candidate])).ok,
                 false,"pending intent grants no read");

    for(let i=0;i<deviceCommit.length;i++){
      const mutated=[...deviceCommit];
      mutated[i]=(i===4?"other_session":i===5?"resource_"+randomUUID().replaceAll("-",""):other);
      assert.equal(await commit(mutated),false,"Device confirmation mismatch "+i);
    }
    assert.equal(await commit(deviceCommit),true,"Device commits only exact approved selection");
    assert.equal(await commit(deviceCommit),false,"Device replay denied");
    const activeCandidate=await verify([owner,actor,client,"session_one","lab_one",device,candidate]);
    assert.equal(activeCandidate.ok,true,"two-party issuance readable only after commit");
    assert.equal(activeCandidate.grant.grant_id,grant,"parent ledger reused");
    assert.ok(Date.parse(activeCandidate.grant.valid_until)-Date.now()<61*60*1000,
              "new resource lifetime at most one hour");
    assert.equal(await (async()=> (await db.query(
      "select count(*)::int as total from public.ordax_remote_capability_grants"
    )).rows[0].total)(),1,"issuance does not mint parent grants");

    const ownerCancelResource="resource_"+randomUUID().replaceAll("-","");
    const cancelIntent=randomUUID();
    const cancelledDecision=[owner,client,"lab_one",space,project,device,actor,
                             "session_one",ownerCancelResource,cancelIntent];
    assert.equal(await approve(cancelledDecision),true);
    const ownerRevoke=async (values:unknown[]) => (await db.query(
      "select public.ordax_revoke_project_workspace_resource_v1($1,$2,$3) as revoked",
      values)).rows[0].revoked as boolean;
    assert.equal(await ownerRevoke([other,client,ownerCancelResource]),false);
    assert.equal(await ownerRevoke([owner,other,ownerCancelResource]),false);
    assert.equal(await ownerRevoke([owner,client,ownerCancelResource]),true,
                 "Owner cancels pending intent before Device confirmation");
    assert.equal(await ownerRevoke([owner,client,ownerCancelResource]),false,
                 "pending revocation idempotent");
    assert.equal(await commit([device,cancelIntent,actor,client,"session_one",ownerCancelResource]),
                 false,"cancelled intent cannot create resource");

    const expiredResource="resource_"+randomUUID().replaceAll("-","");
    const expiredIntent=randomUUID();
    assert.equal(await approve([owner,client,"lab_one",space,project,device,actor,
                                "session_one",expiredResource,expiredIntent]),true);
    await db.query("update private.ordax_workspace_owner_intents set expires_at=now()-interval '1 second', approved_at=now()-interval '6 minutes' where intent_id=$1",[expiredIntent]);
    assert.equal(await commit([device,expiredIntent,actor,client,"session_one",expiredResource]),
                 false,"expired Owner approval cannot commit");

    const revokeDuringResource="resource_"+randomUUID().replaceAll("-","");
    const revokeDuringIntent=randomUUID();
    assert.equal(await approve([owner,client,"lab_one",space,project,device,actor,
                                "session_one",revokeDuringResource,revokeDuringIntent]),true);
    await db.exec("update auth.oauth_consents set revoked_at=now()");
    assert.equal(await commit([device,revokeDuringIntent,actor,client,"session_one",revokeDuringResource]),
                 false,"OAuth consent revoked before Device confirmation");
    await db.exec("update auth.oauth_consents set revoked_at=null");
    assert.equal(await ownerRevoke([owner,client,candidate]),true,
                 "issued resource can also be revoked by Owner");
    assert.equal((await verify([owner,actor,client,"session_one","lab_one",device,candidate])).ok,
                 false,"previously issued resource remains revoked");

    for(const fn of [
      "public.ordax_approve_project_workspace_resource_v1(uuid,uuid,text,uuid,uuid,uuid,uuid,text,text,uuid)",
      "public.ordax_commit_project_workspace_resource_v1(uuid,uuid,uuid,uuid,text,text)"
    ]){
      for(const role of ["anon","authenticated","service_role","ordax_edge_executor"]){
        const x=await db.query("select has_function_privilege($1,$2,'EXECUTE') as permitted",[role,fn]);
        assert.equal(x.rows[0].permitted,false,"no public issuance function "+role);
      }
      const edge=await db.query("select has_function_privilege('ordax_edge_runtime',$1,'EXECUTE') as permitted",[fn]);
      assert.equal(edge.rows[0].permitted,true,"only canonic Edge role may invoke gated RPC");
    }
    const internalFn="private.ordax_eligible_workspace_parent_grant_v1(uuid,uuid,uuid,uuid,uuid)";
    const exec=await db.query("select has_function_privilege('ordax_edge_runtime',$1,'EXECUTE') as permitted",[internalFn]);
    assert.equal(exec.rows[0].permitted,false,"internal issuer helper not exposed to Edge");
    for(const role of ["anon","authenticated","service_role","ordax_edge_executor","ordax_edge_runtime"]){
      const x=await db.query("select has_table_privilege($1,'private.ordax_workspace_owner_intents','INSERT') as permitted",[role]);
      assert.equal(x.rows[0].permitted,false,"no direct pending intent writes "+role);
    }

    const revokeSig="public.ordax_revoke_project_workspace_resource_v1(uuid,uuid,text)";
    for(const role of ["anon","authenticated","service_role","ordax_edge_executor"]){
      const x=await db.query("select has_function_privilege($1,$2,'EXECUTE') as permitted",
        [role,revokeSig]);
      assert.equal(x.rows[0].permitted,false,"revoke privilege "+role);
    }
    const edgeAccess=await db.query(
      "select has_function_privilege('ordax_edge_runtime',$1,'EXECUTE') as permitted",[revokeSig]);
    assert.equal(edgeAccess.rows[0].permitted,true);

    const revoke = async (values:[string,string,string]) => (await db.query(
      "select public.ordax_revoke_project_workspace_resource_v1($1,$2,$3) as revoked",
      values)).rows[0].revoked;
    assert.equal(await revoke([other,client,resource]),false,"other Owner denied");
    assert.equal(await revoke([owner,other,resource]),false,"other OAuth client denied");
    assert.equal(await revoke([owner,client,"resource_"+randomUUID().replaceAll("-","")]),
      false,"other resource denied");
    assert.equal(await revoke([owner,client,"invalid/path"]),false,"untrusted path denied");
    assert.equal((await verify()).ok,true,"other Owner attempts leave grant valid");

    // Revocation remains possible AFTER a user withdraws OAuth consent:
    // cancellation must never depend on an active permission to read.
    await db.exec("update auth.oauth_consents set revoked_at=now()");
    await db.exec("set role ordax_edge_runtime");
    assert.equal(await revoke([owner,client,resource]),true,"Owner revokes its resource");
    assert.equal(await revoke([owner,client,resource]),false,"revocation is idempotent");
    await db.exec("reset role");
    await db.exec("update auth.oauth_consents set revoked_at=null");
    assert.equal((await verify()).ok,false,"reference stays revoked after consent returns");
    const stored=await db.query("select revoked_at from private.ordax_workspace_resource_bindings where resource_id=$1",[resource]);
    assert.ok(stored.rows[0].revoked_at,"revocation persisted once");
    const ledger=await db.query("select state from public.ordax_remote_capability_grants where grant_id=$1",[grant]);
    assert.equal(ledger.rows[0].state,"active","parent grant ledger must remain untouched");
  } finally { await db.close(); }
});

test("New schema requires two-party issuance using preexisting grant ledger only",()=>{
  const sql=proposal().toLowerCase().replace(/\s+/g," ");
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
    "ordax_revoke_project_workspace_resource_v1",
    "ordax_approve_project_workspace_resource_v1",
    "ordax_commit_project_workspace_resource_v1",
    "ordax_workspace_owner_intents",
    "a.owner_user_id=p_owner_user_id",
    "a.client_id=p_client_id",
    "r.revoked_at is null",
    "to ordax_edge_runtime"
  ])assert.ok(sql.includes(required),required);
  for(const forbidden of ["create function public.ordax_issue_","grant insert on","grant update on",
    "grant delete on","create policy"]){
    assert.equal(sql.includes(forbidden),false,forbidden);
  }
});
