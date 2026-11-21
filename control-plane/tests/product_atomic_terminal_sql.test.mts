import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import {createRequire} from "node:module";

const require=createRequire(new URL("../cloudflare/package.json",import.meta.url));
const {PGlite}=require("@electric-sql/pglite");
const migration=fs.readFileSync(new URL(
  "../supabase/migrations/20261121001500_product_atomic_terminal_report_v1.sql",import.meta.url,
),"utf8");

const authenticatedMigration=fs.readFileSync(new URL(
  "../supabase/migrations/20261121070000_product_authenticated_report_v1.sql",import.meta.url,
),"utf8");
const TOKEN="b".repeat(64);
const DEVICE="11111111-1111-4111-8111-111111111111";
const REQUEST="22222222-2222-4222-8222-222222222222";
const SECOND="33333333-3333-4333-8333-333333333333";
const EFFECT="44444444-4444-4444-8444-444444444444";
const ATTEMPT="55555555-5555-4555-8555-555555555555";
const LEASE="66666666-6666-4666-8666-666666666666";
const AGENT="77777777-7777-4777-8777-777777777777";
const REPORT="88888888-8888-4888-8888-888888888888";
const OTHER_REPORT="99999999-9999-4999-8999-999999999999";

test("atomic receipt rollback, exact replay and least privilege",async()=>{
  const db=new PGlite();
  try{
    // Stub only the two existing fenced authorities. Execute the exact new
    // production migration against real PostgreSQL transaction semantics.
    await db.exec(`
      create role anon;
      create role authenticated;
      create role service_role;
      create role ordax_edge_executor;
      create table public.test_terminal_credentials(
        device_id uuid primary key, token_sha256 text not null, revoked boolean not null default false
      );
      create function public.ordax_authenticate_product_device_v1(p_device_id uuid,p_token_sha256 text)
      returns boolean language sql stable as $stub$
        select exists(select 1 from public.test_terminal_credentials
          where device_id=p_device_id and token_sha256=p_token_sha256 and not revoked);
      $stub$;
      create table public.test_terminal_actions(
        request_id uuid primary key, status text not null default 'leased',
        report_id uuid, result jsonb, runtime_kind text, agent_version text,
        audit_count integer not null default 0
      );
      create function public.ordax_report_product_action_v1(
        p_device_id uuid,p_request_id uuid,p_effect_id uuid,p_attempt_id uuid,
        p_lease_id uuid,p_execution_epoch bigint,p_agent_instance_id uuid,
        p_boot_id text,p_report_id uuid,p_status text,p_result jsonb,
        p_result_sha256 text,p_error_code text
      ) returns jsonb language plpgsql as $stub$
      declare v public.test_terminal_actions%rowtype;
      begin
        select * into v from public.test_terminal_actions where request_id=p_request_id for update;
        if not found then
          return jsonb_build_object('ok',false,'error','product_action_not_found');
        end if;
        if v.status in ('succeeded','failed','cancelled') then
          if v.report_id=p_report_id and v.result=p_result and v.status=p_status then
            return jsonb_build_object('ok',true,'replayed',true,'status',v.status);
          end if;
          return jsonb_build_object('ok',false,'error','terminal_report_conflict');
        end if;
        update public.test_terminal_actions
           set status=p_status,report_id=p_report_id,result=p_result,audit_count=audit_count+1
         where request_id=p_request_id;
        return jsonb_build_object('ok',true,'replayed',false,'status',p_status);
      end;
      $stub$;
      create function public.ordax_bind_product_action_runtime_provenance_v1(
        p_device_id uuid,p_request_id uuid,p_effect_id uuid,p_attempt_id uuid,
        p_lease_id uuid,p_execution_epoch bigint,p_agent_instance_id uuid,
        p_boot_id text,p_runtime_kind text,p_agent_version text
      ) returns boolean language plpgsql as $stub$
      declare v public.test_terminal_actions%rowtype;
      begin
        select * into v from public.test_terminal_actions where request_id=p_request_id for update;
        if not found or p_runtime_kind not in ('ordax-os','desktop-agent','mobile-client','other')
            or p_agent_version is null or length(p_agent_version) not between 1 and 80 then
          return false;
        end if;
        if v.runtime_kind is not null then
          return v.runtime_kind=p_runtime_kind and v.agent_version=p_agent_version;
        end if;
        update public.test_terminal_actions
          set runtime_kind=p_runtime_kind,agent_version=p_agent_version
          where request_id=p_request_id;
        return true;
      end;
      $stub$;
    `);
    await db.exec(migration);
    await db.exec(authenticatedMigration);
    await db.query("insert into public.test_terminal_credentials(device_id,token_sha256) values($1,$2)",[DEVICE,TOKEN]);
    await db.query(
      "insert into public.test_terminal_actions(request_id,runtime_kind,agent_version) values($1,$2,$3)",
      [REQUEST,"desktop-agent","0.4.7"]);
    const submit=async(requestId:string,reportId:string,kind:string|null,version:string|null,token:string|null=TOKEN)=>
      (await db.query(
        "select public.ordax_authenticated_report_product_action_v1("+
        "$1::uuid,$2::text,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7::bigint,"+
        "$8::uuid,$9::text,$10::uuid,$11::text,$12::jsonb,$13::text,"+
        "$14::text,$15::text,$16::text) as result",
        [DEVICE,token,requestId,EFFECT,ATTEMPT,LEASE,1,AGENT,"boot-example",
          reportId,"succeeded",JSON.stringify({ok:true}),"a".repeat(64),null,kind,version],
      )).rows[0].result;
    const read=async(requestId:string)=>(await db.query(
      "select * from public.test_terminal_actions where request_id=$1",[requestId],
    )).rows[0];
    for (const token of [null,"invalid","c".repeat(64)])
      assert.deepEqual(await submit(REQUEST,REPORT,"desktop-agent","0.4.7",token),
        {ok:false,error:"invalid_device_token"});
    assert.equal((await read(REQUEST)).audit_count,0);
    await db.query("update public.test_terminal_credentials set revoked=true where device_id=$1",[DEVICE]);
    assert.deepEqual(await submit(REQUEST,REPORT,"desktop-agent","0.4.7"),{ok:false,error:"invalid_device_token"});
    await db.query("update public.test_terminal_credentials set revoked=false where device_id=$1",[DEVICE]);
    const conflict=await submit(REQUEST,REPORT,"desktop-agent","0.4.8");
    assert.deepEqual(conflict,{ok:false,error:"runtime_provenance_conflict"});
    const before=await read(REQUEST);
    assert.equal(before.status,"leased");
    assert.equal(before.report_id,null);
    assert.equal(before.result,null);
    assert.equal(before.audit_count,0,"rejected provenance must roll back terminal audit");
    const accepted=await submit(REQUEST,REPORT,"desktop-agent","0.4.7");
    assert.equal(accepted.ok,true);
    assert.equal(accepted.replayed,false);
    const replay=await submit(REQUEST,REPORT,"desktop-agent","0.4.7");
    assert.equal(replay.ok,true);
    assert.equal(replay.replayed,true);
    assert.deepEqual(await submit(REQUEST,OTHER_REPORT,"desktop-agent","0.4.7"),
      {ok:false,error:"terminal_report_conflict"});
    assert.equal((await read(REQUEST)).audit_count,1);
    await db.query("insert into public.test_terminal_actions(request_id) values($1)",[SECOND]);
    assert.deepEqual(await submit(SECOND,REPORT,null,"0.4.8"),
      {ok:false,error:"runtime_provenance_conflict"});
    assert.equal((await read(SECOND)).status,"leased");
    assert.equal((await submit(SECOND,REPORT,null,null)).ok,true);
    const perms=await db.query(
      "select has_function_privilege('anon',$1,'EXECUTE') as anon_exec,"+
      "has_function_privilege('authenticated',$1,'EXECUTE') as auth_exec,"+
      "has_function_privilege('ordax_edge_executor',$1,'EXECUTE') as edge_exec",
      ["public.ordax_report_product_action_atomic_v1("+
        "uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid,text,jsonb,text,text,text,text)"]);
    assert.deepEqual(perms.rows[0],{anon_exec:false,auth_exec:false,edge_exec:true});
    const authPerms=await db.query(
      "select has_function_privilege('anon',$1,'EXECUTE') anon_exec,"+
      "has_function_privilege('authenticated',$1,'EXECUTE') auth_exec,"+
      "has_function_privilege('service_role',$1,'EXECUTE') service_exec,"+
      "has_function_privilege('ordax_edge_executor',$1,'EXECUTE') edge_exec",
      ["public.ordax_authenticated_report_product_action_v1("+
        "uuid,text,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid,text,jsonb,text,text,text,text)"]);
    assert.deepEqual(authPerms.rows[0],{anon_exec:false,auth_exec:false,service_exec:false,edge_exec:true});
    await db.query("update public.test_terminal_credentials set revoked=true where device_id=$1",[DEVICE]);
    assert.deepEqual(await submit(REQUEST,REPORT,"desktop-agent","0.4.7"),{ok:false,error:"invalid_device_token"});
    assert.equal((await read(REQUEST)).audit_count,1);
  } finally { await db.close(); }
});
