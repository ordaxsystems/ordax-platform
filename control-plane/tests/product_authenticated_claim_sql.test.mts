import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import {createRequire} from "node:module";

const require=createRequire(new URL("../cloudflare/package.json",import.meta.url));
const {PGlite}=require("@electric-sql/pglite");
const migration=fs.readFileSync(new URL(
  "../supabase/migrations/20261121031500_product_authenticated_claim_v1.sql",import.meta.url,
),"utf8");

const DEVICE="11111111-1111-4111-8111-111111111111";
const UNKNOWN="99999999-9999-4999-8999-999999999999";
const AGENT="22222222-2222-4222-8222-222222222222";
const REQUEST="33333333-3333-4333-8333-333333333333";
const TOKEN="a".repeat(64);

test("one SQL call authenticates enrolled Device before any capacity or lease mutation",async()=>{
  const db=new PGlite();
  try{
    await db.exec(`
      create role anon;
      create role authenticated;
      create role service_role;
      create role ordax_edge_executor;
      create table public.test_device_claim(
        device_id uuid primary key,token_sha256 text not null,
        active boolean not null default true,revoked boolean not null default false
      );
      create table public.test_claim_job(
        request_id uuid primary key,device_id uuid not null,status text not null,
        attempt integer not null default 0
      );
      create function public.ordax_authenticate_product_device_v1(
        p_device_id uuid,p_token_sha256 text
      ) returns boolean language sql stable as $stub$
        select exists(select 1 from public.test_device_claim
         where device_id=p_device_id and token_sha256=p_token_sha256
           and active=true and revoked=false);
      $stub$;
      create function public.ordax_claim_product_action_v1(
        p_device_id uuid,p_agent_instance_id uuid,p_boot_id text,
        p_lease_seconds integer default 120
      ) returns jsonb language plpgsql as $stub$
      declare v_request uuid;
      begin
        if p_device_id is null or p_agent_instance_id is null
          or p_boot_id is null or length(p_boot_id) not between 8 and 160
          or p_lease_seconds not between 30 and 300 then
          return jsonb_build_object('ok',false,'error','claim_invalid');
        end if;
        update public.test_claim_job set status='leased', attempt=attempt+1
          where request_id=(select request_id from public.test_claim_job
             where device_id=p_device_id and status='queued' order by request_id limit 1)
          returning request_id into v_request;
        return jsonb_build_object('ok',true,'job',
          case when v_request is null then null
             else jsonb_build_object('request_id',v_request) end);
      end;
      $stub$;
    `);
    await db.exec(migration);
    await db.query("insert into public.test_device_claim(device_id,token_sha256) values($1,$2)",[DEVICE,TOKEN]);
    await db.query("insert into public.test_claim_job(request_id,device_id,status) values($1,$2,'queued')",[REQUEST,DEVICE]);
    const submit=async(device:string|null,token:string|null,lease=120,agent:string|null=AGENT)=>
      (await db.query("select public.ordax_authenticated_claim_product_action_v1("+
        "$1::uuid,$2::text,$3::uuid,$4::text,$5::integer) as result",
        [device,token,agent,"boot-valid-identity",lease],
      )).rows[0].result;
    const row=async()=>(await db.query(
      "select status,attempt from public.test_claim_job where request_id=$1",[REQUEST],
    )).rows[0];

    for(const [device,token] of [
      [UNKNOWN,TOKEN],[DEVICE,"b".repeat(64)],[DEVICE,"not-a-hash"],
      [DEVICE,null],[null,TOKEN],
    ] as Array<[string|null,string|null]>){
      assert.deepEqual(await submit(device,token),{ok:false,error:"invalid_device_token"});
      assert.deepEqual(await row(),{status:"queued",attempt:0});
    }
    await db.query("update public.test_device_claim set revoked=true where device_id=$1",[DEVICE]);
    assert.deepEqual(await submit(DEVICE,TOKEN),{ok:false,error:"invalid_device_token"});
    assert.deepEqual(await row(),{status:"queued",attempt:0});
    await db.query("update public.test_device_claim set revoked=false,active=false where device_id=$1",[DEVICE]);
    assert.deepEqual(await submit(DEVICE,TOKEN),{ok:false,error:"invalid_device_token"});
    assert.deepEqual(await row(),{status:"queued",attempt:0});
    await db.query("update public.test_device_claim set active=true where device_id=$1",[DEVICE]);
    assert.deepEqual(await submit(DEVICE,TOKEN,0),{ok:false,error:"claim_invalid"});
    assert.deepEqual(await submit(DEVICE,TOKEN,120,null),{ok:false,error:"claim_invalid"});
    assert.deepEqual(await row(),{status:"queued",attempt:0});
    assert.deepEqual(await submit(DEVICE,TOKEN),{
      ok:true,job:{request_id:REQUEST},
    });
    assert.deepEqual(await row(),{status:"leased",attempt:1});
    assert.deepEqual(await submit(DEVICE,TOKEN),{ok:true,job:null},
      "no work after lease; never create a second attempt");

    const p=await db.query(
      "select has_function_privilege('anon',$1,'EXECUTE') anon_exec,"+
      "has_function_privilege('authenticated',$1,'EXECUTE') auth_exec,"+
      "has_function_privilege('service_role',$1,'EXECUTE') service_exec,"+
      "has_function_privilege('ordax_edge_executor',$1,'EXECUTE') edge_exec",
      ["public.ordax_authenticated_claim_product_action_v1(uuid,text,uuid,text,integer)"],
    );
    assert.deepEqual(p.rows[0],{
      anon_exec:false,auth_exec:false,service_exec:false,edge_exec:true,
    });
  } finally {await db.close();}
});
