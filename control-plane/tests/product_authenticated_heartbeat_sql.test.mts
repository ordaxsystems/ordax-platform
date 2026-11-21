import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import {createRequire} from "node:module";

const require=createRequire(new URL("../cloudflare/package.json",import.meta.url));
const {PGlite}=require("@electric-sql/pglite");
const atomicMigration=fs.readFileSync(new URL(
  "../supabase/migrations/20261121002500_product_atomic_heartbeat_v1.sql",import.meta.url,
),"utf8");
const authenticatedMigration=fs.readFileSync(new URL(
  "../supabase/migrations/20261121034000_product_authenticated_heartbeat_v1.sql",import.meta.url,
),"utf8");

const DEVICE="11111111-1111-4111-8111-111111111111";
const OTHER="99999999-9999-4999-8999-999999999999";
const TOKEN="a".repeat(64);

test("authenticated heartbeat rejects revoked credentials before any presence or capacity mutation",async()=>{
  const db=new PGlite();
  try{
    await db.exec(`
      create role anon;
      create role authenticated;
      create role service_role;
      create role ordax_edge_executor;
      create table public.test_device_heartbeat(
        device_id uuid primary key, token_sha256 text not null,
        active boolean not null default true,
        revoked boolean not null default false,
        online boolean not null default false,
        capacity integer not null default 4,
        presence_writes integer not null default 0,
        capacity_writes integer not null default 0
      );
      create function public.ordax_authenticate_product_device_v1(
        p_device_id uuid,p_token_sha256 text
      ) returns boolean language sql stable as $stub$
        select exists(select 1 from public.test_device_heartbeat
          where device_id=p_device_id and token_sha256=p_token_sha256
            and active=true and revoked=false);
      $stub$;
      create function public.ordax_record_product_presence_v1(
        p_device_id uuid,p_online boolean,p_runtime_kind text,
        p_agent_version text,p_capability_digest text,p_force boolean
      ) returns boolean language plpgsql as $stub$
      begin
        update public.test_device_heartbeat set online=p_online,
          presence_writes=presence_writes+1 where device_id=p_device_id;
        return found;
      end;
      $stub$;
      create function public.ordax_record_product_capacity_v1(
        p_device_id uuid,p_max_concurrent_jobs integer
      ) returns boolean language plpgsql as $stub$
      begin
        if p_max_concurrent_jobs=13 then return false; end if;
        update public.test_device_heartbeat set capacity=p_max_concurrent_jobs,
          capacity_writes=capacity_writes+1 where device_id=p_device_id and online=true;
        return found;
      end;
      $stub$;
    `);
    await db.exec(atomicMigration);
    await db.exec(authenticatedMigration);
    await db.query("insert into public.test_device_heartbeat(device_id,token_sha256) values($1,$2)",
      [DEVICE,TOKEN]);
    const send=async(device:string|null,token:string|null,online=true,capacity=8,force=false)=>
      (await db.query("select public.ordax_authenticated_product_heartbeat_v1("+
        "$1::uuid,$2::text,$3::boolean,$4::text,$5::text,"+
        "$6::text,$7::boolean,$8::integer) as result",
        [device,token,online,"desktop-agent","1.31.0","a".repeat(64),force,capacity],
      )).rows[0].result;
    const state=async()=>(await db.query(
      "select online,capacity,presence_writes,capacity_writes"+
        " from public.test_device_heartbeat where device_id=$1",[DEVICE],
    )).rows[0];
    const untouched={
      online:false,capacity:4,presence_writes:0,capacity_writes:0,
    };

    for(const [device,token] of [
      [OTHER,TOKEN],[DEVICE,"b".repeat(64)],[DEVICE,null],
      [null,TOKEN],[DEVICE,"unhashed"],
    ] as Array<[string|null,string|null]>){
      assert.deepEqual(await send(device,token),{ok:false,error:"invalid_device_token"});
      assert.deepEqual(await state(),untouched);
    }
    await db.query("update public.test_device_heartbeat set revoked=true where device_id=$1",[DEVICE]);
    assert.deepEqual(await send(DEVICE,TOKEN),{ok:false,error:"invalid_device_token"});
    assert.deepEqual(await state(),untouched);
    await db.query("update public.test_device_heartbeat set revoked=false,active=false where device_id=$1",[DEVICE]);
    assert.deepEqual(await send(DEVICE,TOKEN),{ok:false,error:"invalid_device_token"});
    assert.deepEqual(await state(),untouched);

    await db.query("update public.test_device_heartbeat set active=true where device_id=$1",[DEVICE]);
    assert.deepEqual(await send(DEVICE,TOKEN,true,13),{
      ok:false,error:"product_capacity_unavailable",
    });
    assert.deepEqual(await state(),untouched,
      "failed capacity must roll back canonical presence write");
    assert.deepEqual(await send(DEVICE,TOKEN,true,8),{ok:true,recorded:true});
    assert.deepEqual(await state(),{
      online:true,capacity:8,presence_writes:1,capacity_writes:1,
    });
    assert.deepEqual(await send(DEVICE,TOKEN,false,32,true),{ok:true,recorded:true});
    assert.deepEqual(await state(),{
      online:false,capacity:8,presence_writes:2,capacity_writes:1,
    },"forced offline must not write capacity");
    assert.deepEqual(await send(DEVICE,TOKEN,true,0),{
      ok:false,error:"product_capacity_unavailable",
    },"canonical lower authority still rejects invalid capacity");
    assert.deepEqual(await state(),{
      online:false,capacity:8,presence_writes:2,capacity_writes:1,
    });

    const p=await db.query(
      "select has_function_privilege('anon',$1,'EXECUTE') anon_exec,"+
      "has_function_privilege('authenticated',$1,'EXECUTE') auth_exec,"+
      "has_function_privilege('service_role',$1,'EXECUTE') service_exec,"+
      "has_function_privilege('ordax_edge_executor',$1,'EXECUTE') edge_exec",
      ["public.ordax_authenticated_product_heartbeat_v1("+
        "uuid,text,boolean,text,text,text,boolean,integer)"],
    );
    assert.deepEqual(p.rows[0],{
      anon_exec:false,auth_exec:false,service_exec:false,edge_exec:true,
    });
  } finally {await db.close();}
});
