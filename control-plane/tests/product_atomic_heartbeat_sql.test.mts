import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import {createRequire} from "node:module";

const require=createRequire(new URL("../cloudflare/package.json",import.meta.url));
const {PGlite}=require("@electric-sql/pglite");
const migration=fs.readFileSync(new URL(
  "../supabase/migrations/20261121002500_product_atomic_heartbeat_v1.sql",import.meta.url,
),"utf8");

test("one heartbeat transaction commits presence plus capacity or rolls both back",async()=>{
  const db=new PGlite();
  try{
    await db.exec(`
      create role anon;
      create role authenticated;
      create role service_role;
      create role ordax_edge_executor;
      create table public.test_device_heartbeat(
        device_id uuid primary key, online boolean not null default false,
        capacity integer not null default 4,
        presence_writes integer not null default 0,
        capacity_writes integer not null default 0
      );
      create function public.ordax_record_product_presence_v1(
        p_device_id uuid,p_online boolean,p_runtime_kind text,
        p_agent_version text,p_capability_digest text,p_force boolean
      ) returns boolean language plpgsql as $stub$
      begin
        update public.test_device_heartbeat
           set online=p_online,presence_writes=presence_writes+1
         where device_id=p_device_id;
        return found;
      end;
      $stub$;
      create function public.ordax_record_product_capacity_v1(
        p_device_id uuid,p_max_concurrent_jobs integer
      ) returns boolean language plpgsql as $stub$
      begin
        -- A real capacity RPC may deny an update for a missing/offline device.
        if p_max_concurrent_jobs=13 then return false; end if;
        update public.test_device_heartbeat
           set capacity=p_max_concurrent_jobs,capacity_writes=capacity_writes+1
         where device_id=p_device_id and online=true;
        return found;
      end;
      $stub$;
    `);
    await db.exec(migration);
    const id="11111111-1111-4111-8111-111111111111";
    await db.query("insert into public.test_device_heartbeat(device_id) values($1)",[id]);
    const send=async(online:boolean,capacity:number,force=false)=>
      (await db.query("select public.ordax_record_product_heartbeat_v1("+
        "$1::uuid,$2::boolean,$3::text,$4::text,$5::text,$6::boolean,$7::integer) as result",
        [id,online,"desktop-agent","0.4.8","a".repeat(64),force,capacity],
      )).rows[0].result;
    const read=async()=>(await db.query(
      "select online,capacity,presence_writes,capacity_writes from public.test_device_heartbeat where device_id=$1",
      [id],
    )).rows[0];

    assert.deepEqual(await send(true,13),{ok:false,error:"product_capacity_unavailable"});
    assert.deepEqual(await read(),{
      online:false,capacity:4,presence_writes:0,capacity_writes:0,
    },"failed capacity must undo the earlier presence write");
    assert.deepEqual(await send(true,8),{ok:true,recorded:true});
    assert.deepEqual(await read(),{
      online:true,capacity:8,presence_writes:1,capacity_writes:1,
    });
    assert.deepEqual(await send(false,32,true),{ok:true,recorded:true});
    assert.deepEqual(await read(),{
      online:false,capacity:8,presence_writes:2,capacity_writes:1,
    },"offline must not refresh stale capacity");
    assert.deepEqual(await send(true,0),{ok:false,error:"product_capacity_unavailable"});
    assert.deepEqual(await read(),{
      online:false,capacity:8,presence_writes:2,capacity_writes:1,
    },"invalid limits must fail before writing");
    const p=await db.query(
      "select has_function_privilege('anon',$1,'EXECUTE') as anon_exec,"+
      "has_function_privilege('authenticated',$1,'EXECUTE') as auth_exec,"+
      "has_function_privilege('ordax_edge_executor',$1,'EXECUTE') as edge_exec",
      ["public.ordax_record_product_heartbeat_v1(uuid,boolean,text,text,text,boolean,integer)"],
    );
    assert.deepEqual(p.rows[0],{anon_exec:false,auth_exec:false,edge_exec:true});
  } finally {await db.close();}
});
