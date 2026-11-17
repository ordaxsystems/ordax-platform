import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(new URL("../cloudflare/package.json", import.meta.url));
const { PGlite } = require("@electric-sql/pglite");
const migration = fs.readFileSync(
  new URL("../supabase/migrations/20261117172000_product_installation_host_projection_v1.sql", import.meta.url),
  "utf8",
);
const PREFIX_HEX = "6f726461782e70726f647563742e6465766963652d62696e64696e672f31006f726461782d6465736b746f7000";

test("canonical product discovery groups installed Desktop with its physical Windows agent without merging device credentials",async()=>{
  const db = new PGlite();
  const [owner,otherOwner,client,otherClient,pc,desktop,sameName,foreign] =
    Array.from({length:8},()=>randomUUID());
  try {
    await db.exec([
      "create schema private; create schema extensions;",
      "create role anon; create role authenticated; create role service_role; create role ordax_edge_executor;",
      "create table private.eligible_owner(id uuid primary key);",
      "create table public.ordax_product_devices(device_id uuid primary key,owner_user_id uuid,display_name text,state text,device_kind text,channel text);",
      "create table private.ordax_product_device_credentials(device_id uuid primary key,machine_binding_sha256 text,revoked_at timestamptz);",
      "create table public.ordax_remote_capability_grants(grant_group_id uuid,profile_key text,device_id uuid,space_id uuid,project_id uuid,capability text,access_mode text,valid_until timestamptz,owner_user_id uuid,client_kind text,client_id text,state text);",
      "create table public.ordax_device_presence(device_id uuid,online boolean,last_seen_at timestamptz);",
      // The PGlite digest shim tests equality and scope. Real SHA-256 is
      // verified against the connected PostgreSQL authority separately.
      "create function extensions.digest(bytes bytea,algorithm text) returns bytea language sql immutable as $$ select case when algorithm='sha256' then decode(md5(encode(bytes,'hex'))||md5(encode(bytes,'hex')),'hex') else null::bytea end $$;",
      "create function private.ordax_trusted_actor_auth_eligible_v1(subject uuid) returns boolean language sql stable security definer set search_path='' as $$ select exists(select 1 from private.eligible_owner where id=subject) $$;",
      "create function private.ordax_product_presence_online_v1(online boolean,last_seen timestamptz,asof timestamptz) returns boolean language sql stable as $$ select coalesce(online,false) $$;",
      "create function public.ordax_list_product_targets_v1(uuid,text,text) returns jsonb language sql as $$ select '{}'::jsonb $$;",
    ].join("\n"));
    await db.exec(migration);
    for(const id of [owner,otherOwner]){
      await db.query("insert into private.eligible_owner values($1)",[id]);
    }
    for (const [id,subject,name] of [
      [pc,owner,"DESKTOP-X"],
      [desktop,owner,"OrdaX Desktop (DESKTOP-X)"],
      [sameName,owner,"OrdaX Desktop (DESKTOP-X)"],
      [foreign,otherOwner,"DESKTOP-X"],
    ]) {
      await db.query("insert into public.ordax_product_devices values ($1,$2,$3,'active','desktop','development')",[id,subject,name]);
      await db.query("insert into public.ordax_device_presence values($1,true,now())",[id]);
    }
    const physicalBinding="a".repeat(64);
    const appBinding=(await db.query(
      "select encode(extensions.digest(decode($1,'hex')||convert_to($2,'UTF8'),'sha256'),'hex') as hash",
      [PREFIX_HEX,physicalBinding],
    )).rows[0].hash;
    for(const [id,binding] of [
      [pc,physicalBinding],[desktop,appBinding],[sameName,"c".repeat(64)],[foreign,"d".repeat(64)],
    ]){
      await db.query("insert into private.ordax_product_device_credentials values($1,$2,null)",[id,binding]);
    }
    const grant="insert into public.ordax_remote_capability_grants values($1,'computer-observe',$2,null,null,'computer.windows','read',now()+interval '1 hour',$3,'product-mcp',$4,'active')";
    for(const id of [pc,desktop,sameName])await db.query(grant,[randomUUID(),id,owner,client]);
    await db.query(grant,[randomUUID(),foreign,otherOwner,client]);
    const list=async(subject=owner,cid=client)=>(await db.query(
      "select public.ordax_list_product_targets_v1($1::uuid,'product-mcp',$2::text) as result",
      [subject,cid],
    )).rows[0].result as any;
    const catalog=await list();
    assert.equal(catalog.ok,true);
    assert.equal(catalog.targets.length,3);
    const byId=Object.fromEntries(catalog.targets.map((row:any)=>[row.device_id,row]));
    assert.equal(byId[pc].device_name,"DESKTOP-X");
    assert.equal(byId[pc].endpoint_role,"physical_computer");
    assert.equal(byId[pc].physical_host_device_id,pc);
    assert.equal(byId[desktop].device_name,"OrdaX Desktop");
    assert.equal(byId[desktop].endpoint_role,"ordax_desktop_installation");
    assert.equal(byId[desktop].physical_host_device_id,pc);
    assert.equal(byId[sameName].device_name,"OrdaX Desktop (DESKTOP-X)");
    assert.equal(byId[sameName].endpoint_role,"standalone_runtime_endpoint");
    assert.equal(byId[sameName].physical_host_device_id,null);
    assert.equal(JSON.stringify(catalog).includes(foreign),false);
    await db.query("delete from public.ordax_remote_capability_grants where device_id=$1",[pc]);
    const isolated=(await list()).targets.find((row:any)=>row.device_id===desktop);
    assert.equal(isolated.device_name,"OrdaX Desktop");
    assert.equal(isolated.endpoint_role,"ordax_desktop_installation");
    assert.equal(isolated.physical_host_device_id,null,
      "a physical device without an OAuth grant cannot be revealed from private enrollment metadata");
    await db.query("update private.ordax_product_device_credentials set revoked_at=now() where device_id=$1",[pc]);
    const revoked=(await list()).targets.find((row:any)=>row.device_id===desktop);
    assert.equal(revoked.endpoint_role,"standalone_runtime_endpoint");
    assert.equal(revoked.physical_host_device_id,null);
    assert.deepEqual(await list(owner,otherClient),{ok:true,targets:[]});
    for (const sig of [
      "private.ordax_desktop_installation_host_v1(uuid)",
      "public.ordax_list_product_targets_v1(uuid,text,text)",
    ]){
      for(const role of ["anon","authenticated","service_role"]){
        assert.equal((await db.query("select has_function_privilege($1,$2,'EXECUTE') as allowed",
          [role,sig])).rows[0].allowed,false,role+" "+sig);
      }
    }
    assert.equal((await db.query(
      "select has_function_privilege('ordax_edge_executor','private.ordax_desktop_installation_host_v1(uuid)','EXECUTE') as allowed",
    )).rows[0].allowed,false);
    assert.equal((await db.query(
      "select has_function_privilege('ordax_edge_executor','public.ordax_list_product_targets_v1(uuid,text,text)','EXECUTE') as allowed",
    )).rows[0].allowed,true);
    assert.doesNotMatch(migration,/create or replace function public\.ordax_owner_select_central_device_v1/i);
  }finally{
    await db.close();
  }
});
