import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {randomUUID,createHash} from 'node:crypto';
import {handleProductDeviceTransport} from '../cloudflare/src/product_device_transport.ts';
import {OWNER_MCP_GRANT_PROFILES} from '../cloudflare/src/product_owner_grant_profiles.ts';
const {Client}=createRequire(new URL('../cloudflare/package.json',import.meta.url))('pg');

test('device route resolves only a fenced action; model identity fields never reach SQL',async t=>{
  const device=randomUUID(),body={job_id:randomUUID(),effect_id:randomUUID(),attempt_id:randomUUID(),
    lease_id:randomUUID(),execution_epoch:1,agent_instance_id:randomUUID(),boot_id:'fixture-boot'};
  const env={POSTGRES:{connectionString:'postgres://fixture:fixture@localhost/fixture'}} as any;
  const calls:any[]=[];
  let authenticated=true,permitted=true;
  t.mock.method(Client.prototype,'connect',async()=>{});
  t.mock.method(Client.prototype,'end',async()=>{});
  t.mock.method(Client.prototype,'query',async(sql:string,args:any[])=>{
    calls.push({sql,args});
    if(sql.includes('ordax_authenticate_product_device_v1'))
      return {rows:[{result:authenticated}]};
    assert.match(sql,/select public\.ordax_orchestrator_read_authorization_v1/);
    return {rows:[{result:permitted?{ok:true,authorization:{fixture:true}}:
      {ok:false,error:'orchestrator_authorization_required'}}]};
  });
  const request=(value:unknown)=>new Request('https://mcp.example/v3/device/transport/orchestrator-read-authorization',{
    method:'POST',headers:{'x-ordax-device-id':device,'x-ordax-device-token':'a'.repeat(64),
      'content-type':'application/json'},body:JSON.stringify(value)});
  assert.equal((await handleProductDeviceTransport(request(body),env)).status,200);
  assert.deepEqual(calls[0].args,[device,createHash('sha256').update('a'.repeat(64)).digest('hex')]);
  assert.deepEqual(calls[1].args,[device,body.job_id,body.effect_id,body.attempt_id,
    body.lease_id,1,body.agent_instance_id,body.boot_id]);
  for(const field of ['owner_user_id','subject_id','client_id','grant_id','device_id','app_id','capability','runtime_kind']){
    calls.length=0;
    assert.equal((await handleProductDeviceTransport(request({...body,[field]:'forged'}),env)).status,400);
    assert.equal(calls.length,1,field);
  }
  calls.length=0;authenticated=false;
  assert.equal((await handleProductDeviceTransport(request(body),env)).status,401);
  assert.equal(calls.length,1);
  authenticated=true;permitted=false;
  const denied=await handleProductDeviceTransport(request(body),env);
  assert.equal(denied.status,403);
  assert.deepEqual(await denied.json(),{ok:false,error:'orchestrator_authorization_required'});
});

test('Lab read profile is independent from every Computer Control profile',()=>{
  assert.deepEqual(OWNER_MCP_GRANT_PROFILES['orchestrator-app-read'],{
    scope:'device',capabilities:[{capability:'orchestrator.app_read',accessMode:'read'}]});
  for(const [name,profile] of Object.entries(OWNER_MCP_GRANT_PROFILES)){
    if(name==='orchestrator-app-read')continue;
    assert.equal(profile.capabilities.some(c=>c.capability==='orchestrator.app_read'),false,name);
  }
});
