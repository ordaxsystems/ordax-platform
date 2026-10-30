import test from 'node:test';
import assert from 'node:assert/strict';
import { projectWorkspaceGrantProjection } from '../cloudflare/src/project_workspace_grant_contract.ts';

const now=Date.parse('2026-10-21T23:40:00.000Z');
const owner='11111111-1111-4111-8111-111111111111';
const space='22222222-2222-4222-8222-222222222222';
const project='33333333-3333-4333-8333-333333333333';
const actor='44444444-4444-4444-8444-444444444444';
const client='55555555-5555-4555-8555-555555555555';
const device='66666666-6666-4666-8666-666666666666';
const id='77777777-7777-4777-8777-777777777777';
const trusted={ownerUserId:owner,spaceId:space,projectId:project,
  labProjectId:'lab_project_A',actorId:actor,clientId:client,
  workspaceSessionId:'workspace_session_A',deviceId:device,
  resourceId:'resource_opaque_aabbccdd1122'};
const row={grant_id:id,owner_user_id:owner,space_id:space,project_id:project,
  lab_project_id:trusted.labProjectId,actor_id:actor,client_id:client,
  workspace_session_id:trusted.workspaceSessionId,device_id:device,
  resource_id:trusted.resourceId,allowed_actions:['read'],issued_by:'trusted-runtime-picker',
  issued_at:'2026-10-21T23:00:00.000Z',
  valid_until:'2026-10-22T01:00:00.000Z',revoked_at:null,active:true};
const projection=(r=row,t=trusted,clock=now)=>projectWorkspaceGrantProjection(r,t,clock);

test('verified projection mirrors Runtime consumer without token, root or unrelated DB fields',()=>{
  const value=projection({...row,root:'C:\\secret\\project',access_token:'NEVER'});
  assert.deepEqual(value,{
    authorized:true,projectId:trusted.labProjectId,actorId:actor,clientId:client,
    workspaceSessionId:trusted.workspaceSessionId,deviceId:device,
    resourceId:trusted.resourceId,expiresAt:row.valid_until,
  });
  assert.equal(Object.isFrozen(value),true);
  assert.ok(!JSON.stringify(value).includes('secret'));
  assert.ok(!JSON.stringify(value).includes('NEVER'));
});

for(const field of ['owner_user_id','space_id','project_id','lab_project_id','actor_id',
  'client_id','workspace_session_id','device_id','resource_id']){
  test('exact scope enforcement for '+field,()=>{
    assert.equal(projection({...row,[field]:'not_the_owner'}),null);
  });
}

test('rejects incomplete and forged identity, raw path, prototype/shape anomalies',()=>{
  assert.equal(projection(null),null);
  assert.equal(projection([]),null);
  assert.equal(projection({...row,grant_id:'not-a-uuid'}),null);
  assert.equal(projection(row,{...trusted,deviceId:'abc'}),null);
  assert.equal(projection(row,{...trusted,resourceId:'C:\\data'}),null);
  assert.equal(projection(row,{...trusted,projectId:'lab_project_A'}),null);
  assert.equal(projection(row,{...trusted,workspaceSessionId:'../'}),null);
});
test('no full-computer, write, execute or duplicate read grant masquerades as project read',()=>{
  for(const actions of [['read','write'],['execute'],['write'],['read','read'],[],null]){
    assert.equal(projection({...row,allowed_actions:actions}),null);
  }
});
test('revoked, inactive, untrusted picker, no expiry or unreasonable expiry fail closed',()=>{
  for(const patch of [
    {active:false},{revoked_at:'2026-10-21T22:00:00Z'},
    {issued_by:'full-computer-control'},{issued_at:null},
    {issued_at:'2026-10-22T00:00:00.000Z'},
    {issued_at:'2026-10-20T20:00:00.000Z'},
    {valid_until:null},
    {valid_until:'2026-10-21T23:39:59.999Z'},
    {valid_until:'2026-11-01T01:00:00.000Z'},
    {valid_until:'not a timestamp'}
  ]) assert.equal(projection({...row,...patch}),null);
});
test('invalid clocks cannot silently extend grants',()=>{
  assert.equal(projection(row,trusted,NaN),null);
  assert.equal(projection(row,trusted,Infinity),null);
  assert.equal(projection(row,trusted,now+24*60*60*1000),null);
});
