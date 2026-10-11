import test from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startRelayLab } from './relay.mjs';
import { scopeRelayMcp } from './scoped-mcp.ts';
import { handleOrdaxMcp } from '../../cloudflare/src/mcp_http.ts';

// Unlike the in-memory fixture, three separate OS processes each read their
// own real test folder. They are NOT VMs, containers or kernel-isolated nodes.
// The server-side model/tool-choice is a fixture, NOT a real ChatGPT session.
const clients = Array.from({length:3},(_,i)=>{
  const n=i+1;
  return {id:'spoke-'+n,secret:randomBytes(32).toString('hex'),
    deviceId:randomUUID(),subjectId:randomUUID(),clientId:'test-client-'+n,
    project:'workspace-'+n,marker:'arquivo-exclusivo-do-cliente-'+n};
});
const records=new Map(), children=new Map(), execution=[];
function ask(child,message,expected,timeoutMs=3000) {
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{cleanup();reject(Error('spoke_timeout'));},timeoutMs);
    const onExit=()=>{cleanup();reject(Error('spoke_exited'));};
    const onMessage=reply=>{
      if(reply?.type!==expected || (message.correlationId && reply.correlationId!==message.correlationId)
        || (message.requestId && reply.requestId!==message.requestId)) return;
      cleanup();resolve(reply);
    };
    const cleanup=()=>{
      clearTimeout(timer); child.off('message',onMessage);child.off('exit',onExit);
    };
    child.on('message',onMessage);
    child.on('exit',onExit);
    if(message.type) child.send(message);
  });
}
const hub={
  session:async()=>Response.json({ok:true,session:{subject_id:'central-admin'}}),
  targets:async()=>Response.json({ok:true,targets:clients.map(c=>({
    device_id:c.deviceId,device_name:c.id,online:true,
  }))}),
  createAction:async request=>{
    const action=await request.json();
    const client=clients.find(c=>c.deviceId===action.device_id);
    if(!client) return Response.json({ok:false,error:'target_not_found'},{status:404});
    const child=children.get(client.id);
    if(!child) return Response.json({ok:false,error:'spoke_offline'},{status:503});
    const requestId=randomUUID();
    const read=await ask(child,{
      type:'read-folder',deviceId:client.id,requestId,correlationId:requestId,
      path:action.arguments.path,
    },'read-response');
    if(!read.ok || read.deviceId!==client.id || !read.result ||
      !read.result.note.includes(client.marker)) {
      return Response.json({ok:false,error:'device_read_failed'},{status:503});
    }
    execution.push({clientId:client.clientId,deviceId:client.deviceId,project:action.project});
    records.set(requestId,{ok:true,action:{
      request_id:requestId,device_id:client.deviceId,
      project:client.project, action:action.action,status:'succeeded',
      result:{device_id:client.deviceId,files:read.result.files,note:read.result.note},
    },subjectId:client.subjectId,clientId:client.clientId});
    return Response.json({ok:true,request_id:requestId});
  },
  getAction:async(_request,requestId)=>{
    const row=records.get(requestId);
    return row?Response.json({ok:true,action:row.action}):
      Response.json({ok:false,error:'not_found'},{status:404});
  },
};
const resolveScope=async request=>{
  const bearer=request.headers.get('authorization')?.replace(/^Bearer /,'')||'';
  const client=clients.find(c=>bearer.length===c.secret.length &&
    timingSafeEqual(Buffer.from(bearer),Buffer.from(c.secret)));
  if(!client) return null;
  return {deviceId:client.deviceId,subjectId:client.subjectId,clientId:client.clientId,
    spaceId:null,project:client.project,rootPath:'pasta 1',actions:['workspace.directory_list']};
};
const verifyReceipt=async(_request,requestId,scope)=>{
  const row=records.get(requestId);
  return !!row && row.subjectId===scope.subjectId && row.clientId===scope.clientId
    && row.action.device_id===scope.deviceId && row.action.project===scope.project;
};
const handlers=scopeRelayMcp(hub,resolveScope,verifyReceipt);
async function tool(client,toolName,args){
  const response=await handleOrdaxMcp(new Request('https://lab.example/mcp',{
    method:'POST',headers:{'content-type':'application/json',authorization:'Bearer '+client.secret},
    body:JSON.stringify({jsonrpc:'2.0',id:randomUUID(),method:'tools/call',
      params:{name:toolName,arguments:args}}),
  }),handlers);
  assert.equal(response.status,200);
  const result=(await response.json()).result;
  return result?.structuredContent || result;
}
async function adapter({deviceId,requestId,prompt}){
  const client=clients.find(c=>c.id===deviceId);
  if(!client || !prompt.startsWith('analise a pasta 1')) throw Error('invalid_prompt');
  const malicious=prompt.includes('forcar-outro-pc');
  const selected=malicious?clients[(clients.indexOf(client)+1)%3]:client;
  const result=await tool(client,'workspace_directory_list',{
    device_id:selected.deviceId,project:client.project,path:'pasta 1',wait_for_completion_ms:0,
  });
  if(result?.ok!==true || result.action?.device_id!==client.deviceId ||
      result.action.result?.device_id!==client.deviceId) throw Error('denied_wrong_target');
  return {deviceId,requestId,result:JSON.stringify({
    deviceId,requestId,analysis:result.action.result.note,
  })};
}

test('3 processos clientes → Relay HTTP → MCP existente → leitura somente no próprio processo',async t=>{
  execution.length=0;records.clear();
  const roots=[];
  const lab=await startRelayLab({
    devices:clients.map(c=>({id:c.id,secret:c.secret})),inference:adapter,
  });
  t.after(async()=>{
    for(const child of children.values()) child.kill();
    await lab.close();
    await Promise.all(roots.map(dir=>rm(dir,{recursive:true,force:true})));
    children.clear();
  });
  for(const c of clients){
    const dir=await mkdtemp(join(tmpdir(),'ordax-relay-spoke-'));
    roots.push(dir);
    await mkdir(join(dir,'pasta 1'));
    await writeFile(join(dir,'pasta 1','descricao.txt'),c.marker);
    const child=fork(new URL('./spoke-process.mjs',import.meta.url),[],{
      cwd:dir,stdio:['ignore','pipe','pipe','ipc'],env:{
        ...process.env,ORDAX_LAB_SPOKE_ID:c.id,
        ORDAX_LAB_SPOKE_TOKEN:c.secret,ORDAX_LAB_HUB_URL:lab.url,
        ORDAX_LAB_SPOKE_ROOT:dir,
      },
    });
    children.set(c.id,child);
    const ready=await ask(child,{},'ready');
    assert.equal(ready.deviceId,c.id);
  }
  // A direct IPC attempt to spoof another device must fail before file read.
  const first=clients[0],second=clients[1];
  const wrong=await ask(children.get(first.id),{
    type:'read-folder',deviceId:second.id,requestId:randomUUID(),
    correlationId:randomUUID(),path:'pasta 1',
  },'read-response');
  assert.equal(wrong.ok,false);
  assert.equal(wrong.error,'target_mismatch');
  const requests=clients.map(c=>({client:c,requestId:randomUUID()}));
  const replies=await Promise.all(requests.map(({client,requestId})=>ask(children.get(client.id),{
    type:'start',requestId,prompt:'analise a pasta 1',
  },'done',10000)));
  assert.equal(execution.length,3);
  for(let i=0;i<clients.length;i++){
    const c=clients[i],reply=replies[i];
    assert.equal(reply.status,200,JSON.stringify(reply));
    assert.equal(reply.deviceId,c.id);
    assert.equal(reply.result.request_id,requests[i].requestId);
    const result=JSON.parse(reply.result.result);
    assert.equal(result.deviceId,c.id);
    assert.equal(result.requestId,requests[i].requestId);
    assert.equal(result.analysis,c.marker);
    for(const other of clients.filter(x=>x!==c)){
      assert.ok(!JSON.stringify(result).includes(other.marker));
      assert.ok(!JSON.stringify(reply).includes(other.secret));
    }
  }
  // Even a perfectly formed tool call must fail if the model selects PC B
  // for PC A. Nothing is sent to any spoke process after scope rejection.
  const prior=execution.length;
  await assert.rejects(adapter({
    deviceId:first.id,requestId:randomUUID(),
    prompt:'analise a pasta 1 forcar-outro-pc',
  }),/denied_wrong_target/);
  assert.equal(execution.length,prior);
  const owned=Array.from(records.entries()).find(([,row])=>row.clientId===first.clientId);
  assert.ok(owned);
  const otherStatus=await tool(second,'ordax_action_status',{request_id:owned[0]});
  assert.equal(otherStatus.ok,false);
  assert.ok(!JSON.stringify(otherStatus).includes(first.marker));
});
