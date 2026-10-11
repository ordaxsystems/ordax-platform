// Test-only virtual spoke: a separate operating-system process.
// No TCP listener, no peer lookup, no host-wide file enumeration.
// This process is NOT a VM and its filesystem is NOT isolated by the kernel.
import { readFile, readdir, realpath } from 'node:fs/promises';
import { resolve, sep } from 'node:path';

const deviceId = process.env.ORDAX_LAB_SPOKE_ID;
const secret = process.env.ORDAX_LAB_SPOKE_TOKEN;
const url = process.env.ORDAX_LAB_HUB_URL;
const fixtureRoot = process.env.ORDAX_LAB_SPOKE_ROOT;
if (!deviceId || !secret || !url || !fixtureRoot || typeof process.send !== 'function') {
  process.exit(2);
}
const acceptedRoot = await realpath(fixtureRoot);
let started = false;

process.on('message', async command => {
  if (!command || typeof command !== 'object') return;
  if (command.type === 'read-folder') {
    const {requestId,correlationId} = command;
    const denied = error => process.send?.({
      type:'read-response',correlationId,deviceId,requestId,ok:false,error,
    });
    if (command.deviceId !== deviceId || command.path !== 'pasta 1'
      || typeof requestId !== 'string' || typeof correlationId !== 'string') {
      denied('target_mismatch'); return;
    }
    try {
      const folder = await realpath(resolve(acceptedRoot,'pasta 1'));
      if (!folder.startsWith(acceptedRoot + sep)) { denied('path_outside_root'); return; }
      const entries = await readdir(folder,{withFileTypes:true});
      if (entries.length !== 1 || entries[0].name !== 'descricao.txt' || !entries[0].isFile()) {
        denied('unexpected_fixture'); return;
      }
      const notePath = await realpath(resolve(folder,'descricao.txt'));
      if (!notePath.startsWith(folder + sep)) { denied('path_outside_root'); return; }
      const content = await readFile(notePath,'utf8');
      process.send?.({type:'read-response',correlationId,deviceId,requestId,ok:true,
        result:{files:['descricao.txt'],note:content.trim()}});
    } catch { denied('unavailable'); }
  }
  if (command.type === 'start' && !started) {
    started = true;
    const requestId = command.requestId;
    try {
      const response = await fetch(url+'/v1/infer',{
        method:'POST',headers:{
          'content-type':'application/json','authorization':'Bearer '+secret,
          'x-ordax-lab-device-id':deviceId,
        },
        body:JSON.stringify({request_id:requestId,prompt:command.prompt}),
        signal:AbortSignal.timeout(10000),
      });
      const result=await response.json();
      process.send?.({type:'done',deviceId,requestId,status:response.status,result});
    } catch { process.send?.({type:'done',deviceId,requestId,status:503,result:{ok:false,error:'transport_unavailable'}}); }
  }
});
process.send({type:'ready',deviceId});
