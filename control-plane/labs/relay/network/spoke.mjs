import { connect } from 'node:net';
import { lookup } from 'node:dns/promises';
import { randomUUID } from 'node:crypto';

if (process.env.ORDAX_RELAY_NETWORK_LAB !== 'internal-container-only') process.exit(2);
const id=process.env.RELAY_TEST_CLIENT_ID;
const token=process.env.RELAY_TEST_CLIENT_TOKEN;
const ownSentinel=process.env.RELAY_TEST_OWN_SENTINEL;
if(!/^spoke-[123]$/.test(id||'')||typeof token!=='string'||token.length<32
  ||!/^[123]$/.test(ownSentinel||'')) process.exit(2);

function tcpAccessible(host,port=9901,timeoutMs=1200){
  return new Promise(resolve=>{
    const socket=connect({host,port});
    let resolved=false;
    const done=ok=>{
      if(resolved)return;
      resolved=true; socket.destroy(); resolve(ok);
    };
    socket.once('connect',()=>done(true));
    socket.once('error',()=>done(false));
    socket.setTimeout(timeoutMs,()=>done(false));
  });
}
const selfIp='172.29.20'+ownSentinel+'.30';
let selfReached=false;
for(let n=0;n<30;n++){
  if(await tcpAccessible(selfIp)){selfReached=true;break;}
  await new Promise(r=>setTimeout(r,100));
}
if(!selfReached) throw Error('own_network_sentinel_missing');
for(const peer of [1,2,3].filter(n=>String(n)!==ownSentinel)){
  const direct=await tcpAccessible('172.29.20'+peer+'.30');
  if(direct) throw Error('LATERAL_ROUTE_OPEN');
  let dnsVisible=false;
  try{await lookup('sentinel'+peer);dnsVisible=true;}catch{}
  if(dnsVisible) throw Error('PEER_DISCOVERY_VISIBLE');
}
// Same request UUID on three distinct simulated PCs must be namespaced by
// the authenticated device, never globally reused or sent to another spoke.
const requestId='11111111-1111-4111-8111-111111111111';
const response=await fetch('http://hub:8900/v1/infer',{
  method:'POST',headers:{
    'content-type':'application/json','authorization':'Bearer '+token,
    'x-ordax-lab-device-id':id,
  },
  body:JSON.stringify({request_id:requestId,prompt:'analise a pasta 1'}),
  signal:AbortSignal.timeout(8000),
});
const data=await response.json();
if(response.status!==200 || data.ok!==true || data.request_id!==requestId
  || data.result!=='isolated:'+id+':analise a pasta 1') throw Error('CROSS_CLIENT_RESULT');
for(const peer of [1,2,3].filter(n=>'spoke-'+n!==id)){
  if(data.result.includes('spoke-'+peer)) throw Error('PEER_CONTENT_LEAK');
}
// Both foreign identities must reject this credential. This exercises six
// impossible client→peer pairings across three independently networked PCs.
for (const n of [1,2,3].filter(n=>'spoke-'+n!==id)) {
  const foreign='spoke-'+n;
  const impersonated=await fetch('http://hub:8900/v1/infer',{
    method:'POST',headers:{
      'content-type':'application/json','authorization':'Bearer '+token,
      'x-ordax-lab-device-id':foreign,
    },
    body:JSON.stringify({request_id:randomUUID(),prompt:'tentar agir por outro pc'}),
    signal:AbortSignal.timeout(8000),
  });
  if(impersonated.status!==401) throw Error('OTHER_DEVICE_IMPERSONATION_ACCEPTED');
  if(JSON.stringify(await impersonated.json()).includes('isolated:')) throw Error('OTHER_DEVICE_RESULT_EXPOSED');
}

// Replay is scoped to authenticated device+request ID, never request ID
// alone. A conflicting payload fails 409 without rewriting the receipt.
const retry=async prompt=>fetch('http://hub:8900/v1/infer',{
  method:'POST',headers:{
    'content-type':'application/json','authorization':'Bearer '+token,
    'x-ordax-lab-device-id':id,
  },
  body:JSON.stringify({request_id:requestId,prompt}),
  signal:AbortSignal.timeout(8000),
});
const repeated=await retry('analise a pasta 1');
if(repeated.status!==200) throw Error('EMULATED_PC_REPLAY_FAILED');
const replayResult=await repeated.json();
if(replayResult.replayed!==true || replayResult.result!=='isolated:'+id+':analise a pasta 1')
  throw Error('CROSS_PC_REPLAY_LEAK');
const conflicting=await retry('mudar conteudo apos o primeiro envio');
if(conflicting.status!==409) throw Error('EMULATED_PC_REPLAY_CONFLICT_ALLOWED');
if((await conflicting.json()).error!=='request_conflict') throw Error('REPLAY_CONFLICT_NOT_RECORDED');

// Three independent conversation-like turns per spoke, interleaved across the
// three real container clients. This proves receipt routing, NOT GPT memory.
const latencies=[];
for(let turn=1;turn<=3;turn++){
  const turnId=randomUUID();
  const phrase='turno-'+turn+'-'+id;
  const started=performance.now();
  const current=await fetch('http://hub:8900/v1/infer',{
    method:'POST',headers:{
      'content-type':'application/json','authorization':'Bearer '+token,
      'x-ordax-lab-device-id':id,
    },
    body:JSON.stringify({request_id:turnId,prompt:phrase}),
    signal:AbortSignal.timeout(8000),
  });
  const roundTripMs=performance.now()-started;
  const value=await current.json();
  if(current.status!==200 || value.request_id!==turnId
    || value.result!=='isolated:'+id+':'+phrase) throw Error('CROSS_CONVERSATION_RESULT');
  if([1,2,3].some(n=>'spoke-'+n!==id && JSON.stringify(value).includes('isolated:spoke-'+n))) {
    throw Error('PEER_CONVERSATION_CONTENT_LEAK');
  }
  latencies.push(Number(roundTripMs.toFixed(2)));
}
console.log('RELAY_NETWORK_LATENCY_MS='+id+':'+latencies.join(','));
const discovery=await fetch('http://hub:8900/v1/devices',{
  signal:AbortSignal.timeout(3000),
});
if(discovery.status!==404) throw Error('DEVICE_DISCOVERY_AVAILABLE');
console.log('RELAY_ISOLATED_CONTAINER='+id+' PASS');
console.log('EMULATED_PC_IDENTITY='+id+' FOREIGN_TOKENS_DENIED=2 REPLAY_EXACT=PASS REPLAY_CONFLICT=DENIED SHARED_REQUEST_UUID=ISOLATED');
