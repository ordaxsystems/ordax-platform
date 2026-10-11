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
const requestId=randomUUID();
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
const discovery=await fetch('http://hub:8900/v1/devices',{
  signal:AbortSignal.timeout(3000),
});
if(discovery.status!==404) throw Error('DEVICE_DISCOVERY_AVAILABLE');
console.log('RELAY_ISOLATED_CONTAINER='+id+' PASS');
