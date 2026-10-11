// Container-network ONLY. Proxies to the actual loopback-only Relay test
// implementation, without publishing any host port. Never run outside the
// private, internal Docker networks defined in compose.yml.
import { createServer as tcpServer, connect } from 'node:net';
import { startRelayLab } from '../relay.mjs';

if (process.env.ORDAX_RELAY_NETWORK_LAB !== 'internal-container-only') process.exit(2);
const secrets=[1,2,3].map(i=>process.env['RELAY_TEST_SPOKE'+i+'_TOKEN']);
if (secrets.some(v=>typeof v!=='string'||v.length<32)) process.exit(2);
const relay=await startRelayLab({
  devices:secrets.map((secret,i)=>({id:'spoke-'+(i+1),secret})),
  inference:async ({deviceId,requestId,prompt})=>({
    deviceId,requestId,result:'isolated:'+deviceId+':'+prompt,
  }),
});
const port=Number(new URL(relay.url).port);
const gateway=tcpServer(socket=>{
  const upstream=connect({host:'127.0.0.1',port});
  socket.on('error',()=>upstream.destroy());
  upstream.on('error',()=>socket.destroy());
  socket.pipe(upstream).pipe(socket);
});
gateway.listen(8900,'0.0.0.0');
process.on('SIGTERM',()=>{
  gateway.close();
  void relay.close().finally(()=>process.exit(0));
});
