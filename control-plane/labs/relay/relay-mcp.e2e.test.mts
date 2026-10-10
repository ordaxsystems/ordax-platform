import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { startRelayLab } from "./relay.mjs";
import { scopeRelayMcp } from "./scoped-mcp.ts";
import { handleOrdaxMcp } from "../../cloudflare/src/mcp_http.ts";

// End-to-end *lab* transport: real loopback HTTP -> central model adapter fixture
// -> actual ORDAX MCP implementation -> fake device executor -> exact client response.
// GPT inference, physical PCs, OS firewall and production grants are not simulated
// as real provider or deployment success.
const clients=Array.from({length:3},(_,i)=>{
  const n=i+1;
  return {
    id:`pc-${n}`,secret:randomBytes(32).toString("hex"),
    scope:{
      deviceId:`00000000-0000-4000-8000-00000000000${n}`,
      subjectId:`10000000-0000-4000-8000-00000000000${n}`,
      clientId:`client-${n}`,spaceId:null,project:`workspace-${n}`,
      rootPath:"pasta 1",actions:["workspace.directory_list"]
    },
    filename:`arquivo-particular-do-pc-${n}.txt`
  };
});
const jobs=new Map();const executed=[];
const handlers=scopeRelayMcp({
  session:async()=>Response.json({ok:true,session:{subject_id:"central-admin"}}),
  targets:async()=>Response.json({ok:true,targets:clients.map(d=>({device_id:d.scope.deviceId,device_name:d.id}))}),
  createAction:async(req)=>{
    const action=await req.json();
    const current=clients.find(c=>c.scope.deviceId===action.device_id);
    if(!current) throw Error("cannot select that PC");
    executed.push({deviceId:current.scope.deviceId,project:action.project,path:action.arguments.path});
    const jobId=randomUUID();
    jobs.set(jobId,{ok:true,action:{
      request_id:jobId,device_id:current.scope.deviceId,project:current.scope.project,
      action:action.action,status:"succeeded",error_code:null,
      result:{device_id:current.scope.deviceId,files:[current.filename]}
    }});
    return Response.json({ok:true,request_id:jobId});
  },
  getAction:async(_req,jobId)=>{
    const job=jobs.get(jobId);
    return job?Response.json(job):Response.json({ok:false,error:"not_found"},{status:404});
  }
},async req=>{
  const token=req.headers.get("authorization")?.slice("Bearer ".length) || "";
  const user=clients.find(client=>token.length===client.secret.length &&
    timingSafeEqual(Buffer.from(token),Buffer.from(client.secret)));
  return user?.scope || null;
});

async function adapter({deviceId,prompt}) {
  const client=clients.find(c=>c.id===deviceId);
  if(!client) throw Error("unregistered");
  // This is an injected GPT/tool-choice fixture, not a real model decision.
  if (!prompt.startsWith("analise a pasta 1")) throw Error("unsupported_request");
  const modelSelectedOtherPc=prompt.includes("forcar-pc-2");
  const choice={
    device_id:modelSelectedOtherPc?clients[1].scope.deviceId:client.scope.deviceId,
    project:client.scope.project,path:"pasta 1",wait_for_completion_ms:0
  };
  const response=await handleOrdaxMcp(new Request("https://relay-lab.example/mcp",{
    method:"POST",headers:{authorization:`Bearer ${client.secret}`,"content-type":"application/json"},
    body:JSON.stringify({jsonrpc:"2.0",id:randomUUID(),method:"tools/call",
      params:{name:"workspace_directory_list",arguments:choice}})
  }),handlers);
  if(response.status!==200) throw Error("plugin_unavailable");
  const result=(await response.json()).result?.structuredContent;
  if(result?.ok!==true || result.action?.result?.device_id!==client.scope.deviceId) {
    throw Error("relay_target_mismatch");
  }
  return JSON.stringify({requestDeviceId:client.scope.deviceId,files:result.action.result.files});
}
async function post(url,client,prompt) {
  return fetch(url+"/v1/infer",{
    method:"POST",headers:{"content-type":"application/json",
      "x-ordax-lab-device-id":client.id,
      authorization:`Bearer ${client.secret}`},
    body:JSON.stringify({request_id:randomUUID(),prompt})
  });
}
test("3 PCs: HTTP Relay -> MCP plugin -> executor correto -> resposta única por origem",async t=>{
  executed.length=0;
  const lab=await startRelayLab({devices:clients.map(c=>({id:c.id,secret:c.secret})),inference:adapter});
  t.after(()=>lab.close());
  const replies=await Promise.all(clients.map(async c=>{
    const response=await post(lab.url,c,"analise a pasta 1");
    assert.equal(response.status,200);return response.json();
  }));
  assert.equal(executed.length,3);
  for(let i=0;i<clients.length;i++){
    const reply=JSON.parse(replies[i].result);
    assert.equal(reply.requestDeviceId,clients[i].scope.deviceId);
    assert.deepEqual(reply.files,[clients[i].filename]);
    assert.equal(executed[i].deviceId,clients[i].scope.deviceId);
    assert.equal(executed[i].project,clients[i].scope.project);
    assert.equal(executed[i].path,"pasta 1");
    assert.ok(!JSON.stringify(replies[i]).includes(clients[(i+1)%3].filename));
  }
});
test("se o modelo escolher PC errado, o Relay rejeita ANTES da execução",async t=>{
  executed.length=0;
  const lab=await startRelayLab({devices:clients.map(c=>({id:c.id,secret:c.secret})),inference:adapter});
  t.after(()=>lab.close());
  const response=await post(lab.url,clients[0],"analise a pasta 1 forcar-pc-2");
  assert.equal(response.status,503);
  assert.equal((await response.json()).error,"adapter_unavailable");
  assert.equal(executed.length,0);
});
test("credencial trocada não roteia nem inicia chamada MCP",async t=>{
  executed.length=0;
  const lab=await startRelayLab({devices:clients.map(c=>({id:c.id,secret:c.secret})),inference:adapter});
  t.after(()=>lab.close());
  const response=await fetch(lab.url+"/v1/infer",{method:"POST",headers:{
    "content-type":"application/json","x-ordax-lab-device-id":clients[0].id,
    authorization:`Bearer ${clients[1].secret}`},
    body:JSON.stringify({request_id:randomUUID(),prompt:"analise a pasta 1"})
  });
  assert.equal(response.status,401);
  assert.equal(executed.length,0);
});
