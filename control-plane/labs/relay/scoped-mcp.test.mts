import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { handleOrdaxMcp } from "../../cloudflare/src/mcp_http.ts";
import { scopeRelayMcp } from "./scoped-mcp.ts";

const devices = [1,2,3].map(n => ({
  deviceId: `00000000-0000-4000-8000-00000000000${n}`,
  subjectId: `10000000-0000-4000-8000-00000000000${n}`,
  clientId: `client-${n}`, spaceId: null, project: `projeto-${n}`,
  rootPath: "pasta 1",
  actions: ["workspace.directory_list","workspace.file_stat","workspace.text_read"],
  secret: randomBytes(32).toString("hex"),
  privateFile: `resultado-exclusivo-do-pc-${n}.txt`
}));
function createFixture() {
  const records = new Map();
  const invocations = [];
  let corruptStatus = false;
  const hub = {
    async session() { return Response.json({ok:true,session:{subject_id:"HUB-OPERATOR-NOT-FOR-CLIENTS"}}); },
    async targets() { return Response.json({ok:true, targets:devices.map(d => ({
      device_id:d.deviceId,device_name:d.clientId,online:true,private_token:d.secret,
      grant_groups:[{profile_key:"full-computer-control",capabilities:[{capability:"computer.type",access_mode:"write"}]}]
    }))}); },
    async createAction(req) {
      const action = await req.json();
      invocations.push(action);
      const requestId = randomUUID();
      const d = devices.find(d => d.deviceId === action.device_id);
      if (!d) throw new Error("bad_device");
      records.set(requestId, {ok:true,action:{
        request_id:requestId,device_id:d.deviceId,subject_id:d.subjectId,client_id:d.clientId,project:d.project,
        action:action.action,status:"succeeded",error_code:null,
        result:{device_id:d.deviceId,files:[d.privateFile],path:action.arguments.path},
      }});
      return Response.json({ok:true,request_id:requestId});
    },
    async getAction(_req,requestId) {
      const record = records.get(requestId);
      if (!record) return Response.json({ok:false,error:"not_found"},{status:404});
      if (corruptStatus) return Response.json({ok:true,action:{...record.action,device_id:devices[2].deviceId,
        result:{secret:devices[2].privateFile}}});
      return Response.json(record);
    },
  };
  const resolver = async request => {
    const bearer = request.headers.get("authorization")?.replace(/^Bearer /,"") || "";
    const d = devices.find(d => bearer.length === d.secret.length &&
      timingSafeEqual(Buffer.from(bearer),Buffer.from(d.secret)));
    if (!d) return null;
    const {secret, privateFile, ...scope} = d;
    return scope;
  };
  const verify = async (_req, requestId, scope) => {
    // The test store plays the role of canonical Product authority. It is
    // independent of the LLM's tool arguments and public result payload.
    const action = records.get(requestId)?.action;
    return Boolean(action && action.subject_id === scope.subjectId
      && action.client_id === scope.clientId && action.device_id === scope.deviceId
      && action.project === scope.project);
  };
  const handlers = scopeRelayMcp(hub,resolver,verify);
  async function tool(d, name, args) {
    const res = await handleOrdaxMcp(new Request("https://lab.example/mcp",{
      method:"POST",headers:{authorization:`Bearer ${d.secret}`,"content-type":"application/json"},
      body:JSON.stringify({jsonrpc:"2.0",id:randomUUID(),method:"tools/call",
        params:{name,arguments:args}})
    }),handlers);
    assert.equal(res.status,200);
    const payload = await res.json();
    return payload.result?.structuredContent || payload.error;
  }
  return {tool,invocations, corrupt:()=>{corruptStatus=true;}};
}
const args = d => ({device_id:d.deviceId,project:d.project,path:"pasta 1",wait_for_completion_ms:0});

test("plugin MCP real: solicitação 'analise a pasta 1' de três usuários mantém origem, projeto e retorno", async () => {
  const lab = createFixture();
  const result = await Promise.all(devices.map(d => lab.tool(d,"workspace_directory_list",args(d))));
  assert.equal(lab.invocations.length,3);
  for (let i=0;i<devices.length;i++){
    const data = result[i];
    assert.equal(data.ok,true,JSON.stringify(data));
    assert.equal(data.action.result.device_id,devices[i].deviceId);
    assert.deepEqual(data.action.result.files,[devices[i].privateFile]);
    assert.equal(data.action.project,devices[i].project);
    assert.equal(lab.invocations[i].device_id,devices[i].deviceId);
    assert.equal(lab.invocations[i].project,devices[i].project);
    assert.ok(!JSON.stringify(data).includes(devices[(i+1)%3].privateFile));
  }
});

test("plugin não deixa usuário descobrir outros dispositivos e não publica token do hub", async () => {
  const lab=createFixture();
  for (const d of devices) {
    const response=await lab.tool(d,"ordax_targets",{});
    assert.equal(response.ok,true);
    assert.equal(response.targets.length,1);
    assert.equal(response.targets[0].device_id,d.deviceId);
    for (const other of devices.filter(other => other !== d)){
      assert.ok(!JSON.stringify(response).includes(other.deviceId));
      assert.ok(!JSON.stringify(response).includes(other.clientId));
      assert.ok(!JSON.stringify(response).includes(other.secret));
    }
    const profile=await lab.tool(d,"ordax_profile",{});
    assert.equal(profile.id,d.subjectId);
    assert.ok(!JSON.stringify(profile).includes("HUB-OPERATOR"));
  }
});

test("GPT com device_id, projeto ou pasta errados recebe negação ANTES do executor", async () => {
  const lab=createFixture(); const d=devices[0];
  for (const changes of [
    {device_id:devices[1].deviceId},
    {project:devices[1].project},
    {space_id:devices[1].subjectId},
    {path:"pasta 2"},
    {path:"pasta 1/../pc-dois"},
    {path:"pasta 1\\dados"},
    {path:"C:/private"},
    {target_device_id:devices[1].deviceId},
  ]) {
    const output=await lab.tool(d,"workspace_directory_list",{...args(d),...changes});
    assert.equal(output.ok,false,JSON.stringify(changes));
    assert.equal(output.error,"relay_scope_denied");
  }
  const wrongTool=await lab.tool(d,"computer_type",{device_id:d.deviceId,text:"invadir"});
  assert.equal(wrongTool.error,"relay_scope_denied");
  assert.equal(lab.invocations.length,0);
});

test("resultado ou consulta de status de outro cliente não podem atravessar a fronteira", async () => {
  const lab=createFixture();
  const original=await lab.tool(devices[0],"workspace_directory_list",args(devices[0]));
  const other=await lab.tool(devices[1],"ordax_action_status",{request_id:original.request_id});
  assert.equal(other.ok,false);
  assert.ok(!JSON.stringify(other).includes(devices[0].privateFile));
  lab.corrupt();
  const switched=await lab.tool(devices[0],"workspace_directory_list",args(devices[0]));
  assert.equal(switched.ok,false);
  assert.ok(!JSON.stringify(switched).includes(devices[2].privateFile));
});

test("credencial inválida não alcança catalogação, ferramentas ou ações", async () => {
  const lab=createFixture();
  const wrongCredential=await handleOrdaxMcp(new Request("https://lab.example/mcp", {
    method:"POST",headers:{authorization:"Bearer invalid-credential","content-type":"application/json"},
    body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/call",params:{
      name:"workspace_directory_list",arguments:args(devices[0])
    }})
  }),scopeRelayMcp({
    session:async()=>{throw new Error("should not reach backend");},
    targets:async()=>{throw new Error("should not reach backend");},
    createAction:async()=>{throw new Error("should not reach backend");},
    getAction:async()=>{throw new Error("should not reach backend");},
  }, async()=>null, async()=>false));
  assert.equal(wrongCredential.status,403);
  assert.equal(lab.invocations.length,0);
});

test("mesmo PC e pasta não bastam: status de outro cliente é recusado", async () => {
  const lab=createFixture();
  const valid=await lab.tool(devices[0],"workspace_directory_list",args(devices[0]));
  assert.equal(valid.ok,true);
  // Same device can have multiple accounts; a request ID is not authorization.
  // The fixture deliberately returns a status belonging to client-1 while a
  // different token is used. It must not surface the private file.
  const someoneElse=await lab.tool(devices[1],"ordax_action_status",{request_id:valid.request_id});
  assert.equal(someoneElse.ok,false);
  assert.ok(!JSON.stringify(someoneElse).includes(devices[0].privateFile));
});

test("dois clientes do mesmo PC e projeto não compartilham recibos",async () => {
  const id=randomUUID();
  const {secret:_,privateFile:__, ...scopeA}=devices[0];
  const scopeB={...scopeA,subjectId:devices[1].subjectId,clientId:devices[1].clientId};
  const handlers=scopeRelayMcp({
    session:async()=>Response.json({ok:true}),
    targets:async()=>Response.json({ok:true,targets:[]}),
    createAction:async()=>{throw Error("somente leitura");},
    getAction:async()=>Response.json({ok:true,action:{
      request_id:id,device_id:scopeA.deviceId,project:scopeA.project,
      action:"workspace.directory_list",status:"succeeded",result:{files:["PRIVADO_CLIENTE_A"]}
    }})
  }, async request => request.headers.get("authorization")==="Bearer "+devices[0].secret ? scopeA :
      request.headers.get("authorization")==="Bearer "+devices[1].secret ? scopeB : null,
  async (_request,requestId,scope) => requestId===id && scope.subjectId===scopeA.subjectId && scope.clientId===scopeA.clientId);
  async function status(secret) {
    const response=await handleOrdaxMcp(new Request("https://lab.example/mcp",{
      method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+secret},
      body:JSON.stringify({jsonrpc:"2.0",id:2,method:"tools/call",
        params:{name:"ordax_action_status",arguments:{request_id:id}}})
    }),handlers);
    return (await response.json()).result;
  }
  const denied=await status(devices[1].secret);
  assert.equal(denied.isError,true);
  assert.ok(!JSON.stringify(denied).includes("PRIVADO_CLIENTE_A"));
  const allowed=await status(devices[0].secret);
  assert.equal(allowed.isError,false);
  assert.ok(JSON.stringify(allowed).includes("PRIVADO_CLIENTE_A"));
});
