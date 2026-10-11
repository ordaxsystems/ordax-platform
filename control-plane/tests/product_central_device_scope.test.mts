import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  selectCanonicalRelayDeviceScope, selectCanonicalRelayProjectScope,
} from "../cloudflare/src/product_relay_scope.ts";
import {
  createCanonicalCentralAdmissionVerifier,
} from "../cloudflare/src/product_central_admission.ts";
import {
  createCanonicalCentralMcpReadHandlers,
  createCanonicalCentralSessionMcpGateway,
} from "../cloudflare/src/product_central_mcp.ts";
import {
  env, owner, client, otherClient, device, secondDevice,
  projectId, requestId, actionRecord, token, withIssuer,
} from "./product_mcp_test_fixtures.mts";

const spaceId = "99999999-9999-4999-8999-999999999999";
const sessionId = "chatgpt-verified-device-20261011";
const base = { subjectId:owner, clientId:client, deviceId:device,
  spaceId:null, projectId:null, requestId,
  conversationId:"chat-device-0001", sessionId };
const meta = [{ capability:"computer.screen_info", access_mode:"read" },
  { capability:"computer.windows", access_mode:"read" }];
const group = (options:Record<string,unknown> = {}) => ({
  grant_group_id: randomUUID(), profile_key:"device-metadata",
  space_id:null, project_id:null, valid_until:null,
  capabilities:meta, ...options,
});
const projectGroup = () => ({
  grant_group_id:randomUUID(), profile_key:"project-read",
  space_id:spaceId, project_id:projectId, valid_until:null,
  capabilities:[{capability:"workspace.text_read",access_mode:"read"}],
});
const catalog=(grants:object[]=[group()], target:string=device)=>
  ({ok:true,targets:[{device_id:target,device_name:"PC autorizado",online:true,
    grant_groups:grants}]});
const identity = async (jwt:string)=>new Request("https://central.example/mcp",{
  headers:{authorization:"Bearer "+jwt,"x-ordax-device-id":secondDevice,
    "x-ordax-client-id":otherClient},
});
const deps = (deviceCatalog:unknown, accepted=base)=>({
  listTargets:async (_env:unknown,record:{clientId:string})=>
    record.clientId===client?deviceCatalog:{ok:true,targets:[]},
  verifySession:async (principal:{ownerUserId:string,clientId:string},
    claim:typeof base)=>principal.ownerUserId===owner
    && principal.clientId===client && claim.subjectId===owner
    && claim.clientId===accepted.clientId && claim.deviceId===accepted.deviceId
    && claim.spaceId===accepted.spaceId && claim.projectId===accepted.projectId
    && claim.requestId===accepted.requestId
    && claim.conversationId===accepted.conversationId
    && claim.sessionId===accepted.sessionId,
});

test("canonical PostgreSQL projection has NO scope_kind, both NULL IDs mean device-only",()=>{
  const x=catalog();
  assert.equal("scope_kind" in (x.targets[0].grant_groups[0] as object),false);
  assert.deepEqual(selectCanonicalRelayDeviceScope(x),{
    deviceId:device,spaceId:null,projectId:null,
    allowedActions:["computer.screen_info","computer.windows"],
  });
  assert.equal(selectCanonicalRelayProjectScope(x),null);
});

test("device access never implies project access and project access never implies device",()=>{
  const pc=catalog([projectGroup()]);
  assert.equal(selectCanonicalRelayDeviceScope(pc),null);
  assert.deepEqual(selectCanonicalRelayProjectScope(pc),{
    deviceId:device,spaceId,projectId,allowedActions:["workspace.text_read"],
  });
  for(const bad of [
    {space_id:null,project_id:projectId},
    {space_id:spaceId,project_id:null},
    {space_id:spaceId,project_id:projectId},
  ]){
    assert.equal(selectCanonicalRelayDeviceScope(catalog([group(bad)])),null);
  }
  assert.equal(selectCanonicalRelayDeviceScope(catalog([
    group({capabilities:[{capability:"workspace.text_read",access_mode:"read"}]})])),null);
});

test("device grant is read-only and expired, duplicated or ambiguous grants fail closed",()=>{
  const mixed=catalog([group({capabilities:[
    {capability:"computer.windows",access_mode:"write"},
    {capability:"computer.screen_info",access_mode:"read"},
  ]})]);
  assert.deepEqual(selectCanonicalRelayDeviceScope(mixed)?.allowedActions,["computer.screen_info"]);
  for(const grants of [
    [group({valid_until:"2020-01-01T00:00:00Z"})],
    [group(),group()],
    [group({capabilities:[...meta,meta[0]]})],
    [group({capabilities:[]})],
    [group({valid_until:"not a date"})],
  ])assert.equal(selectCanonicalRelayDeviceScope(catalog(grants)),null);
  assert.equal(selectCanonicalRelayDeviceScope({
    ok:true,targets:[...catalog().targets,...catalog([group()],secondDevice).targets]
  }),null);
});

test("durably attested device-only conversation matches signed exact OAuth client",async()=>{
  await withIssuer(async()=>{
    const verifier=createCanonicalCentralAdmissionVerifier(env,deps(catalog()));
    const jwt=await token();
    const accepted=await verifier(await identity(jwt),base);
    assert.equal(accepted.ok,true,JSON.stringify(accepted));
    if(!accepted.ok)return;
    assert.equal(accepted.spaceId,null);
    assert.equal(accepted.projectId,null);
    assert.deepEqual(accepted.allowedActions,["computer.screen_info","computer.windows"]);
    assert.equal(accepted.deviceId,device);
    assert.ok(Object.isFrozen(accepted));
    assert.equal((await verifier(await identity(await token({client_id:otherClient})),base)).ok,false);
    assert.equal((await verifier(await identity(jwt),{...base,deviceId:secondDevice})).ok,false);
    assert.equal((await verifier(await identity(jwt),{...base,spaceId:spaceId} as any)).ok,false);
    assert.equal((await verifier(await identity(jwt),{...base,projectId:projectId} as any)).ok,false);
  });
});

test("server-owned session binding may select among authorized PCs only AFTER trusted mapping",async()=>{
  await withIssuer(async()=>{
    let queried=0,attested=0;
    const double={ok:true,targets:[
      ...catalog([group()]).targets,
      ...catalog([group()],secondDevice).targets,
    ]};
    const verifier=createCanonicalCentralAdmissionVerifier(env,{
      listTargets:async()=>{queried++;return double;},
      verifySession:async(_client,record)=>{
        attested++;
        return record.deviceId===device && record.sessionId===sessionId;
      },
    });
    const jwt=await token();
    assert.equal((await verifier(await identity(jwt),base)).ok,true);
    const q=queried;
    assert.equal((await verifier(await identity(jwt),
      {...base,deviceId:secondDevice})).ok,false);
    assert.equal(queried,q,"unattested other PC must not query the target catalog");
    assert.equal(attested,2);
  });
});

test("device receipt requires signed exact client, device and NULL project",async()=>{
  await withIssuer(async()=>{
    let returnedOther=false,removed=false,calls=0;
    const handlers=createCanonicalCentralMcpReadHandlers(env,{
      listTargets:async()=>removed?{ok:true,targets:[]}:catalog(),
      getAction:async()=>{
        calls++;
        return actionRecord({
          project_id:returnedOther?projectId:null,
          capability:"computer.screen_info",
          result:{ok:true,geometry:"CONFIDENTIAL-PC-A"},
          status:"succeeded",finished_at:"2026-10-11T13:00:00Z",
        });
      },
    });
    const jwt=await token();
    const req=await identity(jwt);
    const targets=await handlers.targets(req);
    assert.equal(targets.status,200);
    assert.equal((await targets.json()).targets[0].device_id,device);
    const receipt=await handlers.getAction(req,requestId);
    assert.equal(receipt.status,200);
    assert.equal((await receipt.json()).action.result.geometry,"CONFIDENTIAL-PC-A");
    returnedOther=true;
    assert.equal((await handlers.getAction(req,requestId)).status,403);
    returnedOther=false;
    removed=true;
    assert.equal((await handlers.getAction(req,requestId)).status,403);
    assert.ok(calls>=2);
    assert.equal((await handlers.createAction(req)).status,403);
  });
});

test("mixed PC and project grants without persisted routing remain ambiguous",async()=>{
  await withIssuer(async()=>{
    const handlers=createCanonicalCentralMcpReadHandlers(env,{
      listTargets:async()=>catalog([group(),projectGroup()]),
      getAction:async()=>actionRecord({project_id:null,capability:"computer.windows"}),
    });
    assert.equal((await handlers.targets(await identity(await token()))).status,403);
  });
});

test("MCP Product session marker is required for a device-bound read turn",async()=>{
  await withIssuer(async()=>{
    const gateway=createCanonicalCentralSessionMcpGateway(env,base,{
      ...deps(catalog()),
      getAction:async()=>actionRecord({project_id:null,capability:"computer.windows"}),
    });
    const jwt=await token();
    async function send(marker:string|null){
      return gateway(new Request("https://central.example/mcp",{
        method:"POST",headers:{authorization:"Bearer "+jwt,"content-type":"application/json"},
        body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/call",
          params:{name:"ordax_targets",arguments:{},
            ...(marker!==null?{_meta:{"openai/session":marker}}:{})}}),
      }));
    }
    assert.notEqual((await send(null)).status,200);
    assert.notEqual((await send("chatgpt-another-session-20261011")).status,200);
    const yes=await send(sessionId);
    assert.equal(yes.status,200,JSON.stringify(await yes.clone().json()));
    assert.equal((await yes.json()).result.structuredContent.targets[0].device_id,device);
  });
});
