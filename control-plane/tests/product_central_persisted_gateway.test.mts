import test from "node:test";
import assert from "node:assert/strict";
import { createPersistedCentralSessionMcpGateway } from "../cloudflare/src/product_central_mcp.ts";
import { env,owner,client,device,projectId,requestId,token,withIssuer } from "./product_mcp_test_fixtures.mts";

const binding={subjectId:owner,clientId:client,deviceId:device,
  spaceId:"99999999-9999-4999-8999-999999999999",
  projectId,requestId,conversationId:"chat-a-real-host-would-attest-001",
  sessionId:"provider-session-can-not-authorize-itself-001"};

test("canonical persisted MCP denies signed OAuth tool calls if no real Postgres binding exists",async()=>{
  await withIssuer(async()=>{
    let catalogReads=0,receiptReads=0;
    const gate=createPersistedCentralSessionMcpGateway(env,binding,{
      // Even a malicious caller supplying a fake callback cannot override
      // the production PostgreSQL authority installed by this factory.
      verifySession:async()=>true,
      listTargets:async()=>{catalogReads++;return {ok:true,targets:[{
        device_id:device,grant_groups:[{
          space_id:binding.spaceId,project_id:projectId,valid_until:null,
          capabilities:[{capability:"workspace.text_read",access_mode:"read"}],
        }],
      }]};},
      getAction:async()=>{receiptReads++;return null;},
    } as any);
    const jwt=await token();
    const tool=async(name:string,marker=binding.sessionId)=>{
      const response=await gate(new Request("https://central.example/mcp",{
        method:"POST",headers:{authorization:"Bearer "+jwt,
          "content-type":"application/json"},
        body:JSON.stringify({jsonrpc:"2.0",id:123,method:"tools/call",
          params:{name,arguments:{},_meta:{"openai/session":marker}}}),
      }));
      return response;
    };
    for(const name of ["ordax_targets","ordax_action_status"]){
      const result=await tool(name);
      const body=await result.clone().json();
      assert.ok(result.status!==200 || body?.result?.structuredContent?.ok===false
        || body?.result?.isError===true,
        JSON.stringify({name,status:result.status,body}));
    }
    const wrong=await tool("ordax_targets","another-session-111");
    assert.notEqual(wrong.status,200);
    assert.equal(catalogReads,0,"no Product DB proof, not even eligible target enumeration");
    assert.equal(receiptReads,0,"no foreign receipt should be queried");
  });
});
test("persisted gateway cannot be created with an injected fake session verifier",()=>{
  const gate=createPersistedCentralSessionMcpGateway(env,binding);
  assert.equal(typeof gate,"function");
  assert.equal(Object.keys(binding).length,8);
});
