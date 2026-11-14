import test from "node:test";
import assert from "node:assert/strict";
import {
  PRODUCT_GITHUB_WEBHOOK_PATH,
  createProductGithubWebhookHandler,
  githubAuthorityRevocation,
  verifyGithubWebhookSignature,
} from "../cloudflare/src/product_github_webhook.ts";
import { isProductTrustedClientPath } from "../cloudflare/src/product_mcp_entry.ts";

const SECRET = "github-webhook-secret-" + "x".repeat(40);
const DELIVERY = "11111111-1111-4111-8111-111111111111";

async function signature(body: string, secret = SECRET) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const bytes = new Uint8Array(await crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(body),
  ));
  return "sha256=" + [...bytes].map(v => v.toString(16).padStart(2, "0")).join("");
}

async function request(
  event: string,
  payload: Record<string, unknown>,
  options: { secret?: string; delivery?: string; signature?: string } = {},
) {
  const body = JSON.stringify(payload);
  return new Request("https://mcp.ordax.com.br" + PRODUCT_GITHUB_WEBHOOK_PATH, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-github-event": event,
      "x-github-delivery": options.delivery ?? DELIVERY,
      "x-hub-signature-256": options.signature ?? await signature(
        body, options.secret ?? SECRET,
      ),
    },
    body,
  });
}

test("GitHub webhook signature verification uses raw HMAC SHA-256 bytes", async () => {
  const raw = new TextEncoder().encode('{"action":"suspend"}');
  const signed = await signature(new TextDecoder().decode(raw));
  assert.equal(await verifyGithubWebhookSignature(SECRET, raw, signed), true);
  assert.equal(await verifyGithubWebhookSignature(SECRET, raw, "sha256="+"0".repeat(64)), false);
  assert.equal(await verifyGithubWebhookSignature("short", raw, signed), false);
});

test("destructive GitHub provider events normalize only installation/repository identity", () => {
  assert.deepEqual(githubAuthorityRevocation("installation", {
    action:"suspend",installation:{id:12345},sender:{id:999},
  }), {
    event:"installation",action:"suspend",installationId:"12345",repositoryIds:[],
  });
  assert.deepEqual(githubAuthorityRevocation("installation_repositories", {
    action:"added",installation:{id:12345},
    repositories_removed:[{id:9,full_name:"drop/me"},{id:7},{id:9}],
    repositories_added:[{id:88}],
  }), {
    event:"installation_repositories",action:"added",
    installationId:"12345",repositoryIds:["7","9"],
  });
  assert.deepEqual(githubAuthorityRevocation("repository", {
    action:"renamed",installation:{id:12345},
    repository:{id:77,full_name:"new/name"},changes:{repository:{name:{from:"old"}}},
  }), {
    event:"repository",action:"renamed",installationId:"12345",repositoryIds:["77"],
  });
  for (const value of [
    ["installation",{action:"unsuspend",installation:{id:1}}],
    ["installation_repositories",{action:"added",installation:{id:1},repositories_removed:[]}],
    ["repository",{action:"edited",installation:{id:1},repository:{id:2}}],
    ["repository",{action:"deleted",repository:{id:2}}],
  ] as const) {
    assert.equal(githubAuthorityRevocation(value[0],value[1]),null);
  }
});

test("webhook stays invisible while independent release config is absent", async () => {
  let calls=0;
  const handler=createProductGithubWebhookHandler({},{
    applyRevocation:async()=>{calls+=1;throw Error("must not run");},
  });
  const response=await handler(await request("installation",{
    action:"deleted",installation:{id:123},
  }));
  assert.equal(response.status,404);
  assert.equal(calls,0);
  assert.equal(isProductTrustedClientPath(PRODUCT_GITHUB_WEBHOOK_PATH),false,
    "workers.dev trusted-client ingress must never expose provider webhook");
});

test("invalid signature fails before JSON authority or Postgres", async () => {
  let calls=0;
  const handler=createProductGithubWebhookHandler({
    PRODUCT_GITHUB_APP_WEBHOOK_ENABLED:"enabled",
    PRODUCT_GITHUB_APP_WEBHOOK_SECRET:SECRET,
  },{
    applyRevocation:async()=>{calls+=1;throw Error("must not run");},
  });
  const response=await handler(await request("installation",{
    action:"deleted",installation:{id:123},
  },{signature:"sha256="+"0".repeat(64)}));
  assert.equal(response.status,401);
  assert.equal(calls,0);
});

test("signed destructive delivery reaches exactly one normalized revocation RPC", async () => {
  const calls:any[]=[];
  const handler=createProductGithubWebhookHandler({
    PRODUCT_GITHUB_APP_WEBHOOK_ENABLED:"enabled",
    PRODUCT_GITHUB_APP_WEBHOOK_SECRET:SECRET,
  },{
    applyRevocation:async(_env,input)=>{
      calls.push(input);
      return {ok:true,replayed:false,delivery_id:DELIVERY,
        connection_count:1,binding_count:1,grant_count:2,action_count:1,intent_count:1};
    },
  });
  const response=await handler(await request("installation_repositories",{
    action:"removed",installation:{id:12345},
    repositories_removed:[{id:44},{id:42}],
    repositories_added:[],
    sender:{id:999},
  }));
  assert.equal(response.status,200);
  assert.deepEqual(await response.json(),{ok:true,accepted:true,replayed:false});
  assert.equal(calls.length,1);
  assert.deepEqual(calls[0].event,"installation_repositories");
  assert.deepEqual(calls[0].action,"removed");
  assert.deepEqual(calls[0].installationId,"12345");
  assert.deepEqual(calls[0].repositoryIds,["42","44"]);
  assert.match(calls[0].payloadSha256,/^[0-9a-f]{64}$/);
  assert.equal("sender" in calls[0],false);
  assert.equal("repository_full_name" in calls[0],false);
});

test("signed non-destructive and user-token events are acknowledged without database mutation", async () => {
  let calls=0;
  const handler=createProductGithubWebhookHandler({
    PRODUCT_GITHUB_APP_WEBHOOK_ENABLED:"enabled",
    PRODUCT_GITHUB_APP_WEBHOOK_SECRET:SECRET,
  },{
    applyRevocation:async()=>{calls+=1;throw Error("must not run");},
  });
  for(const [event,payload] of [
    ["installation",{action:"unsuspend",installation:{id:123}}],
    ["repository",{action:"unarchived",installation:{id:123},repository:{id:44}}],
    ["installation_repositories",{action:"added",installation:{id:123},
      repositories_added:[{id:44}],repositories_removed:[]}],
    ["github_app_authorization",{action:"revoked",sender:{id:999}}],
  ] as const){
    const response=await handler(await request(event,payload as any));
    assert.equal(response.status,202,event);
    assert.deepEqual(await response.json(),{ok:true,accepted:true,ignored:true});
  }
  assert.equal(calls,0);
});

test("ping is signature-verified but has no database side effect", async () => {
  let calls=0;
  const handler=createProductGithubWebhookHandler({
    PRODUCT_GITHUB_APP_WEBHOOK_ENABLED:"enabled",
    PRODUCT_GITHUB_APP_WEBHOOK_SECRET:SECRET,
  },{
    applyRevocation:async()=>{calls+=1;throw Error("must not run");},
  });
  const response=await handler(await request("ping",{zen:"Keep it logically awesome"}));
  assert.equal(response.status,200);
  assert.equal(calls,0);
});

test("database uncertainty never acknowledges a destructive webhook", async () => {
  const handler=createProductGithubWebhookHandler({
    PRODUCT_GITHUB_APP_WEBHOOK_ENABLED:"enabled",
    PRODUCT_GITHUB_APP_WEBHOOK_SECRET:SECRET,
  },{
    applyRevocation:async()=>{throw Error("postgres uncertain");},
  });
  const response=await handler(await request("repository",{
    action:"deleted",installation:{id:123},repository:{id:44},
  }));
  assert.equal(response.status,503);
  assert.deepEqual(await response.json(),{ok:false,error:"github_webhook_unavailable"});
});
