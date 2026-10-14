import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  PRODUCT_INTELLIGENCE_RELAY_BINDING_SCHEMA,
  WEB_INTELLIGENCE_REMOTE_REQUEST_SCHEMA,
  bindCanonicalIntelligenceRelayEnvelope,
  validateTrustedIntelligenceRelayBinding,
} from "../cloudflare/src/product_intelligence_relay_contract.ts";

const subjectId = "11111111-1111-4111-8111-111111111111";
const deviceId = "22222222-2222-4222-8222-222222222222";
const spaceId = "33333333-3333-4333-8333-333333333333";
const projectId = "44444444-4444-4444-8444-444444444444";
const clientId = "ordax-web:test-client";

const request = (overrides: Record<string, unknown> = {}) => ({
  intent: "ask",
  prompt: "Explique o estado atual.",
  context: [],
  maxTokens: 512,
  ...overrides,
});

const binding = (overrides: Record<string, unknown> = {}) => ({
  subjectId,
  clientId,
  deviceId,
  spaceId,
  projectId,
  operationId: randomUUID(),
  ...overrides,
});

const envelope = (
  contextOverrides: Record<string, unknown> = {},
  requestOverrides: Record<string, unknown> = {},
  envelopeOverrides: Record<string, unknown> = {},
) => ({
  schema: WEB_INTELLIGENCE_REMOTE_REQUEST_SCHEMA,
  context: { subjectId, targetDeviceId: deviceId, spaceId, projectId, ...contextOverrides },
  request: request(requestOverrides),
  ...envelopeOverrides,
});

test("canonical binding accepts global, Space and Space+Project context without turning context into grant scope", () => {
  for (const pair of [
    { spaceId: null, projectId: null },
    { spaceId, projectId: null },
    { spaceId, projectId },
  ]) {
    const trusted = binding(pair);
    const value = envelope(pair);
    const bound = bindCanonicalIntelligenceRelayEnvelope(value, trusted);
    assert.ok(bound, JSON.stringify(pair));
    assert.equal(bound.schema, PRODUCT_INTELLIGENCE_RELAY_BINDING_SCHEMA);
    assert.equal(bound.clientId, clientId);
    assert.equal(bound.operationId, trusted.operationId.toLowerCase());
    assert.deepEqual(bound.context, {
      subjectId,
      targetDeviceId: deviceId,
      spaceId: pair.spaceId,
      projectId: pair.projectId,
    });
    assert.equal(bound.request.prompt, "Explique o estado atual.");
  }
});

test("project context without Space fails closed before any future dispatch", () => {
  assert.equal(validateTrustedIntelligenceRelayBinding(binding({ spaceId: null })), null);
  assert.equal(bindCanonicalIntelligenceRelayEnvelope(
    envelope({ spaceId: null }), binding({ spaceId: null })), null);
  assert.ok(bindCanonicalIntelligenceRelayEnvelope(
    envelope({ projectId: null }), binding({ projectId: null })));
});

test("untrusted envelope cannot retarget subject, device, Space or project", () => {
  const trusted = binding();
  for (const changed of [
    { subjectId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
    { targetDeviceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" },
    { spaceId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc" },
    { projectId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" },
  ]) assert.equal(bindCanonicalIntelligenceRelayEnvelope(envelope(changed), trusted), null);
});

test("model payload cannot supply client, operation, provider, credentials or authority fields", () => {
  const trusted = binding();
  for (const value of [
    envelope({}, {}, { clientId }),
    envelope({}, {}, { operationId: trusted.operationId }),
    envelope({}, { provider: "openai" }),
    envelope({}, { apiKey: "secret" }),
    envelope({}, { authority: "execute" }),
    envelope({}, { toolExecution: true }),
    envelope({ clientId }),
    envelope({ operationId: trusted.operationId }),
  ]) assert.equal(bindCanonicalIntelligenceRelayEnvelope(value, trusted), null);

  const accepted = bindCanonicalIntelligenceRelayEnvelope(envelope(), trusted);
  assert.ok(accepted);
  assert.equal(accepted.clientId, clientId);
  assert.equal(accepted.operationId, trusted.operationId.toLowerCase());
  assert.ok(!("provider" in accepted.request));
});

test("canonical Intelligence request bounds are enforced at the transport edge", () => {
  const trusted = binding();
  for (const value of [
    envelope({}, { intent: "execute" }),
    envelope({}, { prompt: "x".repeat(32_001) }),
    envelope({}, { maxTokens: 0 }),
    envelope({}, { maxTokens: 2_049 }),
    envelope({}, { maxTokens: 12.5 }),
    envelope({}, { context: Array.from({ length: 17 }, (_, i) => ({
      id: `ctx-${i}`, scope: "user", text: "x", provenance: "test",
    })) }),
    envelope({}, { context: [{ id: "ctx", scope: "tool", text: "x", provenance: "test" }] }),
    envelope({}, { context: [{ id: "ctx", scope: "user", text: "x", provenance: "test", authority: "execute" }] }),
    envelope({}, { context: [{ id: "ctx", scope: "user", text: "x".repeat(8_193), provenance: "test" }] }),
  ]) assert.equal(bindCanonicalIntelligenceRelayEnvelope(value, trusted), null);

  const totalTooLarge = envelope({}, { context: Array.from({ length: 9 }, (_, i) => ({
    id: `ctx-${i}`, scope: "document", text: "x".repeat(8_000), provenance: "verified-test",
  })) });
  assert.equal(bindCanonicalIntelligenceRelayEnvelope(totalTooLarge, trusted), null);
});

test("trusted binding itself is exact, bounded and cannot infer authority", () => {
  for (const value of [
    null,
    binding({ subjectId: "not-a-uuid" }),
    binding({ deviceId: "not-a-uuid" }),
    binding({ operationId: "not-a-uuid" }),
    binding({ clientId: "short" }),
    binding({ clientId: "bad/client" }),
    { ...binding(), grantId: randomUUID() },
  ]) assert.equal(validateTrustedIntelligenceRelayBinding(value), null);
});

test("source-only contract is not advertised as a Product action or public Worker route", async () => {
  const [scope, relayScope, worker, mcp] = await Promise.all([
    readFile(new URL("../cloudflare/src/product_action_scope.ts", import.meta.url), "utf8"),
    readFile(new URL("../cloudflare/src/product_relay_scope.ts", import.meta.url), "utf8"),
    readFile(new URL("../cloudflare/src/index.ts", import.meta.url), "utf8"),
    readFile(new URL("../cloudflare/src/mcp_http.ts", import.meta.url), "utf8"),
  ]);
  for (const source of [scope, relayScope, worker, mcp]) {
    assert.doesNotMatch(source, /intelligence\.respond/);
    assert.doesNotMatch(source, /product_intelligence_relay_contract/);
  }
});
