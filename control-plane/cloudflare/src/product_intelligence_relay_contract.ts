import { isCanonicalUuid } from "./product_remote_grant_contract.ts";

/**
 * Transport compatibility boundary for the OS-owned `ordax.intelligence/1` request.
 *
 * This module is deliberately not an Intelligence implementation and is not a
 * Product action allowlist. It only validates the already-canonical Web envelope
 * and binds it to server-side identity/target/context provenance supplied by a
 * trusted host. Provider selection, model routing, Memory and inference remain
 * owned by ordax-os.
 *
 * Keep the request bounds aligned with `ordax.intelligence/1`. A schema/bounds
 * change in ordax-os requires an explicit compatibility review here; do not add
 * permissive fallback parsing.
 */
export const WEB_INTELLIGENCE_REMOTE_REQUEST_SCHEMA =
  "ordax.web-intelligence-remote-request/1";
export const PRODUCT_INTELLIGENCE_RELAY_BINDING_SCHEMA =
  "ordax.product-intelligence-relay-binding/1";

const INTELLIGENCE_MAX_PROMPT_CHARS = 32_000;
const INTELLIGENCE_MAX_CONTEXT_ITEMS = 16;
const INTELLIGENCE_MAX_CONTEXT_ITEM_CHARS = 8_192;
const INTELLIGENCE_MAX_CONTEXT_TOTAL_CHARS = 65_536;
const INTELLIGENCE_MAX_PROVENANCE_CHARS = 512;
const INTELLIGENCE_MAX_ID_CHARS = 160;
const INTELLIGENCE_MAX_TOKENS = 2_048;
const INTENTS = new Set(["ask", "explain", "summarize", "diagnose"]);
const CONTEXT_SCOPES = new Set(["user", "workspace", "system", "document"]);
const CLIENT_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]+$/;

type Json = Record<string, unknown>;

export type TrustedIntelligenceRelayBinding = Readonly<{
  /** Verified Product subject. Never accepted from model/tool JSON as authority. */
  subjectId: string;
  /** Exact authenticated client/transport identity. */
  clientId: string;
  /** Device selected by trusted Product/session authority. */
  deviceId: string;
  /** Authorized presentation context. Space-only is valid; project requires Space. */
  spaceId: string | null;
  projectId: string | null;
  /** Persisted once by the trusted host for future idempotent dispatch. */
  operationId: string;
}>;

function record(value: unknown): Json | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Json
    : null;
}

function exactKeys(value: Json, keys: readonly string[]): boolean {
  return Object.keys(value).sort().join(",") === [...keys].sort().join(",");
}

function boundedText(value: unknown, maximum: number): string | null {
  if (typeof value !== "string" || value.includes("\0")) return null;
  const normalized = value.trim();
  return normalized && normalized.length <= maximum ? normalized : null;
}

function nullableCanonicalUuid(value: unknown): string | null | undefined {
  if (value === null) return null;
  return isCanonicalUuid(value) ? value.toLowerCase() : undefined;
}

function canonicalClientId(value: unknown): string | null {
  if (typeof value !== "string" || value.length < 8 || value.length > 160
      || !CLIENT_RE.test(value)) return null;
  return value;
}

function canonicalLocation(value: unknown): Readonly<{
  subjectId: string;
  targetDeviceId: string;
  spaceId: string | null;
  projectId: string | null;
}> | null {
  const input = record(value);
  if (!input || !exactKeys(input,
    ["subjectId", "targetDeviceId", "spaceId", "projectId"])) return null;
  if (!isCanonicalUuid(input.subjectId) || !isCanonicalUuid(input.targetDeviceId)) return null;
  const spaceId = nullableCanonicalUuid(input.spaceId);
  const projectId = nullableCanonicalUuid(input.projectId);
  if (spaceId === undefined || projectId === undefined) return null;
  if (projectId !== null && spaceId === null) return null;
  return Object.freeze({
    subjectId: input.subjectId.toLowerCase(),
    targetDeviceId: input.targetDeviceId.toLowerCase(),
    spaceId,
    projectId,
  });
}

function canonicalRequestContext(value: unknown): readonly Readonly<{
  id: string;
  scope: string;
  text: string;
  provenance: string;
}>[] | null {
  if (!Array.isArray(value) || value.length > INTELLIGENCE_MAX_CONTEXT_ITEMS) return null;
  let total = 0;
  const normalized: Array<Readonly<{
    id: string;
    scope: string;
    text: string;
    provenance: string;
  }>> = [];
  for (const raw of value) {
    const item = record(raw);
    if (!item || !exactKeys(item, ["id", "scope", "text", "provenance"])
      || typeof item.scope !== "string" || !CONTEXT_SCOPES.has(item.scope)) return null;
    const id = boundedText(item.id, INTELLIGENCE_MAX_ID_CHARS);
    const text = boundedText(item.text, INTELLIGENCE_MAX_CONTEXT_ITEM_CHARS);
    const provenance = boundedText(item.provenance, INTELLIGENCE_MAX_PROVENANCE_CHARS);
    if (!id || !text || !provenance) return null;
    total += text.length;
    if (total > INTELLIGENCE_MAX_CONTEXT_TOTAL_CHARS) return null;
    normalized.push(Object.freeze({ id, scope: item.scope, text, provenance }));
  }
  return Object.freeze(normalized);
}

function canonicalIntelligenceRequest(value: unknown): Readonly<{
  intent: string;
  prompt: string;
  context: readonly Readonly<{ id: string; scope: string; text: string; provenance: string }>[];
  maxTokens: number;
}> | null {
  const input = record(value);
  if (!input || !exactKeys(input, ["intent", "prompt", "context", "maxTokens"])
    || typeof input.intent !== "string" || !INTENTS.has(input.intent)) return null;
  const prompt = boundedText(input.prompt, INTELLIGENCE_MAX_PROMPT_CHARS);
  const context = canonicalRequestContext(input.context);
  if (!prompt || context === null || !Number.isSafeInteger(input.maxTokens)
    || (input.maxTokens as number) < 1 || (input.maxTokens as number) > INTELLIGENCE_MAX_TOKENS) return null;
  return Object.freeze({
    intent: input.intent,
    prompt,
    context,
    maxTokens: input.maxTokens as number,
  });
}

export function validateTrustedIntelligenceRelayBinding(
  value: unknown,
): TrustedIntelligenceRelayBinding | null {
  const input = record(value);
  if (!input || !exactKeys(input,
    ["subjectId", "clientId", "deviceId", "spaceId", "projectId", "operationId"])) return null;
  if (!isCanonicalUuid(input.subjectId) || !isCanonicalUuid(input.deviceId)
    || !isCanonicalUuid(input.operationId)) return null;
  const clientId = canonicalClientId(input.clientId);
  const spaceId = nullableCanonicalUuid(input.spaceId);
  const projectId = nullableCanonicalUuid(input.projectId);
  if (!clientId || spaceId === undefined || projectId === undefined
    || (projectId !== null && spaceId === null)) return null;
  return Object.freeze({
    subjectId: input.subjectId.toLowerCase(),
    clientId,
    deviceId: input.deviceId.toLowerCase(),
    spaceId,
    projectId,
    operationId: input.operationId.toLowerCase(),
  });
}

/**
 * Validate and bind an untrusted Web Intelligence envelope to trusted transport
 * provenance. Returning null means the request must not be queued or forwarded.
 *
 * This function does not grant access, enqueue an action, select a provider or
 * execute inference. A future transport owner must resolve the trusted binding
 * from canonical Product/session authority before calling it.
 */
export function bindCanonicalIntelligenceRelayEnvelope(
  value: unknown,
  trustedValue: unknown,
): Readonly<{
  schema: typeof PRODUCT_INTELLIGENCE_RELAY_BINDING_SCHEMA;
  clientId: string;
  operationId: string;
  context: Readonly<{
    subjectId: string;
    targetDeviceId: string;
    spaceId: string | null;
    projectId: string | null;
  }>;
  request: NonNullable<ReturnType<typeof canonicalIntelligenceRequest>>;
}> | null {
  const envelope = record(value);
  const trusted = validateTrustedIntelligenceRelayBinding(trustedValue);
  if (!envelope || !trusted || !exactKeys(envelope, ["schema", "context", "request"])
    || envelope.schema !== WEB_INTELLIGENCE_REMOTE_REQUEST_SCHEMA) return null;
  const context = canonicalLocation(envelope.context);
  const request = canonicalIntelligenceRequest(envelope.request);
  if (!context || !request
    || context.subjectId !== trusted.subjectId
    || context.targetDeviceId !== trusted.deviceId
    || context.spaceId !== trusted.spaceId
    || context.projectId !== trusted.projectId) return null;
  return Object.freeze({
    schema: PRODUCT_INTELLIGENCE_RELAY_BINDING_SCHEMA,
    clientId: trusted.clientId,
    operationId: trusted.operationId,
    context,
    request,
  });
}
