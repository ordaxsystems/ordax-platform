/** Signed Owner usage read: informational MCP aggregates, never chargeable data. */
import { authenticateProductRequest, type ProductAuthEnv } from "./product_auth.ts";
import {
  readProductMcpUsage,
  productMcpUsageMeterEnabled,
  ProductPostgresError,
  type ProductPostgresEnv,
} from "./product_postgres_store.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";

type Env = ProductAuthEnv & ProductPostgresEnv;
type UsageReader = typeof readProductMcpUsage;
export const PRODUCT_OWNER_MCP_USAGE_PATH = "/v3/product/usage";
const MONTH = /^\d{4}-(?:0[1-9]|1[0-2])-01$/;
const TOOL = /^[a-z][a-z0-9._-]{1,95}$/;

export function validOwnerMcpUsage(value: unknown): value is {
  ok: true;
  schema: "ordax.product-mcp-usage/1";
  observed_only: true;
  billable: false;
  current_month: string;
  previous_month: string;
  entries: Array<{ month: string; tool_name: string; tool_calls: number }>;
} {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  if (v.ok !== true || v.schema !== "ordax.product-mcp-usage/1"
      || v.observed_only !== true || v.billable !== false
      || typeof v.current_month !== "string" || !MONTH.test(v.current_month)
      || typeof v.previous_month !== "string" || !MONTH.test(v.previous_month)
      || !Array.isArray(v.entries) || v.entries.length > 256) return false;
  const seen = new Set<string>();
  return v.entries.every((entry: unknown) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
    const row = entry as Record<string, unknown>;
    if (row.month !== v.current_month && row.month !== v.previous_month) return false;
    if (typeof row.tool_name !== "string" || !TOOL.test(row.tool_name)
        || !Number.isSafeInteger(row.tool_calls) || (row.tool_calls as number) < 0) return false;
    const key = row.month + ":" + row.tool_name;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

const respond = (value: unknown, status = 200): Response => Response.json(value, {
  status,
  headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
});

/** Only the signed JWT subject selects rows; no user supplied account ID. */
export async function handleProductOwnerMcpUsageRead(
  request: Request,
  env: Env,
  read: UsageReader = readProductMcpUsage,
): Promise<Response> {
  if (request.method !== "GET") return respond({ ok: false, error: "method_not_allowed" }, 405);
  const identity = await authenticateProductRequest(request, env);
  if (!identity.ok) return respond({ ok: false, error: identity.error }, identity.status);
  if (identity.role !== "authenticated" || !isCanonicalUuid(identity.subjectId)) {
    return respond({ ok: false, error: "product_owner_identity_invalid" }, 403);
  }
  try {
    const usage = await read(env, identity.subjectId);
    if (usage?.ok === false && usage.error === "product_owner_auth_ineligible") {
      return respond({ ok: false, error: "product_owner_auth_ineligible" }, 403);
    }
    if (!validOwnerMcpUsage(usage)) {
      return respond({ ok: false, error: "product_mcp_usage_invalid_response" }, 502);
    }
    return respond({ ...usage,
      collection_active_now: productMcpUsageMeterEnabled(env),
      coverage: "partial_observational",
      quota: null,
      charge: null,
    });
  } catch (error) {
    return respond({ ok: false, error: error instanceof ProductPostgresError
      && error.code === "product_postgres_unconfigured"
      ? "product_postgres_unconfigured" : "product_mcp_usage_unavailable" }, 503);
  }
}
