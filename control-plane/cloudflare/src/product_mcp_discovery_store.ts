import { openPostgresSession } from "./data_postgres_driver.ts";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { ProductPostgresError, safePostgresFailure, type ProductPostgresEnv } from "./product_postgres_store.ts";

type DiscoveryResult = {
  ok: boolean;
  error?: string;
  devices_granted?: number;
  phase?: "discovery" | "catalog";
  targets?: unknown[];
};

export type DiscoveryTargetsResult = DiscoveryResult & {
  phase: "discovery" | "catalog";
};

type DiscoveryClient = {
  connect(): Promise<void>;
  query(sql: string, params: string[]): Promise<{ rows: Array<{ result?: DiscoveryResult }> }>;
  end(): Promise<void>;
};

// Composition-only seam for deterministic tests; not request metadata or a
// second database authority. Production always uses the same pg Client.
type DiscoveryDependencies = Readonly<{
  createClient?: (connectionString: string) => DiscoveryClient;
}>;

// Both canonical functions run inside ONE SQL statement. MATERIALIZED forces
// discovery/consent to execute exactly once. CASE forbids enumeration when
// consent/grant materialization failed. No new grant writer or SQL authority.
export const DISCOVER_TARGETS_SQL = `
with discovery as materialized (
  select public.ordax_ensure_product_mcp_target_discovery_v1($1::uuid, $2::uuid) as result
)
select case
  when discovery.result->>'ok' = 'true' then
    public.ordax_list_product_targets_v1(
      $1::uuid, 'product-mcp'::text, $2::text
    ) || pg_catalog.jsonb_build_object('phase', 'catalog')
  else
    discovery.result || pg_catalog.jsonb_build_object('phase', 'discovery')
end as result
from discovery`;

function connectionString(env: ProductPostgresEnv): string {
  const raw = (env.POSTGRES?.connectionString ?? "").trim();
  if (!raw) throw new ProductPostgresError("product_postgres_unconfigured", 503);
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") throw new Error();
  } catch {
    throw new ProductPostgresError("product_postgres_unconfigured", 503);
  }
  return raw;
}

/**
 * Materialize target-discovery authority from the exact signed Product MCP
 * OAuth client. The PostgreSQL RPC independently verifies active OAuth consent
 * for this owner/client and can grant only product.target.read/read.
 */
export async function ensureProductMcpTargetDiscovery(
  env: ProductPostgresEnv,
  ownerUserId: string,
  oauthClientId: string,
  dependencies: DiscoveryDependencies = {},
  includeTargets = false,
): Promise<DiscoveryResult> {
  if (!isCanonicalUuid(ownerUserId) || !isCanonicalUuid(oauthClientId)) {
    throw new ProductPostgresError("product_mcp_client_identity_invalid", 400);
  }

  const postgresUrl = connectionString(env);
  const client: DiscoveryClient = dependencies.createClient
    ? dependencies.createClient(postgresUrl)
    : openPostgresSession(postgresUrl);
  let phase: "connect" | "query" | "decode" = "connect";
  try {
    await client.connect();
    phase = "query";
    const response = await client.query(
      includeTargets ? DISCOVER_TARGETS_SQL
        : "select public.ordax_ensure_product_mcp_target_discovery_v1($1::uuid, $2::uuid) as result",
      [ownerUserId, oauthClientId],
    );
    phase = "decode";
    const rows = response.rows;
    const result = (rows[0] as { result?: DiscoveryResult } | undefined)?.result;
    if (!result || typeof result !== "object" || typeof result.ok !== "boolean"
        || (includeTargets && (result.phase !== "catalog" && result.phase !== "discovery"))
        || (includeTargets && result.phase === "discovery" && result.ok !== false)) {
      throw new ProductPostgresError("product_postgres_invalid_response", 502);
    }
    return result;
  } catch (error) {
    if (error instanceof ProductPostgresError) throw error;
    // Never emit exception messages, SQL, URL, owner/client IDs or stack.
    // Reuse the canonical safe failure classifier rather than another logger.
    console.error(JSON.stringify({
      ...safePostgresFailure(error, "ordax_ensure_product_mcp_target_discovery_v1"), phase,
    }));
    throw new ProductPostgresError("product_postgres_unavailable", 503);
  } finally {
    try {
      await client.end();
    } catch {
      // Hyperdrive owns the upstream pool.
    }
  }
}

/** One Hyperdrive query to enforce OAuth consent, reconcile discovery grants,
 * and list the exact signed client's current targets. The source SQL functions
 * remain authoritative and are NOT copied into the Worker. */
export async function discoverAndListProductMcpTargets(
  env: ProductPostgresEnv,
  ownerUserId: string,
  oauthClientId: string,
  dependencies: DiscoveryDependencies = {},
): Promise<DiscoveryTargetsResult> {
  const result = await ensureProductMcpTargetDiscovery(
    env, ownerUserId, oauthClientId, dependencies, true,
  );
  return result as DiscoveryTargetsResult;
}
