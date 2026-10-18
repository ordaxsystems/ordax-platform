import { Client } from "pg";
import { isCanonicalUuid } from "./product_remote_grant_contract.ts";
import { ProductPostgresError, safePostgresFailure, type ProductPostgresEnv } from "./product_postgres_store.ts";

type DiscoveryResult = {
  ok: boolean;
  error?: string;
  devices_granted?: number;
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
): Promise<DiscoveryResult> {
  if (!isCanonicalUuid(ownerUserId) || !isCanonicalUuid(oauthClientId)) {
    throw new ProductPostgresError("product_mcp_client_identity_invalid", 400);
  }

  const postgresUrl = connectionString(env);
  const client: DiscoveryClient = dependencies.createClient
    ? dependencies.createClient(postgresUrl)
    : new Client({ connectionString: postgresUrl });
  let phase: "connect" | "query" | "decode" = "connect";
  try {
    await client.connect();
    phase = "query";
    const response = await client.query(
      "select public.ordax_ensure_product_mcp_target_discovery_v1($1::uuid, $2::uuid) as result",
      [ownerUserId, oauthClientId],
    );
    phase = "decode";
    const rows = response.rows;
    const result = (rows[0] as { result?: DiscoveryResult } | undefined)?.result;
    if (!result || typeof result !== "object" || typeof result.ok !== "boolean") {
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
