import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const migration = readFileSync(
  new URL("../supabase/migrations/20261015193000_product_mcp_target_discovery_grant_v1.sql", import.meta.url),
  "utf8",
);

test("MCP target discovery grant is consent-bound and read-only", () => {
  assert.match(migration, /auth\.oauth_clients/);
  assert.match(migration, /auth\.oauth_consents/);
  assert.match(migration, /consent\.user_id = p_owner_user_id/);
  assert.match(migration, /consent\.revoked_at is null/);
  assert.match(migration, /c\.deleted_at is null/);
  assert.match(migration, /c\.client_type::text = 'public'/);
  assert.match(migration, /'product-mcp'/);
  assert.match(migration, /'mcp-discovery'/);
  assert.match(migration, /array\['product\.target\.read'\]::text\[\]/);
  assert.match(migration, /array\['read'\]::text\[\]/);
  assert.doesNotMatch(migration, /array\[[^\]]*'write'/);
  assert.doesNotMatch(migration, /computer\.|terminal\.|workspace\.|git\.|browser\.|process\./);
});

test("grant mutation remains PostgreSQL canonical and edge-executor only", () => {
  assert.match(migration, /public\.ordax_replace_remote_grant_group_v1/);
  assert.match(migration, /revoke all on function public\.ordax_authorize_product_mcp_target_discovery_v1[\s\S]*from service_role;/);
  assert.match(migration, /grant execute on function public\.ordax_authorize_product_mcp_target_discovery_v1[\s\S]*to ordax_edge_executor;/);
  assert.doesNotMatch(migration, /insert\s+into\s+public\.ordax_remote_capability_grants/i);
});
