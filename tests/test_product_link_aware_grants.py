"""Grant linkage is enforced in canonical Product PostgreSQL, not D1."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]

MCP=(ROOT/"control-plane/cloudflare/src/product_mcp_entry.ts").read_text("utf-8")
SELECTOR=(ROOT/"control-plane/cloudflare/src/product_relay_scope.ts").read_text("utf-8")
GRANT_SQL=(ROOT/"control-plane/supabase/migrations/20261007213500_central_durable_conversation_binding_v1.sql").read_text("utf-8").lower()
POSTGRES=(ROOT/"control-plane/cloudflare/src/product_postgres_store.ts").read_text("utf-8")

class ProductLinkAwareGrantContractTests(unittest.TestCase):
    def test_legacy_grant_creation_and_revocation_are_retired(self):
        for name in (
            "createProductGrant(", "createProductGrantFromLink(",
            "listProductGrants(", "resolveProductGrantForContext(",
            "resolveProductGrantAdmin(", "revokeProductGrant(",
            "persistProductGrant(", "recordProductAudit(",
        ):
            self.assertNotIn(name,MCP)
        self.assertFalse((ROOT/"control-plane/cloudflare/src/index.ts").exists())
        self.assertIn("createAttestedDeviceActionHandler",MCP)

    def test_legacy_endpoints_cannot_mint_or_revoke(self):
        self.assertNotIn("/v3/product-grants", MCP)
        self.assertNotIn('path === "/v3/product/audit"', MCP)
        self.assertNotIn("legacy_endpoint_retired", MCP)
        self.assertNotIn("env.DB", MCP)
        self.assertNotIn("operatorAuthorized(", MCP)

    def test_authority_uses_exact_space_and_oauth_client(self):
        for p in (
            'g.client_id=p_client_id',
            'g.device_id=p_device_id',
            'g.space_id is not distinct from p_space_id',
            'g.project_id is not distinct from p_project_id',
            "g.state='active'",
            "d.state='active'",
        ):
            self.assertIn(p,GRANT_SQL)
        self.assertIn("group.space_id !== null",SELECTOR)
        self.assertIn("group.project_id !== null",SELECTOR)

    def test_new_mcp_does_not_use_legacy_authority(self):
        self.assertIn('createCanonicalProductMcpReadHandlers',MCP)
        self.assertIn('product_postgres_store',MCP)
        self.assertNotIn('env.DB',MCP)
        self.assertNotIn('ordax_product_grants',MCP)
        self.assertIn('trusted_operation_required',MCP)

if __name__=="__main__":
    unittest.main()
