"""The only production entrypoint is the authenticated PostgreSQL MCP Worker."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "control-plane/cloudflare/src"
ENTRY = SRC / "product_mcp_entry.ts"
WRANGLER = ROOT / "control-plane/cloudflare/wrangler.mcp.toml"


class RetiredLegacyMcp(unittest.TestCase):
    def test_v3_worker_config_and_deploy_scripts_are_absent(self):
        for path in (
            SRC / "index.ts",
            ROOT / "control-plane/cloudflare/wrangler.toml",
            ROOT / "scripts/cloudflare/check_deploy_readiness.py",
            ROOT / "control-plane/cloudflare/d1-cutover-authority-map.json",
            ROOT / "scripts/verify_cloudflare_public.py",
            ROOT / "scripts/verify_cloudflare_v3.py",
        ):
            self.assertFalse(path.exists(), f"Retired Worker artifact restored: {path}")

    def test_canonical_worker_exclusively_mounts_authenticated_mcp(self):
        entry = ENTRY.read_text(encoding="utf-8")
        config = WRANGLER.read_text(encoding="utf-8")
        self.assertIn('main = "src/product_mcp_entry.ts"', config)
        self.assertIn('name = "ordax-mcp"', config)
        for required in ("handleOrdaxMcp", "createCanonicalProductMcpReadHandlers",
                         "trusted_operation_required", "resolveOrBootstrapAttestedSession"):
            self.assertIn(required, entry)
        for forbidden in ("D1Database", "env.DB", "operatorAuthorized(",
                          "ORDAX_OPERATOR_TOKEN", "legacy_mcp_retired"):
            self.assertNotIn(forbidden, entry)

    def test_retired_engineering_routes_are_not_mounted(self):
        entry = ENTRY.read_text(encoding="utf-8")
        for forbidden in ("/v3/device/ws", "/v3/device/recover-report", "/v3/jobs",
                          "/v3/artifacts/", "/v3/product-grants", "legacy_endpoint_retired"):
            self.assertNotIn(forbidden, entry)
        self.assertIn('error: "not_found"', entry)


if __name__ == "__main__":
    unittest.main()
