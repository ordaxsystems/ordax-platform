"""The canonical Worker cannot re-expose D1 engineering or MCP authority."""
from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKER = (ROOT/"control-plane/cloudflare/src/index.ts").read_text("utf-8")
NEW = (ROOT/"control-plane/cloudflare/src/product_mcp_entry.ts").read_text("utf-8")
D1_MAP = json.loads((ROOT/"control-plane/cloudflare/d1-cutover-authority-map.json").read_text("utf-8"))


class RetiredLegacyMcp(unittest.TestCase):
    def test_main_worker_never_mounts_mcp_or_d1(self):
        self.assertNotIn("handleOrdaxMcp(request", WORKER)
        self.assertNotIn("env.DB", WORKER)
        self.assertIn('path === "/mcp"', WORKER)
        self.assertIn('error:"legacy_mcp_retired"', WORKER)
        self.assertNotIn("async function createProductAction(", WORKER)

    def test_legacy_write_authority_removed(self):
        self.assertNotIn("return createProductAction(", WORKER)
        self.assertIn('error:"legacy_product_action_retired"', WORKER)
        self.assertEqual(D1_MAP["legacy_source_callsite_ceilings"]["index.ts"], 0)

    def test_new_mcp_remains_separate(self):
        self.assertNotIn("src/index.ts", NEW)
        self.assertNotIn("D1Database", NEW)
        self.assertIn("createCanonicalProductMcpReadHandlers", NEW)
        self.assertIn("trusted_operation_required", NEW)
        self.assertIn("supports_remote_actions: false", NEW)

    def test_explicit_legacy_routes_fail_closed(self):
        for route in ("/mcp", "/v3/device/ws", "/v3/device/recover-report",
                      "/v3/jobs", "/v3/artifacts/"):
            self.assertIn(route, WORKER)
        self.assertIn("legacy_endpoint_retired", WORKER)
        self.assertIn("410", WORKER)


if __name__ == "__main__":
    unittest.main()
