from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "control-plane/cloudflare/src/index.ts"
MCP = ROOT / "control-plane/cloudflare/src/mcp_http.ts"
SCOPE = ROOT / "control-plane/cloudflare/src/product_action_scope.ts"

class IntelligenceAuthorizationRetirementTests(unittest.TestCase):
    def test_intelligence_actions_remain_device_scoped(self):
        scope = SCOPE.read_text(encoding="utf-8")
        self.assertIn('"intelligence.app_catalog"', scope)
        self.assertIn('"intelligence.app_detail"', scope)
        self.assertIn("APP_INTELLIGENCE_DEVICE_ACTIONS", scope)

    def test_old_d1_grant_writers_are_absent_from_entrypoint(self):
        worker = WORKER.read_text(encoding="utf-8")
        self.assertIn('"/v3/product/device-intelligence-grants"', worker)
        self.assertIn('error: "legacy_product_grants_retired"', worker)
        for handler in ("createOwnerDeviceIntelligenceGrant", "listOwnerDeviceIntelligenceGrants", "revokeOwnerDeviceIntelligenceGrant"):
            self.assertNotIn(handler, worker)

    def test_mcp_does_not_mint_owner_grants(self):
        mcp = MCP.read_text(encoding="utf-8")
        self.assertIn('name: "app_intelligence_catalog"', mcp)
        self.assertIn('name: "app_intelligence_detail"', mcp)
        self.assertNotIn("createOwnerDeviceIntelligenceGrant", mcp)

if __name__ == "__main__":
    unittest.main()
