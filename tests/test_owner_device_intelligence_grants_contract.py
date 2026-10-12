from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HANDLER = ROOT / "control-plane" / "cloudflare" / "src" / "product_intelligence_grants.ts"
SCOPE = ROOT / "control-plane" / "cloudflare" / "src" / "product_action_scope.ts"
WORKER = ROOT / "control-plane" / "cloudflare" / "src" / "index.ts"
MCP = ROOT / "control-plane" / "cloudflare" / "src" / "mcp_http.ts"


class OwnerDeviceIntelligenceGrantContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.handler = HANDLER.read_text(encoding="utf-8")
        cls.scope = SCOPE.read_text(encoding="utf-8")
        cls.worker = WORKER.read_text(encoding="utf-8")
        cls.mcp = MCP.read_text(encoding="utf-8")

    def test_profile_is_fixed_to_two_read_actions(self) -> None:
        self.assertIn('APP_INTELLIGENCE_READ_MODE = "app-intelligence-read"', self.handler)
        self.assertIn('"intelligence.app_catalog"', self.scope)
        self.assertIn('"intelligence.app_detail"', self.scope)
        self.assertIn("APP_INTELLIGENCE_DEVICE_ACTIONS", self.scope)
        self.assertNotIn("computer.click", self.handler)
        self.assertNotIn("terminal.exec", self.handler)
        self.assertNotIn("git.command", self.handler)

    def test_owner_identity_and_device_are_server_derived(self) -> None:
        self.assertIn("authenticateProductRequest(request, env)", self.handler)
        self.assertIn("linkedDeviceForOwner(env, identity.subjectId, linkId)", self.handler)
        self.assertNotIn("body.subject_id", self.handler)
        self.assertNotIn("body.device_id", self.handler)
        self.assertNotIn("body.space_id", self.handler)
        self.assertNotIn("body.actions", self.handler)
        self.assertNotIn("body.projects", self.handler)

    def test_grant_has_no_project_scope_or_execution_authority(self) -> None:
        self.assertIn('const projectsJson = "[]";', self.handler)
        self.assertIn("projects: []", self.handler)
        self.assertIn("stableActions()", self.handler)
        self.assertNotIn("project_id", self.handler)

    def test_worker_retires_legacy_owner_endpoint(self) -> None:
        self.assertIn('"/v3/product/device-intelligence-grants"', self.worker)
        for handler in ("createOwnerDeviceIntelligenceGrant", "listOwnerDeviceIntelligenceGrants", "revokeOwnerDeviceIntelligenceGrant"):
            self.assertNotIn(handler, self.worker)
        self.assertIn('error: "legacy_product_grants_retired"', self.worker)

    def test_mcp_can_request_actions_but_cannot_mint_the_grant(self) -> None:
        self.assertIn('name: "app_intelligence_catalog"', self.mcp)
        self.assertIn('action: "intelligence.app_catalog"', self.mcp)
        self.assertIn('name: "app_intelligence_detail"', self.mcp)
        self.assertIn('action: "intelligence.app_detail"', self.mcp)
        self.assertIn('"app_intelligence_catalog"', self.mcp)
        self.assertIn('"app_intelligence_detail"', self.mcp)
        self.assertNotIn("createOwnerDeviceIntelligenceGrant", self.mcp)
        self.assertNotIn("revokeOwnerDeviceIntelligenceGrant", self.mcp)

    def test_mcp_hints_owner_surface_without_computer_profile(self) -> None:
        self.assertIn('profile: "app-intelligence-read"', self.mcp)
        self.assertIn(
            'APP_INTELLIGENCE_GRANT_SURFACE = "ORDAX Studio > Inteligência de aplicativos"',
            self.mcp,
        )


if __name__ == "__main__":
    unittest.main()
