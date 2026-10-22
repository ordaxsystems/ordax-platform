from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "control-plane" / "cloudflare" / "src" / "product_action_scope.ts"
WORKER = ROOT / "control-plane" / "cloudflare" / "src" / "index.ts"
MCP = ROOT / "control-plane" / "cloudflare" / "src" / "mcp_http.ts"


def _quoted_computer_actions(text: str) -> set[str]:
    return set(re.findall(r'"(computer\.[a-z_]+)"', text))


def _mcp_computer_actions(text: str) -> set[str]:
    return set(re.findall(r'action:\s*"(computer\.[a-z_]+)"', text))


class ProductActionScopeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.scope = SCOPE.read_text(encoding="utf-8")
        cls.worker = WORKER.read_text(encoding="utf-8")
        cls.mcp = MCP.read_text(encoding="utf-8")

    def test_every_remote_computer_action_has_explicit_device_scope(self) -> None:
        scoped = _quoted_computer_actions(self.scope)
        published = _mcp_computer_actions(self.mcp)

        self.assertTrue(published, "MCP must publish typed computer actions")
        self.assertEqual(
            scoped,
            published,
            "device-scoped catalog must exactly match the published Computer MCP surface",
        )

    def test_worker_delegates_scope_catalog_without_duplicate_action_set(self) -> None:
        self.assertNotIn("const PRODUCT_PROJECT_ACTIONS", self.worker)
        self.assertNotIn("const PRODUCT_TYPED_ACTIONS_V2", self.worker)
        self.assertIn("handleProductDeviceTransport(request,env)", self.worker)
        self.assertTrue(_quoted_computer_actions(self.scope))

    def test_scope_catalog_does_not_smuggle_shell_or_project_authority(self) -> None:
        scoped = _quoted_computer_actions(self.scope)
        self.assertNotIn("terminal.exec", scoped)
        self.assertNotIn("git.command", scoped)
        self.assertNotIn("process.start", scoped)
        self.assertTrue(all(action.startswith("computer.") for action in scoped))

    def test_app_intelligence_scope_is_explicit_and_separate_from_computer(self) -> None:
        self.assertIn("APP_INTELLIGENCE_DEVICE_ACTIONS", self.scope)
        self.assertIn('"intelligence.app_catalog"', self.scope)
        self.assertIn('"intelligence.app_detail"', self.scope)
        self.assertIn("COMPUTER_DEVICE_ACTIONS", self.scope)
        self.assertIn("...COMPUTER_DEVICE_ACTIONS", self.scope)
        self.assertIn("...APP_INTELLIGENCE_DEVICE_ACTIONS", self.scope)

    def test_binding_contract_forbids_synthetic_project_on_device_actions(self) -> None:
        self.assertIn('return scope === "device" ? project === null : project !== null;', self.scope)
        self.assertIn('if (DEVICE_SCOPED_ACTIONS.has(action)) return "device";', self.scope)

    def test_scope_is_explicit_not_prefix_authority(self) -> None:
        self.assertNotIn('action.startsWith("computer.")', self.scope)
        self.assertIn("new Set<string>([", self.scope)


class ProjectWorkspaceGrantBoundaryTests(unittest.TestCase):
    """The M1 projection must not become a grant writer or an MCP tool."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = (ROOT / "control-plane/cloudflare/src/project_workspace_grant_contract.ts").read_text(
            encoding="utf-8"
        )
        cls.profiles = (ROOT / "control-plane/cloudflare/src/product_owner_grant_profiles.ts").read_text(
            encoding="utf-8"
        )
        cls.worker = WORKER.read_text(encoding="utf-8")
        cls.mcp = MCP.read_text(encoding="utf-8")

    def test_project_scoped_resource_contract_is_strictly_projection_only(self):
        self.assertIn("projectWorkspaceGrantProjection(", self.contract)
        self.assertIn('r.issued_by !== "trusted-runtime-picker"', self.contract)
        self.assertIn('r.allowed_actions[0] !== "read"', self.contract)
        self.assertIn("r.revoked_at !== null", self.contract)
        self.assertIn("expiry <= nowMs", self.contract)
        self.assertIn("expiry > issued + 24 * 60 * 60 * 1000", self.contract)
        self.assertIn("issued > nowMs", self.contract)
        for field in (
            "owner_user_id", "space_id", "project_id", "lab_project_id",
            "actor_id", "client_id", "workspace_session_id", "device_id",
            "resource_id",
        ):
            self.assertIn("r." + field, self.contract)

    def test_no_live_resource_grant_writer_or_implicit_computer_profile(self):
        self.assertNotIn("projectWorkspaceGrantProjection", self.worker)
        self.assertNotIn("projectWorkspaceGrantProjection", self.mcp)
        self.assertNotIn("workspace.snapshot", self.profiles)
        self.assertNotIn("workspace.verify_binding", self.profiles)
        self.assertNotIn("projectWorkspaceGrantProjection", self.profiles)


if __name__ == "__main__":
    unittest.main()
