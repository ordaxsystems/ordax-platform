from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "control-plane" / "cloudflare" / "src" / "index.ts"
MCP = ROOT / "control-plane" / "cloudflare" / "src" / "mcp_http.ts"
SCOPE = ROOT / "control-plane" / "cloudflare" / "src" / "product_action_scope.ts"
OWNER_GRANTS = ROOT / "control-plane" / "cloudflare" / "src" / "product_device_grants.ts"


def _quoted_actions(text: str) -> set[str]:
    return set(re.findall(r'"([a-z][a-z0-9_.-]+)"', text))


def _set_body(text: str, marker: str) -> str:
    start = text.index(marker) + len(marker)
    return text[start:].split("]);", 1)[0]


class CloudflareDeviceScopeWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.worker = WORKER.read_text(encoding="utf-8")
        cls.mcp = MCP.read_text(encoding="utf-8")
        cls.scope = SCOPE.read_text(encoding="utf-8")
        cls.owner_grants = OWNER_GRANTS.read_text(encoding="utf-8")
        cls.computer_device_actions = _quoted_actions(
            _set_body(cls.scope, "export const COMPUTER_DEVICE_ACTIONS = new Set<string>([")
        )
        cls.app_intelligence_device_actions = _quoted_actions(
            _set_body(cls.scope, "export const APP_INTELLIGENCE_DEVICE_ACTIONS = new Set<string>([")
        )
        cls.device_actions = (
            cls.computer_device_actions
            | cls.app_intelligence_device_actions
        )

    def test_worker_consumes_canonical_device_scope_ssot(self) -> None:
        self.assertIn('from "./product_action_scope"', self.worker)
        self.assertIn("DEVICE_SCOPED_ACTIONS", self.worker)
        self.assertIn("projectBindingMatchesScope", self.worker)

    def test_device_scope_union_is_explicit(self) -> None:
        self.assertTrue(self.computer_device_actions)
        self.assertEqual(
            self.app_intelligence_device_actions,
            {"intelligence.app_catalog", "intelligence.app_detail"},
        )
        self.assertIn("...COMPUTER_DEVICE_ACTIONS", self.scope)
        self.assertIn("...APP_INTELLIGENCE_DEVICE_ACTIONS", self.scope)

    def test_device_computer_actions_are_not_project_scoped_in_worker(self) -> None:
        project_block = _set_body(
            self.worker, "const PRODUCT_PROJECT_ACTIONS = new Set(["
        )
        project_actions = _quoted_actions(project_block)
        overlap = sorted(self.device_actions & project_actions)
        self.assertEqual(overlap, [], f"device actions still project-scoped: {overlap}")

    def test_owner_device_grant_handlers_are_routed_but_not_exposed_to_mcp(self) -> None:
        self.assertIn('from "./product_device_grants"', self.worker)
        self.assertIn("createOwnerDeviceComputerGrant(request, env)", self.worker)
        self.assertIn("listOwnerDeviceComputerGrants(request, env)", self.worker)
        self.assertIn("revokeOwnerDeviceComputerGrant(request, env", self.worker)
        self.assertNotIn("createOwnerDeviceComputerGrant", self.mcp)
        self.assertNotIn("listOwnerDeviceComputerGrants", self.mcp)
        self.assertNotIn("revokeOwnerDeviceComputerGrant", self.mcp)

    def test_cloudflare_mcp_device_actions_do_not_require_project(self) -> None:
        for action in sorted(self.device_actions):
            marker = f'action: "{action}"'
            self.assertIn(marker, self.mcp, f"missing MCP action {action}")
            line = next(line for line in self.mcp.splitlines() if marker in line)
            self.assertNotIn("projectRequired: true", line, action)
            self.assertNotIn("project: PROJECT", line, action)
            required_match = re.search(r"required: \[([^\]]*)\]", line)
            if required_match:
                self.assertNotIn('"project"', required_match.group(1), action)

    def test_project_owned_actions_keep_project_scope(self) -> None:
        for action in ("terminal.exec", "git.command", "browser.click", "process.start"):
            marker = f'action: "{action}"'
            line = next(line for line in self.mcp.splitlines() if marker in line)
            self.assertIn("projectRequired: true", line, action)
            self.assertIn("project: PROJECT", line, action)

    def test_scope_binding_forbids_synthetic_projects(self) -> None:
        self.assertIn(
            'return scope === "device" ? project === null : project !== null;',
            self.scope,
        )
        self.assertIn("projectBindingMatchesScope", self.worker)

    def test_device_scope_uses_distinct_product_postgres_grants(self) -> None:
        canonical = (ROOT / "control-plane/cloudflare/src/product_relay_scope.ts").read_text(
            encoding="utf-8"
        )
        self.assertIn("selectCanonicalRelayDeviceScope", canonical)
        self.assertIn("selectCanonicalRelayProjectScope", canonical)
        self.assertIn("group.space_id !== null", canonical)
        self.assertIn("group.project_id !== null", canonical)

    def test_owner_grant_stays_server_derived(self) -> None:
        self.assertIn("authenticateProductRequest(request, env)", self.owner_grants)
        self.assertIn("linkedDeviceForOwner(env, identity.subjectId, linkId)", self.owner_grants)
        self.assertNotIn("body.subject_id", self.owner_grants)
        self.assertNotIn("body.device_id", self.owner_grants)
        self.assertNotIn("body.actions", self.owner_grants)
        self.assertNotIn("body.projects", self.owner_grants)


if __name__ == "__main__":
    unittest.main()
