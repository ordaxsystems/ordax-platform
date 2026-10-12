from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HANDLER = ROOT / "control-plane" / "cloudflare" / "src" / "product_project_grants.ts"
WORKER = ROOT / "control-plane" / "cloudflare" / "src" / "index.ts"
MCP = ROOT / "control-plane" / "cloudflare" / "src" / "mcp_http.ts"
SCOPE = ROOT / "control-plane" / "cloudflare" / "src" / "product_action_scope.ts"


def quoted_actions(text: str) -> set[str]:
    return set(re.findall(r'"([a-z][a-z0-9_.-]+)"', text))


class OwnerProjectBrowserGrantContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.handler = HANDLER.read_text(encoding="utf-8")
        cls.worker = WORKER.read_text(encoding="utf-8")
        cls.mcp = MCP.read_text(encoding="utf-8")
        cls.scope = SCOPE.read_text(encoding="utf-8")

    def test_profile_is_server_derived_from_canonical_browser_scope(self) -> None:
        self.assertIn('PROJECT_BROWSER_AUTOMATION_MODE = "project-browser-automation"', self.handler)
        self.assertIn("[...PROJECT_BROWSER_ACTIONS].sort()", self.handler)
        self.assertIn('from "./product_action_scope.ts"', self.handler)
        self.assertNotIn("body.actions", self.handler)
        self.assertNotIn("body.subject_id", self.handler)
        self.assertNotIn("body.device_id", self.handler)
        self.assertNotIn("body.space_id", self.handler)

    def test_canonical_browser_scope_is_project_only_and_complete(self) -> None:
        start = self.scope.index("export const PROJECT_BROWSER_ACTIONS = new Set<string>([")
        block = self.scope[start:].split("]);", 1)[0]
        actions = quoted_actions(block)
        self.assertEqual(
            actions,
            {
                "browser.click",
                "browser.list",
                "browser.navigate",
                "browser.screenshot",
                "browser.snapshot",
                "browser.start",
                "browser.status",
                "browser.stop",
                "browser.type",
            },
        )
        self.assertNotIn("computer.", block)

    def test_owner_selects_only_bounded_projects_and_reviewed_mode(self) -> None:
        self.assertIn('new Set(["link_id", "mode", "projects", "expires_at"])', self.handler)
        self.assertIn("MAX_PROJECTS = 20", self.handler)
        self.assertIn("PROJECT_SLUG_RE", self.handler)
        self.assertIn("actionsForMode(mode)", self.handler)
        self.assertIn("normalizedProjects(body.projects)", self.handler)

    def test_identity_device_and_link_are_server_derived(self) -> None:
        self.assertIn("authenticateProductRequest(request, env)", self.handler)
        self.assertIn("linkedDeviceForOwner(env, identity.subjectId, linkId)", self.handler)
        self.assertIn("l.subject_id = ?2", self.handler)
        self.assertIn("d.revoked_at IS NULL", self.handler)

    def test_owner_routes_are_wired_but_never_exposed_as_mcp_grant_tools(self) -> None:
        self.assertIn('from "./product_project_grants"', self.worker)
        self.assertIn('url.pathname === "/v3/product/project-capability-grants"', self.worker)
        self.assertIn("createOwnerProjectGrant(request, env)", self.worker)
        self.assertIn("listOwnerProjectGrants(request, env)", self.worker)
        self.assertIn("revokeOwnerProjectGrant(request, env", self.worker)
        for name in (
            "createOwnerProjectGrant",
            "listOwnerProjectGrants",
            "revokeOwnerProjectGrant",
            "project-capability-grants",
        ):
            self.assertNotIn(name, self.mcp)

    def test_browser_project_grants_remain_explicitly_scoped(self) -> None:
        canonical = (ROOT / "control-plane/cloudflare/src/product_relay_scope.ts").read_text(
            encoding="utf-8"
        )
        self.assertIn("selectCanonicalRelayProjectScope", canonical)
        self.assertIn("isCanonicalUuid(group.project_id)", canonical)
        self.assertIn("isCanonicalUuid(group.space_id)", canonical)
        self.assertNotIn("async function createProductGrant(", self.worker)

    def test_revoke_cannot_touch_unrecognized_project_grants(self) -> None:
        self.assertIn("rowIsOwnerProjectGrant(row)", self.handler)
        self.assertIn('return "custom-project-grant";', self.handler)
        self.assertIn("g.subject_id = ?2", self.handler)


if __name__ == "__main__":
    unittest.main()
