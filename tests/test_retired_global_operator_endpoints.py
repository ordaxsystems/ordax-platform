"""Retired global-operator endpoints cannot regain D1 mutation authority."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "control-plane/cloudflare/src/index.ts"


class RetiredOperatorEndpointsTests(unittest.TestCase):
    def test_global_operator_auth_and_handlers_absent(self):
        src = SOURCE.read_text(encoding="utf-8")
        for legacy in (
            "ORDAX_OPERATOR_TOKEN",
            "operatorAuthorized(",
            "async function provisionDevice(",
            "async function enqueueJob(",
            "async function getJob(",
        ):
            with self.subTest(legacy=legacy):
                self.assertNotIn(legacy, src)

    def test_legacy_routes_explicitly_retired(self):
        src = SOURCE.read_text(encoding="utf-8")
        # The canonical Worker now handles all retired engineering routes in
        # one fail-closed dispatch branch; do not recreate old per-route RPCs.
        for route in (
            'path === "/v3/devices"',
            'path === "/v3/jobs"',
            'path.startsWith("/v3/jobs/")',
            'path.startsWith("/v3/product-grants")',
        ):
            with self.subTest(route=route):
                self.assertIn(route, src)
        self.assertIn('if (legacy) return json({ok:false,error:"legacy_endpoint_retired"},410);', src)

    def test_legacy_openai_review_grant_workflow_is_retired(self):
        # The old manual workflow could mint grants via a shared operator
        # bearer and a D1 endpoint. Owner/PostgreSQL is the only live writer.
        workflow = ROOT / ".github/workflows/openai-review-grant.yml"
        self.assertFalse(workflow.exists())
        runbook = (ROOT / "docs/OPENAI_PLUGIN_REVIEW.md").read_text(encoding="utf-8")
        for retired in (
            "ORDAX_OPERATOR_TOKEN",
            "/v3/product-grants/from-link",
            "ordax-ac1ca1b50d09.workers.dev",
            "eobcxuyvhkvdmkbaihwh",
        ):
            with self.subTest(retired=retired):
                self.assertNotIn(retired, runbook)
        import json
        manifest = json.loads((ROOT / "plugins/ordax-chatgpt/mcp.json").read_text(encoding="utf-8"))
        self.assertIn(manifest["mcpServers"]["ordax"]["url"], runbook)
        self.assertIn("/v3/owner/remote-grant-groups", runbook)
        self.assertIn("product_owner_grant_profiles.ts", runbook)


if __name__ == "__main__":
    unittest.main()
