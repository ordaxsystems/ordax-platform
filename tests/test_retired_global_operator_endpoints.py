"""The MCP must never restore global operator tokens or engineering endpoints."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "control-plane/cloudflare/src/product_mcp_entry.ts"


class RetiredOperatorEndpointsTests(unittest.TestCase):
    def test_global_operator_auth_and_handlers_absent(self):
        src = ENTRY.read_text(encoding="utf-8")
        for legacy in ("ORDAX_OPERATOR_TOKEN", "operatorAuthorized(",
                       "async function provisionDevice(", "async function enqueueJob(",
                       "async function getJob(", "D1Database", "env.DB"):
            with self.subTest(legacy=legacy):
                self.assertNotIn(legacy, src)

    def test_retired_engineering_routes_not_published(self):
        src = ENTRY.read_text(encoding="utf-8")
        for route in ("/v3/jobs", "/v3/product-grants", "/v3/device/ws",
                      "/v3/artifacts/", "legacy_endpoint_retired"):
            self.assertNotIn(route, src)
        self.assertIn('error: "not_found"', src)
        self.assertIn("createAttestedDeviceActionHandler", src)

    def test_legacy_openai_review_grant_workflow_is_retired(self):
        workflow = ROOT / ".github/workflows/openai-review-grant.yml"
        self.assertFalse(workflow.exists())
        runbook = (ROOT / "docs/OPENAI_PLUGIN_REVIEW.md").read_text(encoding="utf-8")
        for retired in ("ORDAX_OPERATOR_TOKEN", "/v3/product-grants/from-link",
                        "ordax-ac1ca1b50d09.workers.dev", "eobcxuyvhkvdmkbaihwh"):
            with self.subTest(retired=retired):
                self.assertNotIn(retired, runbook)
        import json
        manifest = json.loads((ROOT / "plugins/ordax-chatgpt/mcp.json").read_text(encoding="utf-8"))
        self.assertIn(manifest["mcpServers"]["ordax"]["url"], runbook)
        self.assertIn("/v3/owner/remote-grant-groups", runbook)
        self.assertIn("product_owner_grant_profiles.ts", runbook)


if __name__ == "__main__":
    unittest.main()
