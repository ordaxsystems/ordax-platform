"""Reject live MCP Worker deployments from candidate or automatic push workflows."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ordax-mcp-validation-deploy.yml"
GUARD = ROOT / "scripts" / "cloudflare" / "check_mcp_release.py"


class McpProductionDeployGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")
        cls.candidate, cls.production = cls.source.split("  deploy-production:", 1)

    def test_only_explicit_manual_release_can_enter_production_job(self):
        self.assertRegex(self.source, r"(?m)^  workflow_dispatch:$")
        self.assertRegex(self.source, r"(?m)^      publish_production:$")
        self.assertRegex(self.source, r"(?m)^        default: false$")
        self.assertIn("github.event_name == 'workflow_dispatch'", self.production)
        self.assertIn("inputs.publish_production == true", self.production)
        self.assertIn("needs.validate-candidate.outputs.production_ready == 'true'", self.production)
        self.assertIn("environment: cloudflare-v3", self.production)
        self.assertIn("needs: validate-candidate", self.production)

    def test_candidate_can_never_write_production_or_read_deploy_token(self):
        self.assertRegex(self.candidate, r"(?m)^  validate-candidate:$")
        self.assertIn("deploy --dry-run --config wrangler.mcp.toml", self.candidate)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", self.candidate)
        self.assertNotIn("environment: cloudflare-v3", self.candidate)
        self.assertNotIn("Deploy canonical production MCP", self.candidate)
        self.assertNotRegex(
            self.candidate,
            r"\bwrangler@[\d.]+\s+deploy\s+--config\s+wrangler\.mcp\.toml",
        )
        self.assertIn("production_ready=false", self.candidate)
        self.assertIn("python scripts/cloudflare/check_mcp_release.py --validation-candidate", self.candidate)

    def test_production_rechecks_evidence_before_exact_worker_deploy(self):
        self.assertEqual(
            self.production.count("npx --yes wrangler@4.141.0 deploy --config wrangler.mcp.toml"),
            1,
        )
        self.assertIn("python scripts/cloudflare/check_mcp_release.py", self.production)
        check = self.production.index("Revalidate production evidence directly before publication")
        publish = self.production.index("Deploy canonical production MCP")
        self.assertLess(check, publish)
        self.assertIn("CLOUDFLARE_API_TOKEN", self.production)
        self.assertIn("Verify public attested interactive health and readiness", self.production)
        self.assertIn("Verify workers.dev is trusted Product ingress", self.production)
        self.assertIn("permissions:\n  contents: read", self.source)
        self.assertNotIn("D1", self.production)

    def test_release_guard_describes_dry_run_not_unverified_deploy(self):
        source = GUARD.read_text(encoding="utf-8")
        self.assertIn("tests and dry-run bundling only", source)
        self.assertIn("without authorizing public Worker publication", source)
        self.assertIn("return 0 if opt.inspect else 3", source)


if __name__ == "__main__":
    unittest.main()
