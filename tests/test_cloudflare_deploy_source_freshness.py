from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FRESHNESS = ROOT / "scripts/cloudflare/assert-current-main.sh"
WORKFLOW = ROOT / ".github/workflows/ordax-mcp-validation-deploy.yml"


def run_git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


class CloudflareMainSourceFreshnessTests(unittest.TestCase):
    def test_current_main_only_and_remote_fetch_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bare = root / "origin.git"
            checkout = root / "checkout"
            bare.mkdir()
            checkout.mkdir()
            run_git("init", "--bare", str(bare), cwd=root)
            run_git("init", cwd=checkout)
            run_git("config", "user.email", "ci@example.invalid", cwd=checkout)
            run_git("config", "user.name", "CI Test", cwd=checkout)
            run_git("commit", "--allow-empty", "-m", "initial", cwd=checkout)
            run_git("branch", "-M", "main", cwd=checkout)
            run_git("remote", "add", "origin", str(bare), cwd=checkout)
            run_git("push", "-u", "origin", "main", cwd=checkout)

            def verify() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["bash", str(FRESHNESS), str(checkout)],
                    cwd=root, capture_output=True, text=True, check=False,
                )

            good = verify()
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertIn("matches current remote main", good.stdout)

            run_git("commit", "--allow-empty", "-m", "local ahead", cwd=checkout)
            ahead = verify()
            self.assertEqual(ahead.returncode, 4)
            self.assertIn("stale", ahead.stderr)

            run_git("push", "origin", "main", cwd=checkout)
            self.assertEqual(verify().returncode, 0)

            run_git("reset", "--hard", "HEAD~1", cwd=checkout)
            behind = verify()
            self.assertEqual(behind.returncode, 4)
            self.assertIn("stale", behind.stderr)

            run_git("remote", "set-url", "origin", str(root / "missing.git"), cwd=checkout)
            unavailable = verify()
            self.assertEqual(unavailable.returncode, 4)
            self.assertIn("Cannot verify current remote main", unavailable.stderr)

    def test_only_canonical_mcp_publisher_exists_and_validates_release_before_token(self):
        for name in ("deploy-v3.sh", "deploy-production-v3.sh", "bootstrap-worker-v3.sh"):
            self.assertFalse((ROOT / "scripts/cloudflare" / name).exists())
        workflow = WORKFLOW.read_text(encoding="utf-8")
        candidate, production = workflow.split("  deploy-production:", 1)
        self.assertIn("Checkout exact main source", candidate)
        self.assertIn("deploy --dry-run --config wrangler.mcp.toml", candidate)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", candidate)
        self.assertIn("Checkout exact main source for production only", production)
        self.assertLess(
            production.index("Revalidate exact release mode directly before publication"),
            production.index("CLOUDFLARE_API_TOKEN"),
        )
        self.assertEqual(
            production.count("npx --yes wrangler@4.141.0 deploy --config wrangler.mcp.toml"),
            1,
        )
        self.assertNotIn("github.event.workflow_run", workflow)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", FRESHNESS.read_text(encoding="utf-8"))

    def test_retired_v3_deploy_file_is_gone_and_only_canonical_mcp_release_remains(self) -> None:
        self.assertFalse(
            (ROOT / ".github/workflows/cloudflare-v3-deploy.yml").exists(),
            "a blocked legacy Worker must not retain a manual or automatic deploy workflow",
        )
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("  workflow_dispatch:", workflow)
        self.assertIn("  push:", workflow)
        self.assertIn("    branches: [main]", workflow)
        self.assertNotIn("  workflow_run:", workflow)
        self.assertNotIn("github.event.workflow_run", workflow)
        self.assertIn("needs.validate-candidate.outputs.maintenance_ready == 'true'", workflow)
        self.assertIn("Deploy canonical production MCP", workflow)
        self.assertIn("npx --yes wrangler@4.141.0 deploy --config wrangler.mcp.toml", workflow)


if __name__ == "__main__":
    unittest.main()
