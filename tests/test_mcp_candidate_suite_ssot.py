"""Fail closed if canonical MCP release tests or source changes bypass candidate gates.

A candidate gate must not approve a bundle just because a workflow's copied
test allowlist missed a newly added action/status/wake regression. The
canonical runner discovers tests at runtime; each workflow watches relevant
action and PostgreSQL source changes. Deployment policy remains independent: first release stays evidence-gated,
while an already-published canonical Worker may be maintained automatically.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/cloudflare/run_mcp_candidate_tests.sh"
WORKFLOWS = (
    ROOT / ".github/workflows/ordax-mcp-validation-deploy.yml",
    ROOT / ".github/workflows/ordax-mcp-canonical.yml",
    ROOT / ".github/workflows/product-mcp-canary.yml",
)
REQUIRED_SOURCE = (
    "product_mcp_attested_device_action.ts",
    "product_mcp_attested_project_action.ts",
    "product_owner_project_scope.ts",
    "product_postgres_store.ts",
    "data_postgres_driver.ts",
    "product_device_wake.ts",
)
REQUIRED_TESTS = (
    "product_mcp_attested_device_action.test.mts",
    "product_mcp_attested_project_action.test.mts",
    "product_mcp_action_status.test.mts",
    "product_mcp_failure_responses.test.mts",
    "product_postcommit_wake.test.mts",
    "product_postgres_enqueue_concurrent_retry.test.mts",
    "product_device_wake.test.mts",
    "product_postgres_diagnostics.test.mts",
)


class CanonicalMcpCandidateSuiteTests(unittest.TestCase):
    def test_one_runner_discovers_all_current_and_future_action_regressions(self):
        source = RUNNER.read_text("utf-8")
        self.assertIn("set -euo pipefail", source)
        self.assertIn("node --test control-plane/tests/*.test.mts", source)
        self.assertIn("control-plane/labs/relay/scoped-mcp.test.mts", source)
        self.assertIn(
            "python -m unittest tests.test_mcp_candidate_suite_ssot tests.test_central_mcp_candidate_ci_contract",
            source,
        )
        for name in REQUIRED_TESTS:
            self.assertTrue((ROOT / "control-plane/tests" / name).is_file(), name)
        self.assertNotIn("wrangler deploy", source)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", source)

    def test_all_release_events_run_same_suite_and_watch_security_critical_sources(self):
        command = "run: bash scripts/cloudflare/run_mcp_candidate_tests.sh"
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                source = path.read_text("utf-8")
                self.assertEqual(source.count(command), 1)
                self.assertNotIn("run: node --test", source)
                self.assertIn("\n  push:\n", source)
                events = []
                if "\n  pull_request:\n" in source:
                    events.append(source.split("\n  pull_request:\n", 1)[1].split("\n  push:\n", 1)[0])
                push = source.split("\n  push:\n", 1)[1]
                push = push.split("\n  workflow_dispatch:\n", 1)[0].split("\npermissions:\n", 1)[0]
                events.append(push)
                for section in events:
                    for name in REQUIRED_SOURCE:
                        self.assertIn(
                            f'"control-plane/cloudflare/src/{name}"', section,
                            f"{path.name}: source {name} can evade candidate CI",
                        )
                    self.assertEqual(
                        section.count('"control-plane/tests/*.test.mts"'), 1,
                        f"{path.name}: every new MCP regression must trigger candidate CI",
                    )
                    for line in section.splitlines():
                        if '"control-plane/tests/' in line:
                            self.assertEqual(
                                line.strip(), '- "control-plane/tests/*.test.mts"',
                                f"{path.name}: remove duplicated per-test trigger lists",
                            )
                    self.assertIn('"scripts/cloudflare/run_mcp_candidate_tests.sh"', section)
                    self.assertIn('"tests/test_mcp_candidate_suite_ssot.py"', section)

    def test_validation_release_auto_maintains_existing_worker_and_stays_fail_closed(self):
        source = WORKFLOWS[0].read_text("utf-8")
        self.assertNotIn("inputs.publish_production == true", source)
        self.assertIn("needs.validate-candidate.outputs.production_ready == 'true'", source)
        self.assertIn("needs.validate-candidate.outputs.maintenance_ready == 'true'", source)
        self.assertIn("--maintenance-upgrade", source)
        self.assertIn("environment: cloudflare-v3", source)
        self.assertIn("deploy --dry-run --config wrangler.mcp.toml", source)


if __name__ == "__main__":
    unittest.main()
