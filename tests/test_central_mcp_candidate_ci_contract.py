"""Fail closed if release-candidate CI misses Owner-attested MCP boundaries.

Both existing candidate workflows are path-filtered. Generic source CI cannot
substitute for their explicit candidate builds and their Owner selection tests.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    ROOT / ".github/workflows/ordax-mcp-canonical.yml",
    ROOT / ".github/workflows/product-mcp-canary.yml",
)
REQUIRED_SOURCE = (
    "product_central_device_session.ts",
    "product_central_device_session_store.ts",
    "product_central_mcp.ts",
    "product_central_admission.ts",
    "product_owner_grant_admin.ts",
    "product_device_presence.ts",
)
REQUIRED_TESTS = (
    "central_owner_device_selection_sql.test.mts",
    "owner_central_device_selection_route.test.mts",
    "owner_central_target_sql.test.mts",
    "owner_central_target_preflight.test.mts",
    "product_central_device_session.test.mts",
    "product_central_persisted_session.test.mts",
)


class CentralMcpCandidateGateTests(unittest.TestCase):
    def test_all_candidate_events_cover_canonical_owner_and_attestation_source(self):
        for workflow in WORKFLOWS:
            source = workflow.read_text(encoding="utf-8")
            with self.subTest(workflow=workflow.name):
                self.assertIn("\n  pull_request:\n", source)
                self.assertIn("\n  push:\n", source)
                pull = source.split("\n  pull_request:\n", 1)[1].split("\n  push:\n", 1)[0]
                push = source.split("\n  push:\n", 1)[1].split("\n  workflow_dispatch:\n", 1)[0]
                for section in (pull, push):
                    for name in REQUIRED_SOURCE:
                        self.assertIn(
                            f'"control-plane/cloudflare/src/{name}"', section,
                            f"{workflow.name} misses source: {name}"
                        )
                    for name in REQUIRED_TESTS:
                        self.assertIn(
                            f'"control-plane/tests/{name}"', section,
                            f"{workflow.name} misses test: {name}"
                        )

    def test_owner_sql_e2e_is_executed_in_both_non_deploy_candidate_jobs(self):
        for workflow in WORKFLOWS:
            source = workflow.read_text(encoding="utf-8")
            jobs = source.split("\njobs:\n", 1)[1]
            with self.subTest(workflow=workflow.name):
                for name in REQUIRED_TESTS:
                    self.assertIn(
                        f"control-plane/tests/{name} ", jobs.replace("\n", " ") + " ",
                        f"{workflow.name} never executes Owner regression: {name}"
                    )
                self.assertIn("deploy --dry-run", jobs)
                self.assertNotIn("wrangler deploy --env production", jobs)
                self.assertIn("persist-credentials: false", jobs)


if __name__ == "__main__":
    unittest.main()
