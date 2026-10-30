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
        for route, error in (
            ('url.pathname === "/v3/devices"', "legacy_operator_device_provision_retired"),
            ('url.pathname === "/v3/jobs"', "legacy_operator_job_enqueue_retired"),
            ('parts[1] === "jobs"', "legacy_operator_job_read_retired"),
        ):
            with self.subTest(route=route):
                self.assertIn(route, src)
                self.assertIn(f'error: "{error}" }}, 410)', src)


if __name__ == "__main__":
    unittest.main()
