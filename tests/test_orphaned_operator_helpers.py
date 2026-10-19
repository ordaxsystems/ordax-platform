"""Legacy operator job utilities must not reappear in the D1 Worker."""
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "control-plane/cloudflare/src/index.ts"

class OrphanedLegacyHelpersTests(unittest.TestCase):
    def test_no_orphaned_global_operator_job_helpers(self):
        source = SOURCE.read_text(encoding="utf-8")
        for token in ("ACTION_PREFIXES", "actionAllowed(", "bytesToBase64(", "ORDAX_OPERATOR_TOKEN"):
            with self.subTest(token=token):
                self.assertNotIn(token, source)

    def test_canonical_device_transport_and_recovery_not_deleted(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('url.pathname === "/v3/device/recover-report"', source)
        self.assertIn("async function recoverTerminalReport(", source)
        self.assertIn('error: "legacy_operator_job_enqueue_retired"', source)

if __name__ == "__main__":
    unittest.main()
