"""Prevent resurrection of orphaned legacy Worker validation constants."""
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "control-plane/cloudflare/src/index.ts"

class RetiredWorkerIdRegexTests(unittest.TestCase):
    def test_legacy_id_regex_constants_removed(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("const PRODUCT_ID_RE =", source)
        self.assertNotIn("const PROJECT_SLUG_RE =", source)
        self.assertIn("async function recoverTerminalReport(", source)
        self.assertIn('error: "legacy_operator_job_enqueue_retired"', source)

if __name__ == "__main__":
    unittest.main()
