"""Reject orphaned IDs and legacy worker identity in the canonical MCP."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "control-plane/cloudflare/src/product_mcp_entry.ts"
CONFIG = ROOT / "control-plane/cloudflare/wrangler.mcp.toml"


class RetiredWorkerIdRegexTests(unittest.TestCase):
    def test_orphaned_validation_constants_are_absent(self):
        source = ENTRY.read_text(encoding="utf-8")
        for legacy in ("const PRODUCT_ID_RE =", "const PROJECT_SLUG_RE =",
                       "recoverTerminalReport(", "legacy_operator_job_enqueue_retired"):
            self.assertNotIn(legacy, source)
        self.assertIn("isCanonicalUuid", source)

    def test_only_canonical_worker_name_is_publishable(self):
        config = CONFIG.read_text(encoding="utf-8")
        self.assertIn('name = "ordax-mcp"', config)
        self.assertNotIn("ordax-control-plane-v3", config)
        self.assertFalse((ROOT / "control-plane/cloudflare/wrangler.toml").exists())


if __name__ == "__main__":
    unittest.main()
