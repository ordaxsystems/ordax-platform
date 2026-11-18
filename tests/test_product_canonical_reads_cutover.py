"""Canonical Product reads are authenticated per OAuth client and persisted in PostgreSQL."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "control-plane/cloudflare/src/product_mcp_entry.ts"
READS = ROOT / "control-plane/cloudflare/src/product_mcp_reads.ts"
POSTGRES = ROOT / "control-plane/cloudflare/src/product_postgres_store.ts"


class CanonicalProductReadsCutoverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entry = ENTRY.read_text(encoding="utf-8")
        cls.reads = READS.read_text(encoding="utf-8")
        cls.store = POSTGRES.read_text(encoding="utf-8")

    def test_canonical_entry_has_one_read_handler(self):
        self.assertIn('import { createCanonicalProductMcpReadHandlers } from "./product_mcp_reads.ts"', self.entry)
        self.assertIn("createCanonicalProductMcpReadHandlers(env)", self.entry)
        self.assertNotIn("async function listProductTargets(", self.entry)
        self.assertNotIn("async function getProductAction(", self.entry)
        self.assertNotIn("FROM ordax_product_grants g", self.entry)
        self.assertNotIn("FROM ordax_product_action_requests r JOIN ordax_jobs", self.entry)

    def test_signed_exact_client_is_required_and_postgres_owns_results(self):
        self.assertIn("authenticateProductMcpClientRequest(request, env)", self.reads)
        self.assertIn("clientKind: identity.clientKind", self.reads)
        self.assertIn("clientId: identity.clientId", self.reads)
        self.assertIn("listCanonicalProductTargets", self.reads)
        self.assertIn("getProductAction", self.reads)
        self.assertIn('"ordax_list_product_targets_v1"', self.store)
        self.assertIn('"ordax_get_product_action_v1"', self.store)
        self.assertNotIn("env.DB", self.reads)
        self.assertNotIn("this.env.DB", self.reads)


if __name__ == "__main__":
    unittest.main()
