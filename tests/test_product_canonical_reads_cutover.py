from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "control-plane/cloudflare/src/index.ts"
READS = ROOT / "control-plane/cloudflare/src/product_mcp_reads.ts"
POSTGRES = ROOT / "control-plane/cloudflare/src/product_postgres_store.ts"


class CanonicalProductReadsCutoverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.worker = WORKER.read_text(encoding="utf-8")
        cls.reads = READS.read_text(encoding="utf-8")
        cls.store = POSTGRES.read_text(encoding="utf-8")

    def test_legacy_product_read_routes_use_canonical_postgres_handler(self) -> None:
        self.assertIn('import { createCanonicalProductMcpReadHandlers } from "./product_mcp_reads";', self.worker)
        self.assertIn('createCanonicalProductMcpReadHandlers(env).targets(request)', self.worker)
        self.assertRegex(self.worker, r"createCanonicalProductMcpReadHandlers\(env\)\.getAction\(request,\s*parts\[3\]\)")
        self.assertNotIn('async function listProductTargets(', self.worker)
        self.assertNotIn('async function getProductAction(', self.worker)
        self.assertNotIn('FROM ordax_product_grants g', self.worker)
        self.assertNotIn('FROM ordax_product_action_requests r JOIN ordax_jobs', self.worker)

    def test_signed_exact_client_is_required_and_postgres_owns_results(self) -> None:
        self.assertIn('authenticateProductMcpClientRequest(request, env)', self.reads)
        self.assertIn('clientKind: identity.clientKind', self.reads)
        self.assertIn('clientId: identity.clientId', self.reads)
        self.assertIn('listCanonicalProductTargets', self.reads)
        self.assertIn('getProductAction', self.reads)
        self.assertIn('"ordax_list_product_targets_v1"', self.store)
        self.assertIn('"ordax_get_product_action_v1"', self.store)
        self.assertNotIn('env.DB', self.reads)
        self.assertNotIn('this.env.DB', self.reads)


if __name__ == "__main__":
    unittest.main()
