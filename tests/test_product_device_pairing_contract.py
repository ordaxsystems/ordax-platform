from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "control-plane/cloudflare/src/index.ts"
HISTORICAL_MIGRATION = ROOT / "control-plane/cloudflare/migrations/0007_product_device_pairing.sql"

class ProductDevicePairingRetirementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.worker = WORKER.read_text(encoding="utf-8")

    def test_old_device_pairing_and_owner_links_are_retired(self):
        self.assertIn('"/v3/device/product-pairings"', self.worker)
        self.assertIn('"/v3/product/device-links"', self.worker)
        self.assertIn('error: "legacy_product_pairing_retired"', self.worker)
        for handler in ("createProductDevicePairing", "claimProductDevicePairing",
                        "listProductDeviceLinks", "revokeProductDeviceLink"):
            self.assertNotIn(handler, self.worker)

    def test_historical_schema_is_preserved_for_migration_evidence(self):
        migration = HISTORICAL_MIGRATION.read_text(encoding="utf-8")
        self.assertIn("ordax_product_device_pairings", migration)
        self.assertIn("ordax_product_device_links", migration)
        self.assertIn("secret_sha256", migration)
        self.assertNotIn("ordax_product_grants", migration)

if __name__ == "__main__":
    unittest.main()
