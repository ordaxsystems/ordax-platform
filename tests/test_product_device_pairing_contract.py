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

    def test_retired_device_pairing_schema_does_not_remain_in_source(self):
        self.assertFalse(
            HISTORICAL_MIGRATION.exists(),
            "D1 pairing migrations must not remain beside the PostgreSQL owner",
        )
        canonical_sql = (
            ROOT / "control-plane/supabase/migrations"
            / "20261007154000_product_device_identity_v1.sql"
        ).read_text(encoding="utf-8").lower()
        self.assertIn("private.ordax_product_device_credentials", canonical_sql)
        self.assertIn("machine_binding_sha256", canonical_sql)

if __name__ == "__main__":
    unittest.main()
