"""Device identity belongs to PostgreSQL; legacy pairing/link authority is gone."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "control-plane/cloudflare/src/product_mcp_entry.ts"
SETUP = ROOT / "control-plane/cloudflare/src/product_device_setup.ts"
HISTORICAL_MIGRATION = ROOT / "control-plane/cloudflare/migrations/0007_product_device_pairing.sql"


class ProductDevicePairingRetirementTests(unittest.TestCase):
    def test_retired_pairing_routes_cannot_be_published(self):
        entry = ENTRY.read_text(encoding="utf-8")
        setup = SETUP.read_text(encoding="utf-8")
        for retired in ("/v3/device/product-pairings", "/v3/product/device-links",
                        "createProductDevicePairing", "claimProductDevicePairing",
                        "listProductDeviceLinks", "revokeProductDeviceLink"):
            self.assertNotIn(retired, entry)
            self.assertNotIn(retired, setup)
        self.assertIn("handleProductDeviceSetup(request, env)", entry)
        self.assertIn("enrollProductDevice", setup)
        self.assertIn("identifyProductDevice", setup)

    def test_retired_pairing_schema_does_not_remain(self):
        self.assertFalse(HISTORICAL_MIGRATION.exists())
        sql = (ROOT / "control-plane/supabase/migrations"
               / "20261007154000_product_device_identity_v1.sql").read_text(encoding="utf-8").lower()
        self.assertIn("private.ordax_product_device_credentials", sql)
        self.assertIn("machine_binding_sha256", sql)


if __name__ == "__main__":
    unittest.main()
