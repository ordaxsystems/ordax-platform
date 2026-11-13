"""Contract for the production advisory Product wake rollout."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "control-plane" / "cloudflare" / "wrangler.mcp.toml"


class ProductDeviceWakeRolloutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = CONFIG.read_text(encoding="utf-8")

    def test_production_mcp_enables_only_the_existing_advisory_wake(self):
        source = self.source
        self.assertIn('PRODUCT_DEVICE_WAKE_ENABLED = "enabled"', source)
        self.assertIn('name = "DEVICE_WAKE"', source)
        self.assertIn('class_name = "ProductDeviceWake"', source)
        self.assertIn('tag = "product-device-wake-v1"', source)

    def test_wake_rollout_does_not_add_an_alternate_queue(self):
        source = self.source
        self.assertEqual(source.count('PRODUCT_DEVICE_WAKE_ENABLED = "enabled"'), 1)
        self.assertIn('[[hyperdrive]]', source)
        self.assertIn('binding = "POSTGRES"', source)
        self.assertNotIn('binding = "ACTION_QUEUE"', source)


if __name__ == "__main__":
    unittest.main()
