"""Regression: every Device heartbeat RPC is present in the single SQL allowlist."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "control-plane/cloudflare/src/product_postgres_store.ts"
TRANSPORT = ROOT / "control-plane/cloudflare/src/product_device_transport.ts"
MIGRATION = ROOT / "control-plane/supabase/migrations/20261119221101_product_device_attested_capacity_v1.sql"

class DeviceCapacityRpcAllowlistTests(unittest.TestCase):
    def test_capacity_rpc_has_exact_typed_sql_spec(self):
        source = ADAPTER.read_text(encoding="utf-8")
        self.assertIn(
            '  ordax_record_product_capacity_v1: {\n'
            '    keys: ["p_device_id", "p_max_concurrent_jobs"],\n'
            '    casts: ["uuid", "integer"],\n'
            '  },',
            source,
        )
        self.assertIn('callRpc<boolean>(env, "ordax_record_product_capacity_v1"', source)
        self.assertIn('callRpc<boolean>(env, "ordax_record_product_presence_v1"', source)
        self.assertIn('create or replace function public.ordax_record_product_capacity_v1(',
                      MIGRATION.read_text(encoding="utf-8").lower())

    def test_heartbeat_preserves_authenticated_device_path(self):
        source = TRANSPORT.read_text(encoding="utf-8")
        self.assertIn("await recordProductHeartbeat(env", source)
        self.assertNotIn("await recordProductCapacity(env", source)
        self.assertIn("maxConcurrentJobs = typeof rawCapacity", source)
        self.assertIn("rawCapacity : 4", source)
        self.assertIn('error: "product_capacity_unavailable"', source)

if __name__ == "__main__":
    unittest.main()
