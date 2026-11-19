"""Only a live authenticated Device heartbeat may extend actual concurrency."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SQL=ROOT/"control-plane/supabase/migrations/20261119221101_product_device_attested_capacity_v1.sql"
TRANSPORT=ROOT/"control-plane/cloudflare/src/product_device_transport.ts"
STORE=ROOT/"control-plane/cloudflare/src/product_postgres_store.ts"

class ProductCapacityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql=SQL.read_text(encoding="utf-8").lower()
        cls.transport=TRANSPORT.read_text(encoding="utf-8")
        cls.store=STORE.read_text(encoding="utf-8")

    def test_capacity_comes_from_device_and_has_safe_legacy_fallback(self):
        s=self.sql
        for x in (
            "add column max_concurrent_jobs integer",
            "remote_capacity_reported_at timestamptz",
            "max_concurrent_jobs between 1 and 32",
            "private.ordax_product_remote_capacity_v1(p_device_id uuid)",
            "private.ordax_product_remote_capacity_v1()",
            "private.ordax_product_presence_online_v1",
            "pg_catalog.statement_timestamp() - interval '6 minutes'",
            "public.ordax_record_product_capacity_v1(",
            "pg_catalog.pg_advisory_xact_lock",
        ):
            self.assertIn(x,s)
        self.assertEqual(s.count("private.ordax_product_remote_capacity_v1(p_device_id);"),2)
        self.assertIn("to ordax_edge_executor",s)
        self.assertNotIn("to authenticated;",s)
        self.assertNotIn("to anon;",s)

    def test_transport_attests_capacity_without_new_scheduler(self):
        self.assertIn('key !== "max_concurrent_jobs"',self.transport)
        self.assertIn("Number.isInteger(rawCapacity)",self.transport)
        self.assertIn("rawCapacity > 32",self.transport)
        self.assertIn("maxConcurrentJobs = typeof rawCapacity",self.transport)
        self.assertIn("rawCapacity : 4",self.transport)
        self.assertIn("recordProductCapacity(env",self.transport)
        self.assertIn('"ordax_record_product_capacity_v1"',self.store)
        self.assertNotIn("new Queue(",self.transport)

if __name__=="__main__":
    unittest.main()
