"""A live fenced lease consumes capacity even after original enqueue TTL."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / "control-plane/supabase/migrations/20261119214606_product_admission_active_lease_accounting_v1.sql"

class ProductActiveLeaseCapacityContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = SQL.read_text(encoding="utf-8").lower()

    def test_queued_and_live_leased_are_counted_separately(self):
        sql = self.sql
        for token in (
            "r.status = 'queued' and r.expires_at > v_admission_now",
            "r.status = 'leased'",
            "r.expires_at > v_admission_now",
            "or r.lease_expires_at >= v_admission_now",
            "r.status = 'running' and r.lease_expires_at >= v_admission_now",
            "v_pending_count >= private.ordax_product_remote_capacity_v1()",
        ):
            self.assertIn(token, sql)
        self.assertNotIn("r.status in ('queued','leased') and r.expires_at > v_admission_now", sql)

    def test_idempotency_and_atomic_claim_capacity_remain_unchanged(self):
        sql = self.sql
        self.assertEqual(sql.count("create or replace function"), 1)
        order = [
            sql.index("into v_existing"),
            sql.index("v_grant_id := private.ordax_resolve_product_remote_grant_v1"),
            sql.index("product_device_offline"),
            sql.index("perform pg_catalog.pg_advisory_xact_lock"),
            sql.index("into v_pending_count"),
            sql.index("insert into private.ordax_product_action_requests("),
        ]
        self.assertEqual(order, sorted(order))
        self.assertIn("'replayed', true", sql)
        self.assertIn("'product_device_busy'", sql)
        self.assertIn("to ordax_edge_executor", sql)
        self.assertIn("from public, anon, authenticated, service_role, ordax_edge_executor", sql)

if __name__ == "__main__":
    unittest.main()
