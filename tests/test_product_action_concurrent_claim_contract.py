"""Contract tests for bounded concurrent Product claims."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "control-plane/supabase/migrations/20261113070000_product_action_concurrent_claims_v1.sql"


class ProductActionConcurrentClaimContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8").lower()

    def test_claim_capacity_matches_current_runtime_pool(self):
        sql = self.sql
        self.assertIn("v_max_active_actions constant integer := 4", sql)
        self.assertIn("select pg_catalog.count(*)::integer", sql)
        self.assertIn("if v_active_actions >= v_max_active_actions", sql)
        self.assertNotIn("if exists (", sql)

    def test_active_count_keeps_live_leases_and_running_work_fenced(self):
        sql = self.sql
        self.assertIn("r.status = 'running'", sql)
        self.assertIn("r.status = 'leased' and r.lease_expires_at >= v_now", sql)
        self.assertIn("perform private.ordax_retire_orphaned_running_product_actions_v1", sql)
        self.assertIn("execution_epoch = execution_epoch + 1", sql)

    def test_claim_still_uses_row_lock_and_device_claim_transaction_lock(self):
        sql = self.sql
        self.assertIn("pg_advisory_xact_lock", sql)
        self.assertIn("for update skip locked", sql)
        self.assertIn("and status in ('queued','leased')", sql)

    def test_claim_acl_remains_edge_runtime_only(self):
        sql = self.sql
        signature = "public.ordax_claim_product_action_v1(uuid,uuid,text,integer)"
        self.assertIn("revoke all on function " + signature, sql)
        self.assertIn("grant execute on function " + signature, sql)
        self.assertIn("to ordax_edge_runtime", sql)


if __name__ == "__main__":
    unittest.main()
