"""Product admission remains bounded to installed Runtime capacity, not a hidden FIFO."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / "control-plane/supabase/migrations/20261119213655_product_capacity_admission_v1.sql"
DEVICE = ROOT / "control-plane/cloudflare/src/product_mcp_attested_device_action.ts"
PROJECT = ROOT / "control-plane/cloudflare/src/product_mcp_attested_project_action.ts"

class ProductCapacityAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = SQL.read_text(encoding="utf-8").lower()

    def test_single_capacity_authority_shared_by_claim_and_admission(self):
        sql = self.sql
        self.assertIn("create or replace function private.ordax_product_remote_capacity_v1()", sql)
        self.assertEqual(sql.count("select 4;"), 1)
        self.assertIn("v_max_concurrent integer := private.ordax_product_remote_capacity_v1();", sql)
        self.assertIn("v_pending_count >= private.ordax_product_remote_capacity_v1()", sql)
        self.assertIn("revoke all on function private.ordax_product_remote_capacity_v1()", sql)
        self.assertIn("security invoker", sql)

    def test_short_atomic_admission_and_no_overbooking(self):
        sql = self.sql
        replay = sql.index("into v_existing")
        grant = sql.index("v_grant_id := private.ordax_resolve_product_remote_grant_v1")
        presence = sql.index("select private.ordax_product_presence_online_v1")
        lock = sql.index("perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext(p_device_id::text))")
        active = sql.index("into v_pending_count")
        insert = sql.index("insert into private.ordax_product_action_requests(")
        self.assertLess(replay, grant)
        self.assertLess(grant, presence)
        self.assertLess(presence, lock)
        self.assertLess(lock, active)
        self.assertLess(active, insert)
        for clause in (
            "r.status in ('queued','leased')",
            "r.expires_at > v_admission_now",
            "r.status = 'running'",
            "r.lease_expires_at >= v_admission_now",
            "product_device_busy",
        ):
            self.assertIn(clause, sql)
        self.assertIn("private.ordax_expire_queued_product_actions_v1", sql)
        self.assertIn("private.ordax_retire_orphaned_running_product_actions_v1", sql)

    def test_fencing_and_privileges_not_weakened(self):
        sql = self.sql
        for value in (
            "security definer", "set search_path to ''",
            "idempotency_conflict", "'replayed', true",
            "attempt_id = v_attempt_id", "lease_id = v_lease_id",
            "execution_epoch = execution_epoch + 1",
            "for update skip locked",
            "from public, anon, authenticated, service_role, ordax_edge_executor",
            "to ordax_edge_executor",
        ):
            self.assertIn(value, sql)
        for source in (DEVICE, PROJECT):
            body = source.read_text(encoding="utf-8")
            self.assertIn('result.error === "product_device_busy"', body)
            self.assertIn('action_dispatched: false', body)

if __name__ == "__main__":
    unittest.main()
