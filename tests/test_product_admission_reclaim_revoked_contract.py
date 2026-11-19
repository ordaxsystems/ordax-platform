"""Revoked queued grants do not steal slots from valid Product actions."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "control-plane/supabase/migrations/20261119215627_product_admission_reclaim_revoked_v1.sql"
CLAIM = ROOT / "control-plane/supabase/migrations/20261117150000_product_action_grant_revalidation_v1.sql"

class ProductAdmissionReclaimRevokedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8").lower()

    def test_admission_reuses_same_reclamation_as_claim(self):
        source = self.sql
        helper = "private.ordax_retire_unauthorized_queued_product_actions_v1(p_device_id, null)"
        self.assertEqual(source.count("perform " + helper), 1)
        self.assertIn(helper, CLAIM.read_text(encoding="utf-8").lower())
        self.assertLess(source.index("perform " + helper), source.index("into v_pending_count"))
        self.assertLess(
            source.index("perform pg_catalog.pg_advisory_xact_lock"),
            source.index("perform " + helper),
        )

    def test_replay_and_authority_precede_atomic_reclamation(self):
        source = self.sql
        indices = [
            source.index("into v_existing"),
            source.index("v_grant_id := private.ordax_resolve_product_remote_grant_v1"),
            source.index("product_device_offline"),
            source.index("perform pg_catalog.pg_advisory_xact_lock"),
            source.index("perform private.ordax_retire_unauthorized_queued_product_actions_v1"),
            source.index("into v_pending_count"),
            source.index("insert into private.ordax_product_action_requests("),
        ]
        self.assertEqual(indices, sorted(indices))
        self.assertIn("'replayed', true", source)
        self.assertIn("'product_device_busy'", source)
        self.assertIn("private.ordax_product_remote_capacity_v1()", source)
        self.assertIn("private.ordax_expire_queued_product_actions_v1", source)
        self.assertIn("private.ordax_retire_orphaned_running_product_actions_v1", source)

    def test_no_new_rpc_or_acl_expansion(self):
        source = self.sql
        self.assertEqual(source.count("create or replace function"), 1)
        self.assertIn("security definer", source)
        self.assertIn("set search_path to ''", source)
        self.assertIn("from public, anon, authenticated, service_role, ordax_edge_executor", source)
        self.assertIn("to ordax_edge_executor", source)
        self.assertNotIn("create table", source)

if __name__ == "__main__":
    unittest.main()
