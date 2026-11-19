"""Contract: never enqueue a NEW action when canonical device presence expired."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / "control-plane/supabase/migrations/20261119212342_product_offline_action_admission_v1.sql"
DEVICE = ROOT / "control-plane/cloudflare/src/product_mcp_attested_device_action.ts"
PROJECT = ROOT / "control-plane/cloudflare/src/product_mcp_attested_project_action.ts"

class ProductOfflineAdmissionContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = SQL.read_text(encoding="utf-8").lower()

    def test_existing_receipts_win_before_liveness_and_admission(self):
        s = self.sql
        replay = s.index("select *\n    into v_existing")
        grant = s.index("v_grant_id := private.ordax_resolve_product_remote_grant_v1")
        liveness = s.index("private.ordax_product_presence_online_v1(")
        insert = s.index("insert into private.ordax_product_action_requests(")
        self.assertLess(replay, grant)
        self.assertLess(grant, liveness)
        self.assertLess(liveness, insert)
        self.assertIn("'replayed', true", s)
        self.assertIn("'product_device_offline'", s)
        self.assertIn("if not coalesce(v_device_online, false)", s)

    def test_existing_single_authority_and_acl_are_preserved(self):
        s = self.sql
        self.assertEqual(s.count("create or replace function"), 1)
        self.assertIn("public.ordax_enqueue_product_action_v1", s)
        self.assertIn("security definer", s)
        self.assertIn("set search_path to ''", s)
        self.assertIn("revoke all on function public.ordax_enqueue_product_action_v1", s)
        self.assertIn("to ordax_edge_executor", s)
        self.assertIn("private.ordax_resolve_product_remote_grant_v1", s)
        self.assertIn("idempotency_conflict", s)
        self.assertIn("owner_user_id = p_owner_user_id", s)
        self.assertIn("p.last_seen_at", s)
        self.assertNotIn("pg_catalog.coalesce(", s)

    def test_no_false_pending_mcp_receipts(self):
        for path in (DEVICE, PROJECT):
            source = path.read_text(encoding="utf-8")
            self.assertIn('result.error === "product_device_offline"', source)
            self.assertIn('action_dispatched: false', source)

if __name__ == "__main__":
    unittest.main()
