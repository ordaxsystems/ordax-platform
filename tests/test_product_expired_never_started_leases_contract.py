"""Regression: never-started expired leases cannot remain pending forever."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "control-plane/supabase/migrations/20261119210750_product_expire_never_started_leases_v1.sql"
BASE = ROOT / "control-plane/supabase/migrations/20261020091500_product_action_queued_expiration_v1.sql"
CLAIM = ROOT / "control-plane/supabase/migrations/20261113070000_product_action_concurrent_claim_v1.sql"


class NeverStartedLeaseExpiryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8").lower()
        cls.base = BASE.read_text(encoding="utf-8").lower()
        cls.claim = CLAIM.read_text(encoding="utf-8").lower()

    def test_extends_existing_single_expiry_authority(self):
        self.assertIn("create or replace function private.ordax_expire_queued_product_actions_v1", self.sql)
        self.assertEqual(self.sql.count("create or replace function"), 1)
        self.assertIn("security invoker", self.sql)
        self.assertIn("set search_path = ''", self.sql)
        self.assertIn("revoke all on function private.ordax_expire_queued_product_actions_v1", self.sql)
        self.assertNotIn("grant execute", self.sql)

    def test_only_expired_never_started_attempts_are_terminalized(self):
        for predicate in (
            "r.status = 'queued'", "r.status = 'leased'",
            "r.expires_at <= v_now", "r.started_at is null",
            "r.report_id is null", "r.lease_expires_at is not null",
            "r.lease_expires_at < v_now",
        ):
            self.assertIn(predicate, self.sql)
        self.assertIn("set status = 'expired'", self.sql)
        self.assertIn("error_code = 'action_expired'", self.sql)
        self.assertNotIn("set status = 'failed'", self.sql)
        self.assertNotIn("set status = 'running'", self.sql)
        for forbidden in ("attempt_id =", "lease_id =", "execution_epoch =", "effect_id ="):
            self.assertNotIn(forbidden, self.sql)

    def test_expiry_is_used_by_client_scoped_status_and_atomic_claim(self):
        helper = "private.ordax_expire_queued_product_actions_v1"
        self.assertIn("perform " + helper + "(v_device_id, p_request_id)", self.base)
        self.assertIn("perform " + helper + "(p_device_id, null)", self.claim)
        self.assertIn("r.client_id = p_client_id", self.base)
        self.assertIn("for update skip locked", self.claim)

    def test_backfill_only_targets_overdue_unstarted_rows(self):
        backfill = self.sql.split("do $backfill$", 1)[1]
        for predicate in (
            "select distinct r.device_id", "r.expires_at <= pg_catalog.clock_timestamp()",
            "r.status = 'queued'", "r.status = 'leased'",
            "r.started_at is null", "r.report_id is null",
            "r.lease_expires_at is not null",
            "r.lease_expires_at < pg_catalog.clock_timestamp()",
        ):
            self.assertIn(predicate, backfill)
        self.assertTrue(self.sql.strip().endswith("commit;"))


if __name__ == "__main__":
    unittest.main()
