"""Contract for bounded concurrent Product action claims."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / "control-plane/supabase/migrations/20261113070000_product_action_concurrent_claim_v1.sql"


class ProductActionConcurrentClaimContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = SQL.read_text(encoding="utf-8").lower()
        cls.claim = cls.sql.split(
            "create or replace function public.ordax_claim_product_action_v1", 1
        )[1].split("revoke all on function", 1)[0]

    def test_claim_is_bounded_not_device_global_serial(self):
        self.assertIn("v_max_concurrent integer := 4", self.claim)
        self.assertIn("select pg_catalog.count(*)::integer", self.claim)
        self.assertIn("into v_active_count", self.claim)
        self.assertIn("if v_active_count >= v_max_concurrent then", self.claim)
        self.assertNotIn("if exists (", self.claim)

    def test_claim_remains_atomic_and_fenced_per_action(self):
        for phrase in (
            "pg_advisory_xact_lock",
            "for update skip locked",
            "attempt_id = v_attempt_id",
            "lease_id = v_lease_id",
            "execution_epoch = execution_epoch + 1",
            "agent_instance_id = p_agent_instance_id",
            "boot_id = p_boot_id",
            "lease_expires_at = v_lease_expires_at",
        ):
            self.assertIn(phrase, self.claim)
        self.assertLess(
            self.claim.index("pg_advisory_xact_lock"),
            self.claim.index("select pg_catalog.count(*)::integer"),
        )
        self.assertLess(
            self.claim.index("select pg_catalog.count(*)::integer"),
            self.claim.index("for update skip locked"),
        )

    def test_active_count_ignores_expired_unstarted_lease_but_counts_running(self):
        self.assertIn("r.status = 'running'", self.claim)
        self.assertIn(
            "r.status = 'leased' and r.lease_expires_at >= v_now",
            self.claim,
        )
        self.assertIn(
            "r.status = 'leased' and r.lease_expires_at < v_now",
            self.claim,
        )

    def test_existing_recovery_remains_before_capacity_and_claim(self):
        for helper in (
            "private.ordax_expire_queued_product_actions_v1(p_device_id, null)",
            "private.ordax_retire_orphaned_running_product_actions_v1(p_device_id, null)",
        ):
            self.assertIn(helper, self.claim)
            self.assertLess(
                self.claim.index(helper),
                self.claim.index("select pg_catalog.count(*)::integer"),
            )

    def test_edge_executor_is_still_the_only_non_owner_executor(self):
        signature = "public.ordax_claim_product_action_v1(uuid,uuid,text,integer)"
        self.assertIn("security definer", self.sql)
        self.assertIn("set search_path to ''", self.sql)
        self.assertIn("revoke all on function " + signature, self.sql)
        self.assertIn(
            "from public, anon, authenticated, service_role, ordax_edge_executor",
            self.sql,
        )
        self.assertIn("grant execute on function " + signature, self.sql)
        self.assertIn("to ordax_edge_executor", self.sql)


if __name__ == "__main__":
    unittest.main()
