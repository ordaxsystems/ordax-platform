"""Product MCP lease renewal regression gates without mutating production state.

The corresponding SQL postflight executes against the canonical database in a
transaction ending with ROLLBACK. Unit checks here keep its guarantees versioned.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
POSTFLIGHT = ROOT / "control-plane/supabase/tests/product_action_lease_renewal_postflight.sql"
AUTHORITY = ROOT / "control-plane/supabase/migrations/20261007150000_product_remote_authority_v1.sql"
RECOVERY = ROOT / "control-plane/supabase/migrations/20261020154500_product_orphaned_running_lease_recovery_v1.sql"
TRANSPORT = ROOT / "control-plane/cloudflare/src/product_device_transport.ts"


class ProductLeaseRenewalContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probe = POSTFLIGHT.read_text(encoding="utf-8").lower()
        cls.authority = AUTHORITY.read_text(encoding="utf-8").lower()
        cls.recovery = RECOVERY.read_text(encoding="utf-8").lower()
        cls.transport = TRANSPORT.read_text(encoding="utf-8")

    def test_postflight_always_rolls_back_historical_fixture(self):
        self.assertTrue(self.probe.lstrip().startswith("-- postflight"))
        self.assertIn("\nbegin;\n", self.probe)
        self.assertTrue(self.probe.rstrip().endswith("rollback;"))
        self.assertNotIn("\ncommit;", self.probe)
        self.assertIn("r.status = 'succeeded'", self.probe)
        self.assertIn("limit 1 for update", self.probe)
        self.assertNotIn("insert into private.ordax_product_action_requests", self.probe)
        self.assertNotIn("delete from private.ordax_product_action_requests", self.probe)

    def test_postflight_exercises_fenced_denials_and_grace(self):
        for code in (
            "wrong_attempt_accepted", "wrong_lease_accepted",
            "wrong_epoch_accepted", "wrong_agent_accepted",
            "wrong_boot_accepted", "wrong_effect_accepted",
            "invalid_duration_accepted", "valid_leased_renewal_failed",
            "running_grace_renewal_failed", "renewal_modified_fencing",
            "retired_action_revived", "retirement_not_idempotent",
        ):
            self.assertIn("lease_postflight_" + code, self.probe)

    def test_canonical_renewal_matches_exact_fenced_execution(self):
        section = self.authority.split(
            "create or replace function public.ordax_renew_product_action_lease_v1(", 1
        )[1].split("create or replace function public.ordax_progress_product_action_v1(", 1)[0]
        for clause in (
            "p_lease_seconds not between 30 and 300",
            "set lease_expires_at = v_until", "request_id = p_request_id",
            "device_id = p_device_id", "effect_id = p_effect_id",
            "attempt_id = p_attempt_id", "lease_id = p_lease_id",
            "execution_epoch = p_execution_epoch",
            "agent_instance_id = p_agent_instance_id", "boot_id = p_boot_id",
            "status in ('leased','running')", "report_id is null",
        ):
            self.assertIn(clause, section)

    def test_retirement_preserves_unknown_outcome_not_automatic_retry(self):
        self.assertIn("error_code = 'execution_outcome_unconfirmed'", self.recovery)
        self.assertIn("interval '5 minutes'", self.recovery)
        self.assertIn("r.status = 'running'", self.recovery)
        self.assertIn("r.report_id is null", self.recovery)
        self.assertIn("r.lease_expires_at is not null", self.recovery)

    def test_device_transport_uses_single_postgres_renewal_rpc(self):
        self.assertIn("renewProductActionLease(env, { deviceId, ...ctx, leaseSeconds })", self.transport)
        self.assertIn('if (path === PRODUCT_DEVICE_TRANSPORT_PREFIX + "/lease")', self.transport)
        self.assertIn("agentInstanceId", self.transport)
        self.assertIn("executionEpoch", self.transport)
        self.assertIn("leaseId", self.transport)
        self.assertNotIn("env.DB", self.transport)


if __name__ == "__main__":
    unittest.main()
