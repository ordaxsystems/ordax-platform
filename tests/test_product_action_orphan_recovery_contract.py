"""Contract protections for recovery of fenced, orphaned running actions."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / "control-plane/supabase/migrations/20261020154500_product_orphaned_running_lease_recovery_v1.sql"
POSTFLIGHT = ROOT / "control-plane/supabase/tests/product_orphaned_running_lease_recovery_postflight.sql"


class ProductOrphanedRunningLeaseContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = SQL.read_text(encoding="utf-8").lower()
        cls.probe = POSTFLIGHT.read_text(encoding="utf-8").lower()

    def test_orphan_retirement_does_not_redispatch_or_change_fencing(self):
        sql = self.sql.split("create or replace function private.ordax_retire_orphaned_running_product_actions_v1", 1)[1].split(
            "create or replace function public.", 1
        )[0]
        for clause in (
            "r.status = 'running'", "r.report_id is null", "r.device_id = p_device_id",
            "r.lease_expires_at is not null", "interval '5 minutes'",
            "set status = 'failed'", "error_code = 'execution_outcome_unconfirmed'",
            "lease_expires_at = null", "finished_at = pg_catalog.clock_timestamp()",
            "'execution_outcome_unconfirmed'", "insert into private.ordax_product_action_audit",
        ):
            self.assertIn(clause, sql)
        for forbidden in ("execution_epoch =", "attempt_id =", "effect_id =", "agent_instance_id =", "boot_id ="):
            self.assertNotIn(forbidden, sql)

    def test_status_scopes_owner_and_client_before_orphan_mutation(self):
        section = self.sql.split("create or replace function public.ordax_get_product_action_v1", 1)[1].split(
            "create or replace function public.ordax_claim_product_action_v1", 1
        )[0]
        for clause in (
            "r.owner_user_id = p_owner_user_id",
            "r.client_kind = p_client_kind",
            "r.client_id = p_client_id",
            "r.request_id = p_request_id",
            "private.ordax_retire_orphaned_running_product_actions_v1(v_device_id, p_request_id)",
        ):
            self.assertIn(clause, section)
        self.assertLess(section.index("select r.device_id into v_device_id"), section.index(
            "private.ordax_retire_orphaned_running_product_actions_v1"
        ))

    def test_claim_retires_orphans_under_existing_device_lock(self):
        section = self.sql.split("create or replace function public.ordax_claim_product_action_v1", 1)[1].split(
            "create or replace function public.ordax_report_product_action_v1", 1
        )[0]
        self.assertLess(section.index("pg_advisory_xact_lock"), section.index(
            "private.ordax_retire_orphaned_running_product_actions_v1"))
        self.assertLess(section.index("private.ordax_retire_orphaned_running_product_actions_v1"),
                        section.index("if exists ("))
        self.assertIn("r.status = 'running'", section)
        self.assertIn("for update skip locked", section)

    def test_late_report_is_only_reconciled_for_same_original_execution(self):
        section = self.sql.split("create or replace function public.ordax_report_product_action_v1", 1)[1]
        for key in (
            "v_row.status = 'failed'", "v_row.error_code = 'execution_outcome_unconfirmed'",
            "v_row.report_id is null", "v_row.effect_id = p_effect_id",
            "v_row.attempt_id = p_attempt_id", "v_row.lease_id = p_lease_id",
            "v_row.execution_epoch = p_execution_epoch",
            "v_row.agent_instance_id = p_agent_instance_id",
            "v_row.boot_id = p_boot_id",
            "and not v_late_original_report",
            "terminal_report_conflict", "lease_not_active",
        ):
            self.assertIn(key, section)

    def test_private_helper_and_exact_existing_edge_authorities(self):
        self.assertIn("security invoker", self.sql)
        self.assertIn("revoke all on function private.ordax_retire_orphaned_running_product_actions_v1", self.sql)
        for signature in (
            "public.ordax_get_product_action_v1(uuid,text,text,uuid)",
            "public.ordax_claim_product_action_v1(uuid,uuid,text,integer)",
            "public.ordax_report_product_action_v1(uuid,uuid,uuid,uuid,uuid,bigint,uuid,text,uuid,text,jsonb,text,text)",
        ):
            self.assertIn("revoke all on function " + signature, self.sql)
            self.assertIn("grant execute on function " + signature, self.sql)

    def test_sql_postflight_is_rollback_only_and_exercises_real_fences(self):
        self.assertTrue(self.probe.strip().endswith("rollback;"))
        self.assertNotIn("commit;", self.probe)
        for phrase in (
            "orphan_running_wrong_attempt_accepted",
            "orphan_running_legitimate_late_report_denied",
            "orphan_running_late_report_not_idempotent",
            "orphan_running_lease_grace_violated",
            "orphan_running_cross_client_read",
        ):
            self.assertIn(phrase, self.probe)


if __name__ == "__main__":
    unittest.main()
