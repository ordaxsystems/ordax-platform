"""Contract tests for Product action expiration at the PostgreSQL authority."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "control-plane/supabase/migrations/20261020091500_product_action_queued_expiration_v1.sql"


class ProductActionExpiryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8").lower()

    def test_expiry_transitions_only_queued_actions(self):
        sql = self.sql
        self.assertIn("create or replace function private.ordax_expire_queued_product_actions_v1", sql)
        self.assertIn("r.status = 'queued'", sql)
        self.assertIn("r.expires_at <= pg_catalog.clock_timestamp()", sql)
        self.assertIn("set status = 'failed'", sql)
        self.assertIn("error_code = 'action_expired'", sql)
        self.assertIn("finished_at = pg_catalog.clock_timestamp()", sql)
        self.assertNotIn("set status = 'cancelled'", sql)

    def test_get_scopes_authority_before_expiry_mutation(self):
        sql = self.sql
        section = sql.split("create or replace function public.ordax_get_product_action_v1(", 1)[1].split(
            "create or replace function public.ordax_claim_product_action_v1(", 1
        )[0]
        for clause in (
            "r.owner_user_id = p_owner_user_id", "r.client_kind = p_client_kind",
            "r.client_id = p_client_id", "r.request_id = p_request_id",
        ):
            self.assertIn(clause, section)
        self.assertLess(section.index("select r.device_id into v_device_id"), section.index(
            "perform private.ordax_expire_queued_product_actions_v1"
        ))
        self.assertIn("'execution_runtime_kind', r.execution_runtime_kind", section)
        self.assertIn("'execution_agent_version', r.execution_agent_version", section)

    def test_claim_sweeps_before_select_and_rechecks_expiry_on_lease(self):
        sql = self.sql
        section = sql.split("create or replace function public.ordax_claim_product_action_v1(", 1)[1]
        self.assertLess(section.index("pg_advisory_xact_lock"), section.index(
            "perform private.ordax_expire_queued_product_actions_v1"
        ))
        self.assertLess(section.index("perform private.ordax_expire_queued_product_actions_v1"), section.index(
            "select * into v_job"
        ))
        self.assertIn("and expires_at > pg_catalog.clock_timestamp()", section)
        self.assertIn("if not found then", section)

    def test_acl_stays_private_and_exact_client_isolation(self):
        sql = self.sql
        self.assertIn("security invoker", sql)
        self.assertIn("security definer", sql)
        self.assertIn("revoke all on function private.ordax_expire_queued_product_actions_v1", sql)
        for signature in (
            "public.ordax_get_product_action_v1(uuid,text,text,uuid)",
            "public.ordax_claim_product_action_v1(uuid,uuid,text,integer)",
        ):
            self.assertIn("revoke all on function " + signature, sql)
            self.assertIn("grant execute on function " + signature, sql)


if __name__ == "__main__":
    unittest.main()
