"""Contract tests for Product action expiration at the PostgreSQL authority."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASE_MIGRATION = ROOT / "control-plane/supabase/migrations/20261020091500_product_action_queued_expiration_v1.sql"
EXPIRED_STATE_MIGRATION = ROOT / "control-plane/supabase/migrations/20261113182849_product_action_expired_state_v1.sql"
POSTFLIGHT = ROOT / "control-plane/supabase/tests/product_action_queued_expiration_postflight.sql"
MCP_HTTP = ROOT / "control-plane/cloudflare/src/mcp_http.ts"


class ProductActionExpiryContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_sql = BASE_MIGRATION.read_text(encoding="utf-8").lower()
        cls.state_sql = EXPIRED_STATE_MIGRATION.read_text(encoding="utf-8").lower()
        cls.postflight = POSTFLIGHT.read_text(encoding="utf-8").lower()
        cls.mcp_http = MCP_HTTP.read_text(encoding="utf-8")

    def test_expiry_transitions_only_queued_actions_to_expired(self):
        sql = self.state_sql
        self.assertIn("create or replace function private.ordax_expire_queued_product_actions_v1", sql)
        self.assertIn("r.status = 'queued'", sql)
        self.assertIn("r.expires_at <= pg_catalog.clock_timestamp()", sql)
        self.assertIn("set status = 'expired'", sql)
        self.assertIn("error_code = 'action_expired'", sql)
        self.assertIn("finished_at = pg_catalog.clock_timestamp()", sql)
        self.assertNotIn("set status = 'failed'", sql)
        self.assertNotIn("set status = 'cancelled'", sql)

    def test_status_constraint_adds_expired_without_removing_existing_states(self):
        sql = self.state_sql
        self.assertIn("drop constraint ordax_product_action_requests_status_check", sql)
        self.assertIn("add constraint ordax_product_action_requests_status_check", sql)
        for state in ("queued", "leased", "running", "succeeded", "failed", "cancelled", "expired"):
            self.assertIn(f"'{state}'::text", sql)

    def test_backfill_is_restricted_to_actions_that_never_started(self):
        section = self.state_sql.split("-- historical action_expired rows", 1)[1].split(
            "revoke all on function", 1
        )[0]
        for clause in (
            "where status = 'failed'",
            "error_code = 'action_expired'",
            "started_at is null",
            "attempt_id is null",
            "lease_id is null",
            "report_id is null",
        ):
            self.assertIn(clause, section)
        self.assertIn("set status = 'expired'", section)

    def test_get_scopes_authority_before_expiry_mutation(self):
        section = self.base_sql.split(
            "create or replace function public.ordax_get_product_action_v1(", 1
        )[1].split("create or replace function public.ordax_claim_product_action_v1(", 1)[0]
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
        section = self.base_sql.split(
            "create or replace function public.ordax_claim_product_action_v1(", 1
        )[1]
        self.assertLess(section.index("pg_advisory_xact_lock"), section.index(
            "perform private.ordax_expire_queued_product_actions_v1"
        ))
        self.assertLess(section.index("perform private.ordax_expire_queued_product_actions_v1"), section.index(
            "select * into v_job"
        ))
        self.assertIn("and expires_at > pg_catalog.clock_timestamp()", section)
        self.assertIn("if not found then", section)

    def test_acl_stays_private_and_exact_client_isolation(self):
        self.assertIn("security invoker", self.state_sql)
        self.assertIn(
            "revoke all on function private.ordax_expire_queued_product_actions_v1",
            self.state_sql,
        )
        for signature in (
            "public.ordax_get_product_action_v1(uuid,text,text,uuid)",
            "public.ordax_claim_product_action_v1(uuid,uuid,text,integer)",
        ):
            self.assertIn("revoke all on function " + signature, self.base_sql)
            self.assertIn("grant execute on function " + signature, self.base_sql)

    def test_mcp_projects_expired_as_terminal_not_pending(self):
        self.assertIn(
            'const ACTION_STATUSES = new Set(["queued", "leased", "running", "succeeded", "failed", "cancelled", "expired"]);',
            self.mcp_http,
        )
        self.assertIn(
            'const pending = !["succeeded", "failed", "cancelled", "expired"].includes(status);',
            self.mcp_http,
        )

    def test_postflight_is_rollback_only_and_requires_distinct_expired_state(self):
        self.assertTrue(self.postflight.strip().endswith("rollback;"))
        self.assertNotIn("commit;", self.postflight)
        for phrase in (
            "status = 'expired'",
            "started_at is null",
            "attempt_id is null",
            "lease_id is null",
            "product_action_expiry_not_distinct_terminal_state",
            "product_action_expiry_client_isolation_failed",
        ):
            self.assertIn(phrase, self.postflight)


if __name__ == "__main__":
    unittest.main()
