"""Regression for Central sessions opened only after an actual Product action
Runtime heartbeat. This consumes the latest canonical PostgreSQL function
replacement; it is not an alternate selector, grant or source of presence.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (ROOT / "control-plane" / "supabase" / "migrations"
             / "20261022154600_central_session_runtime_heartbeat_preflight_v1.sql")


class CentralRuntimeHeartbeatPreflightContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8")
        cls.opening = cls.sql.split(
            "create or replace function public.ordax_open_central_device_session_v1(", 1
        )[1].split("\n$$;", 1)[0]

    def test_discovery_only_cannot_open_pending_challenge(self):
        sql = self.opening
        offline = sql.index("'central_device_offline'")
        runtime = sql.index("'central_device_runtime_not_ready'")
        existing = sql.index("if v_existing.device_id is not null then")
        challenge = sql.index("insert into private.ordax_central_device_session_challenges(")
        self.assertLess(offline, runtime)
        self.assertLess(runtime, existing)
        self.assertLess(runtime, challenge)
        self.assertIn("from public.ordax_device_presence p", sql)
        self.assertIn("p.agent_version is not null", sql)
        self.assertIn("p.capability_digest ~ '^[0-9a-f]{64}$'", sql)
        self.assertIn("private.ordax_product_presence_online_v1(", sql)
        self.assertEqual(sql.count("'central_device_runtime_not_ready'"), 1)

    def test_does_not_replace_device_selection_or_allow_model_selected_target(self):
        sql = self.opening
        signature = sql.split(")\nreturns", 1)[0]
        self.assertNotIn("p_device_id", signature)
        self.assertIn("private.ordax_central_device_grant_eligible_v1(", sql)
        self.assertIn("cardinality(v_devices)<>1", sql)
        self.assertIn("'central_device_target_ambiguous'", sql)
        self.assertIn("v_existing.state='revoked'", sql)
        self.assertIn("'central_session_target_mismatch'", sql)
        self.assertIn("interval '2 minutes'", sql)
        self.assertIn("interval '30 minutes'", sql)
        self.assertIn("state='pending'", sql)
        self.assertNotIn("insert into public.ordax_remote_capability_grants", self.sql.lower())
        self.assertNotIn("update public.ordax_remote_capability_grants", self.sql.lower())
        self.assertNotIn("delete from public.ordax_remote_capability_grants", self.sql.lower())

    def test_existing_credential_attestation_and_executor_acl_stay_unchanged(self):
        self.assertEqual(
            self.sql.count("create or replace function public.ordax_open_central_device_session_v1("), 1
        )
        self.assertNotIn("ordax_confirm_central_device_session_v1(", self.sql)
        self.assertIn("from public,anon,authenticated,service_role;", self.sql)
        self.assertIn("to ordax_edge_executor;", self.sql)
        self.assertIn("to_regprocedure('private.ordax_product_presence_online_v1(", self.sql)
        self.assertIn("\nbegin;\n", self.sql)


if __name__ == "__main__":
    unittest.main()
