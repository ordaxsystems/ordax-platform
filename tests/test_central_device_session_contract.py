from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "control-plane" / "supabase" / "migrations" / "20261015133000_central_device_attested_session_v1.sql"


class CentralDeviceSessionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8")

    def test_model_cannot_select_device_when_opening_session(self):
        signature = re.search(
            r"create function public\.ordax_open_central_device_session_v1\((.*?)\)\s*returns",
            self.sql,
            re.S | re.I,
        )
        self.assertIsNotNone(signature)
        args = signature.group(1)
        self.assertIn("p_owner_user_id", args)
        self.assertIn("p_client_id", args)
        self.assertIn("p_session_sha256", args)
        self.assertNotIn("p_device_id", args)
        self.assertIn("cardinality(v_devices)<>1", self.sql)
        self.assertIn("central_device_target_ambiguous", self.sql)

    def test_confirmation_requires_exact_product_device_credential(self):
        self.assertIn("p_token_sha256 text,p_challenge_id uuid", self.sql)
        self.assertIn("private.ordax_product_device_credentials", self.sql)
        self.assertIn("c.device_id=p_device_id and c.token_sha256=p_token_sha256", self.sql)
        self.assertIn("c.revoked_at is null", self.sql)
        self.assertIn("v_challenge.device_id<>p_device_id", self.sql)

    def test_binding_does_not_mint_or_modify_capability_grants(self):
        lowered = self.sql.lower()
        forbidden = (
            "insert into public.ordax_remote_capability_grants",
            "update public.ordax_remote_capability_grants",
            "delete from public.ordax_remote_capability_grants",
        )
        for fragment in forbidden:
            self.assertNotIn(fragment, lowered)
        self.assertIn("central_device_grant_revoked", self.sql)

    def test_generic_bind_and_revoke_remain_outside_edge_executor(self):
        self.assertIn(
            "has_function_privilege('ordax_edge_executor',v_bind,'EXECUTE')",
            self.sql,
        )
        self.assertIn(
            "has_function_privilege('ordax_edge_executor',v_revoke,'EXECUTE')",
            self.sql,
        )
        self.assertNotIn(
            "grant execute on function public.ordax_bind_central_conversation_v1",
            self.sql.lower(),
        )
        self.assertNotIn(
            "grant execute on function public.ordax_revoke_central_conversation_v1",
            self.sql.lower(),
        )

    def test_challenge_and_binding_are_bounded(self):
        self.assertIn("interval '2 minutes'", self.sql)
        self.assertIn("interval '30 minutes'", self.sql)
        self.assertIn("central_device_session_pending_unique", self.sql)
        self.assertIn("state in ('pending','confirmed','expired')", self.sql)

    def test_session_resolution_rechecks_current_device_grant(self):
        self.assertIn("ordax_resolve_central_device_session_v1", self.sql)
        self.assertIn("private.ordax_central_device_grant_eligible_v1", self.sql)
        self.assertIn("b.state='active' and b.expires_at>v_now", self.sql)


if __name__ == "__main__":
    unittest.main()
