from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (
    ROOT / "control-plane" / "supabase" / "migrations"
    / "20261021032000_central_session_operational_device_selection_v1.sql"
)


class OperationalDeviceSessionSelectionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8")

    def _function(self, qualified_name: str) -> str:
        pattern = (
            r"create or replace function "
            + re.escape(qualified_name)
            + r"\(.*?\)\s*returns.*?\n\$\$;"
        )
        match = re.search(pattern, self.sql, re.IGNORECASE | re.DOTALL)
        self.assertIsNotNone(match, f"function missing: {qualified_name}")
        return match.group(0)

    def test_operational_grant_eligibility_has_exactly_one_source_of_truth(self):
        eligible = self._function("private.ordax_central_device_grant_eligible_v1")
        for predicate in (
            "g.client_kind='product-mcp'",
            "g.client_id=p_client_id",
            "g.device_id=p_device_id",
            "g.scope_kind='device'",
            "g.state='active'",
            "g.profile_key <> 'mcp-discovery'",
            "g.capability <> 'product.target.read'",
            "g.space_id is null",
            "g.project_id is null",
            "d.state='active'",
            "g.valid_until>pg_catalog.clock_timestamp()",
        ):
            self.assertIn(predicate, eligible)

        opening = self._function("public.ordax_open_central_device_session_v1")
        self.assertIn("private.ordax_central_device_grant_eligible_v1(", opening)
        self.assertIn("p_owner_user_id,p_client_id,d.device_id", opening)
        self.assertIn("d.owner_user_id=p_owner_user_id", opening)
        self.assertNotIn("ordax_remote_capability_grants", opening)
        self.assertNotIn("mcp-discovery", opening)
        self.assertNotIn("product.target.read", opening)
        # A new grant profile must be handled in the single helper only.
        self.assertEqual(self.sql.count("g.profile_key <> 'mcp-discovery'"), 1)
        self.assertEqual(self.sql.count("g.capability <> 'product.target.read'"), 1)

    def test_two_operational_devices_remain_ambiguous(self):
        sql = self._function("public.ordax_open_central_device_session_v1")
        self.assertIn("cardinality(v_devices)<>1", sql)
        self.assertIn("central_device_target_ambiguous", sql)
        signature = sql.split("returns", 1)[0]
        self.assertNotIn("p_device_id", signature)
        self.assertIn("p_session_sha256", signature)

    def test_grant_and_credential_authorities_are_unchanged(self):
        lowered = self.sql.lower()
        for fragment in (
            "insert into public.ordax_remote_capability_grants",
            "update public.ordax_remote_capability_grants",
            "delete from public.ordax_remote_capability_grants",
            "ordax_confirm_central_device_session_v1(",
        ):
            self.assertNotIn(fragment, lowered)
        self.assertIn(
            "grant execute on function public.ordax_open_central_device_session_v1",
            lowered,
        )
        self.assertIn("to ordax_edge_executor", lowered)


if __name__ == "__main__":
    unittest.main()
