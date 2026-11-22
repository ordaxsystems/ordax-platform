"""The Runtime ActionRegistry projection is availability evidence, not an authority."""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "control-plane/supabase/migrations/"
          "20261122090000_product_runtime_capability_manifest_v1.sql")


class RuntimeCapabilityManifestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sql = SOURCE.read_text(encoding="utf-8").lower()

    def test_one_existing_device_presence_and_no_new_grant_authority(self) -> None:
        sql = self.sql
        self.assertIn("alter table public.ordax_device_presence", sql)
        self.assertIn("capability_manifest text[]", sql)
        self.assertIn("capability_manifest_digest text", sql)
        self.assertIn("ordax_authenticated_product_heartbeat_v2", sql)
        self.assertIn("ordax_record_product_heartbeat_v1", sql)
        self.assertIn("ordax_authenticate_product_device_v1", sql)
        self.assertNotIn("create table", sql)
        self.assertNotIn("insert into public.ordax_remote_capability_grants", sql)
        self.assertNotIn("update public.ordax_remote_capability_grants", sql)

    def test_device_manifest_cannot_become_persistent_or_grant_authority(self) -> None:
        sql = self.sql
        self.assertIn("p.capability_manifest_digest = p.capability_digest", sql)
        self.assertIn("p.last_seen_at > pg_catalog.statement_timestamp() - interval '6 minutes'", sql)
        self.assertIn("p.online = true", sql)
        self.assertIn("p_actions is distinct from array(", sql)
        self.assertIn("revoke all on function public.ordax_authenticated_product_heartbeat_v2", sql)
        self.assertIn("to ordax_edge_executor", sql)
        self.assertIn("'runtime_capabilities', t.runtime_capabilities", sql)


if __name__ == "__main__":
    unittest.main()
