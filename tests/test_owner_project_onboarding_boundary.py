"""Regression guard for the Owner onboarding security boundary (#220).

These are source-contract checks, not proof of database deployment or E2E.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "control-plane" / "supabase" / "migrations"
SRC = ROOT / "control-plane" / "cloudflare" / "src"


class OwnerProjectOnboardingBoundaryTest(unittest.TestCase):
    def test_space_creation_remains_dedicated_rpc(self):
        sql = (MIGRATIONS / "20261007193000_space_authority_v1.sql").read_text()
        self.assertIn("create function public.ordax_create_space_v1(", sql)
        self.assertIn("nologin", sql.lower())
        self.assertIn("to ordax_space_executor;", sql)
        self.assertIn("from public, anon, authenticated, service_role, ordax_edge_executor, ordax_space_executor;", sql)

    def test_project_creation_remains_dedicated_rpc(self):
        sql = (MIGRATIONS / "20261007193500_project_authority_v1.sql").read_text()
        self.assertIn("create function public.ordax_create_project_v1(", sql)
        self.assertIn("to ordax_project_executor;", sql)
        self.assertIn("from public, anon, authenticated, service_role, ordax_edge_executor, ordax_space_executor, ordax_project_executor;", sql)

    def test_repository_connection_has_no_generic_mutation_authority(self):
        sql = (MIGRATIONS / "20261007194000_project_connection_contract_hardening_v1.sql").read_text()
        self.assertIn("ordax_project_connections_github_selection_check", sql)
        for role in ("authenticated", "service_role", "ordax_edge_executor", "ordax_project_executor"):
            for operation in ("INSERT", "UPDATE", "DELETE"):
                self.assertIn(
                    f"has_table_privilege('{role}', 'public.ordax_project_connections', '{operation}')",
                    sql,
                )

    def test_native_grants_are_distinct_and_project_scoped(self):
        ts = (SRC / "product_owner_grant_profiles.ts").read_text()
        self.assertIn('"project-native-terminal": profile("project", ["terminal.exec"])', ts)
        self.assertIn('"project-native-process": profile("project", [', ts)
        self.assertIn('"process.list"', ts)
        self.assertIn('"process.start"', ts)

    def test_project_scope_resolver_requires_both_device_bindings(self):
        sql = (MIGRATIONS / "20261016141000_owner_project_scope_resolver_v1.sql").read_text()
        self.assertIn("public.ordax_space_devices", sql)
        self.assertIn("public.ordax_device_project_bindings", sql)
        self.assertIn("private.ordax_subject_can_admin_space_v1", sql)
        self.assertIn("'owner_project_scope_ambiguous'", sql)
        self.assertIn("'owner_project_scope_not_found'", sql)


if __name__ == "__main__":
    unittest.main()
