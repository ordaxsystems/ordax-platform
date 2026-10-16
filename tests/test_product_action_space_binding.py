from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = (
    ROOT
    / "control-plane"
    / "supabase"
    / "migrations"
    / "20261016201500_product_action_space_binding_v1.sql"
)


class ProductActionSpaceBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sql = MIGRATION.read_text(encoding="utf-8")
        cls.lower = cls.sql.lower()

    def test_action_status_projects_server_owned_space_without_weakening_identity_scope(self) -> None:
        self.assertIn("create or replace function public.ordax_get_product_action_v1(", self.lower)
        self.assertIn("'space_id', r.space_id", self.sql)
        self.assertIn("'project_id', r.project_id", self.sql)
        self.assertIn("'execution_runtime_kind', r.execution_runtime_kind", self.sql)
        self.assertIn("'execution_agent_version', r.execution_agent_version", self.sql)
        self.assertIn("and r.owner_user_id = p_owner_user_id", self.sql)
        self.assertIn("and r.client_kind = p_client_kind", self.sql)
        self.assertIn("and r.client_id = p_client_id", self.sql)
        self.assertIn("and r.request_id = p_request_id", self.sql)
        self.assertNotIn("p_space_id", self.sql)
        self.assertNotIn("p_project_id", self.sql)

    def test_action_status_rpc_remains_edge_executor_only(self) -> None:
        signature = "public.ordax_get_product_action_v1(uuid, text, text, uuid)"
        self.assertIn(f"revoke all on function {signature}", self.lower)
        self.assertIn("from public, anon, authenticated, service_role, ordax_edge_executor", self.lower)
        self.assertIn(f"grant execute on function {signature}", self.lower)
        self.assertIn("to ordax_edge_executor", self.lower)
        self.assertNotIn("to authenticated", self.lower.split("grant execute", 1)[1])
        self.assertNotIn("to service_role", self.lower.split("grant execute", 1)[1])


if __name__ == "__main__":
    unittest.main()
