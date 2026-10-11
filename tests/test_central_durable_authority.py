"""Source contract of the one canonical Central request/ChatGPT session binding.

Database authority is PostgreSQL (migration + actual installed postflight).
These static tests do not claim to have authenticated with ChatGPT.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "control-plane/supabase/migrations/20261007213500_central_durable_conversation_binding_v1.sql"
POSTFLIGHT = ROOT / "control-plane/supabase/tests/central_conversation_binding_postflight.sql"
STORE = ROOT / "control-plane/cloudflare/src/product_postgres_store.ts"
ADMISSION = ROOT / "control-plane/cloudflare/src/product_central_admission.ts"

class CentralDurableContract(unittest.TestCase):
    def setUp(self):
        self.sql = MIGRATION.read_text(encoding="utf-8").lower()
        self.probe = POSTFLIGHT.read_text(encoding="utf-8").lower()
        self.store = STORE.read_text(encoding="utf-8")
        self.admission = ADMISSION.read_text(encoding="utf-8")

    def test_only_one_private_mapping_not_an_action_history(self):
        self.assertEqual(self.sql.count("create table private."), 1)
        self.assertIn("create table private.ordax_central_conversation_bindings", self.sql)
        self.assertNotIn("create table public.", self.sql)
        self.assertIn("request_id uuid primary key", self.sql)
        self.assertIn("constraint central_binding_unique_session unique(owner_user_id,client_id,session_sha256)", self.sql)
        self.assertIn("constraint central_binding_unique_web_chat unique(owner_user_id,client_id,conversation_id)", self.sql)
        self.assertIn("force row level security", self.sql)

    def test_device_scope_and_oauth_client_immutable_and_grants_rechecked(self):
        for x in (
            "b.owner_user_id=p_owner_user_id",
            "b.client_id=p_client_id",
            "b.device_id=p_device_id",
            "b.space_id is not distinct from p_space_id",
            "b.project_id is not distinct from p_project_id",
            "b.request_id=p_request_id",
            "b.conversation_id=p_conversation_id",
            "b.session_sha256=p_session_sha256",
            "b.state='active'",
            "b.expires_at>pg_catalog.clock_timestamp()",
            "g.client_id=p_client_id",
            "g.state='active'",
            "g.access_mode='read'",
            "g.valid_until>pg_catalog.clock_timestamp()",
            "d.state='active'",
        ):
            self.assertIn(x, self.sql, x)
        self.assertIn("private.ordax_trusted_actor_auth_eligible_v1", self.sql)
        self.assertIn("p_expires_at > v_now + interval '30 minutes'", self.sql)
        self.assertIn("on conflict do nothing", self.sql)
        self.assertIn("alter table private.ordax_central_conversation_bindings enable row level security", self.sql)

    def test_roles_cannot_mint_sessions_from_model_or_service_anon(self):
        for x in (
            "revoke all on table private.ordax_central_conversation_bindings",
            "from public,anon,authenticated,service_role,ordax_edge_executor,ordax_edge_runtime",
            "grant execute on function public.ordax_bind_central_conversation_v1",
            "grant execute on function public.ordax_verify_central_conversation_v1",
            "grant execute on function public.ordax_revoke_central_conversation_v1",
            "to ordax_edge_executor;",
        ):
            self.assertIn(x, self.sql)
        self.assertIn("'anon','authenticated','service_role','ordax_edge_runtime'", self.probe)
        self.assertIn("central_session_table_acl_exposed", self.probe)

    def test_web_transport_never_mints_authorization_implicitly(self):
        self.assertIn("crypto.subtle.digest", self.store)
        self.assertIn('ordax_verify_central_conversation_v1', self.store)
        self.assertIn("export function createPostgresCentralSessionVerifier", self.admission)
        self.assertIn("validChatGptSessionMarker(binding.sessionId)", self.admission)
        self.assertIn("verifyProductCentralConversation", self.admission)
        self.assertNotIn("legacy D1 fallback", self.sql)

    def test_postflight_checks_installed_function_and_no_binding_denied(self):
        for x in ("pg_get_functiondef", "central_session_schema_or_rls_missing",
                  "central_session_verify_not_exact",
                  "central_session_missing_binding_was_authorized"):
            self.assertIn(x, self.probe)


if __name__ == "__main__":
    unittest.main()
