import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "control-plane" / "supabase" / "migrations" / "20261113223950_owner_github_installation_authority_v1.sql"
WORKER = ROOT / "control-plane" / "cloudflare" / "src" / "product_owner_github_authorization.ts"


class OwnerGithubInstallationBoundaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8")
        cls.worker = WORKER.read_text(encoding="utf-8")
        cls.lowered = cls.sql.lower()

    def test_provider_tokens_are_never_persisted(self):
        for forbidden in (
            "access_token", "refresh_token", "client_secret", "code_verifier",
            "github_token", "oauth_token",
        ):
            self.assertNotIn(forbidden, self.lowered)
        self.assertIn("state_sha256", self.lowered)
        self.assertNotIn("state text", self.lowered)

    def test_ephemeral_authority_tables_stay_private(self):
        self.assertIn(
            "create table private.ordax_owner_github_authorization_challenges",
            self.lowered,
        )
        self.assertIn(
            "create table private.ordax_owner_github_repository_candidates",
            self.lowered,
        )
        self.assertNotIn("grant select on table private.", self.lowered)
        self.assertNotIn("grant insert on table private.", self.lowered)
        self.assertNotIn("grant update on table private.", self.lowered)
        self.assertNotIn("grant delete on table private.", self.lowered)
        self.assertIn(
            "has_schema_privilege(\n    'ordax_owner_project_onboarding_executor', 'private', 'usage'",
            self.lowered,
        )

    def test_only_reviewed_security_definer_rpcs_can_mutate_connection(self):
        self.assertIn("security definer", self.lowered)
        self.assertIn("ordax_owner_select_github_repository_v1", self.lowered)
        self.assertIn(
            "from private.ordax_owner_github_repository_candidates r",
            self.lowered,
        )
        self.assertIn(
            "insert into public.ordax_project_connections",
            self.lowered,
        )
        self.assertIn(
            "grant execute on function public.ordax_owner_select_github_repository_v1",
            self.lowered,
        )
        self.assertNotRegex(
            self.lowered,
            r"grant\s+(insert|update|delete)\s+on\s+(?:table\s+)?public\.ordax_project_connections",
        )

    def test_selection_is_by_verified_candidate_not_browser_installation(self):
        select_start = self.lowered.index(
            "create function public.ordax_owner_select_github_repository_v1"
        )
        select_sql = self.lowered[select_start:]
        self.assertIn("p_repository_id text", select_sql)
        self.assertNotIn("p_installation_id", select_sql)
        self.assertNotIn("p_repository_full_name", select_sql)
        self.assertIn(
            "r.repository_id = p_repository_id::bigint",
            select_sql,
        )
        self.assertIn(
            "github_repository_not_verified",
            select_sql,
        )

    def test_challenge_is_one_way_and_completion_is_one_shot(self):
        self.assertRegex(self.sql, r"state_sha256\s+text\s+not null")
        self.assertIn("status = 'verifying'", self.lowered)
        self.assertIn("c.status = 'pending'", self.lowered)
        self.assertIn("c.status = 'verifying'", self.lowered)
        self.assertIn("c.status = 'verified'", self.lowered)
        self.assertIn("set status = 'selected'", self.lowered)

    def test_worker_uses_user_authorization_and_never_app_installation_token(self):
        self.assertIn("https://github.com/login/oauth/access_token", self.worker)
        self.assertIn('"/user/installations?per_page=100&page=1"', self.worker)
        self.assertIn('"/repositories?per_page=100&page="', self.worker)
        self.assertIn("code_challenge_method", self.worker)
        self.assertIn("PRODUCT_GITHUB_APP_PKCE_SECRET", self.worker)
        self.assertNotIn("/app/installations/", self.worker)
        self.assertNotIn("repository_ids", self.worker)
        self.assertNotIn("installation access token", self.worker.lower())

    def test_worker_never_accepts_provider_identity_on_selection(self):
        selection = self.worker[self.worker.index(
            'PRODUCT_OWNER_GITHUB_REPOSITORY_SELECTIONS_PATH'
        ):]
        self.assertIn(
            'exactObjectKeys(body, ["challenge_id", "repository_id", "confirm"])',
            selection,
        )
        self.assertNotIn(
            'exactObjectKeys(body, ["installation_id"',
            selection,
        )


if __name__ == "__main__":
    unittest.main()
