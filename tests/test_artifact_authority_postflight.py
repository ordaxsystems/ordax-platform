"""PostgreSQL artifact postflight must stay rollback-only, nondeploying and finite."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / "control-plane" / "supabase" / "tests" / "artifact_authority_postflight.sql"


class ArtifactAuthorityPostflightContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sql = SQL.read_text(encoding="utf-8")

    def test_safe_transaction_boundaries(self):
        commands = [
            line.strip().upper()
            for line in self.sql.splitlines()
            if line.strip() and not line.strip().startswith("--")
        ]
        self.assertEqual(commands[0], "BEGIN;")
        self.assertEqual(commands[-1], "ROLLBACK;")
        self.assertNotIn("COMMIT;", commands)
        self.assertIn("SET LOCAL statement_timeout = '20s';", self.sql)
        self.assertIn("pg_catalog.gen_random_uuid()", self.sql)
        self.assertIn("postflight-no-r2", self.sql)
        self.assertNotIn("ORDAX_OPERATOR_TOKEN", self.sql)
        for forbidden in ("DROP TABLE ", "TRUNCATE TABLE ", "ALTER TABLE ", "GRANT ALL ",
                          "CREATE TABLE ", "DELETE FROM PRIVATE."):
            self.assertNotIn(forbidden, self.sql.upper())

    def test_authority_contract_covered_without_r2_or_real_runtime(self):
        for entry in (
            "ordax_create_artifact_upload_v1",
            "ordax_get_artifact_upload_v1",
            "ordax_publish_artifact_v1",
            "ordax_authorize_artifact_download_v1",
            "ordax_rotate_artifact_read_token_v1",
            "ordax_list_artifact_device_objects_v1",
            "ordax_list_artifact_retention_candidates_v1",
            "ordax_begin_product_artifact_upload_v1",
            "ordax_commit_product_artifact_v1",
            "ordax_get_product_artifact_upload_v1",
            "ordax_refresh_product_artifact_read_v1",
            "ordax_delete_artifact_record_v1",
            "ordax_delete_artifact_upload_v1",
            "lease_not_active",
            "multipart_upload_conflict",
            "artifact_replay_conflict",
            "artifact_token_invalid_or_expired",
        ):
            with self.subTest(entry=entry):
                self.assertIn(entry, self.sql)

    def test_deny_leaking_real_device_or_r2_artifact(self):
        self.assertIn("Synthetic metadata ONLY", self.sql)
        self.assertIn("ROLLBACK;", self.sql)
        self.assertIn("fake-boot", self.sql)
        self.assertNotIn("r2.put", self.sql.lower())
        self.assertNotIn("s3:PutObject", self.sql)


if __name__ == "__main__":
    unittest.main()
