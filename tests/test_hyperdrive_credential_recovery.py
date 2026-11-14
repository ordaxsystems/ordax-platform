"""Contracts for canonical Hyperdrive SSOT reconciliation without real writes."""
from contextlib import redirect_stdout
from io import BytesIO, StringIO
import importlib.util
import json
import os
from pathlib import Path
import urllib.error
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "scripts/cloudflare/recover_mcp_hyperdrive.py"
spec = importlib.util.spec_from_file_location("ordax_hyperdrive_recovery", FILE)
recovery = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(recovery)


def hyperdrive_result(origin: dict) -> dict:
    return {
        "success": True,
        "result": {
            "id": recovery.HYPERDRIVE,
            "name": recovery.HYPERDRIVE_NAME,
            "origin": origin,
            "mtls": {"sslmode": recovery.SSLMODE},
            "caching": {"disabled": True},
            "origin_connection_limit": recovery.CONNECTION_LIMIT,
        },
    }


def canonical_origin() -> dict:
    return {
        "host": recovery.HOST,
        "port": recovery.PORT,
        "database": recovery.DATABASE,
        "scheme": "postgres",
        "user": recovery.ROLE,
    }


def migration_origin() -> dict:
    return {
        "host": "synthetic.pooler.supabase.com",
        "port": 5432,
        "database": recovery.DATABASE,
        "scheme": "postgres",
        "user": recovery.ROLE + "." + recovery.PROJECT,
    }


class RecoveryContracts(unittest.TestCase):
    def test_foundation_is_single_direct_origin_authority(self):
        foundation = json.loads(
            (ROOT / "control-plane/cloudflare/production-foundation.json").read_text("utf-8")
        )
        hyper = foundation["live_evidence"]["hyperdrive"]
        self.assertEqual(recovery.HOST, hyper["origin_host"])
        self.assertEqual(recovery.PORT, hyper["origin_port"])
        self.assertEqual(recovery.DATABASE, hyper["database"])
        self.assertEqual(recovery.ROLE, hyper["runtime_role"])
        self.assertEqual(recovery.HYPERDRIVE, hyper["id"])
        self.assertEqual(recovery.HYPERDRIVE_NAME, hyper["name"])
        self.assertEqual(recovery.HOST, f"db.{recovery.PROJECT}.supabase.co")
        self.assertNotIn("pooler.supabase.com", recovery.HOST)
        source = FILE.read_text("utf-8")
        self.assertIn("production-foundation.json", source)
        self.assertNotIn("aws-1-sa-east-1.pooler.supabase.com", source)

    def test_sql_literal_quotes_do_not_escape_statement(self):
        self.assertEqual(recovery.literal("a'b"), "'a''b'")

    def test_read_only_verifier_response_shape(self):
        verifier = {"verifier": "SCRAM-SHA-256$fake", "login": True, "valid": True}
        self.assertEqual(recovery.response_rows([verifier]), [verifier])
        self.assertEqual(recovery.response_rows({"result": [verifier]}), [verifier])
        self.assertEqual(recovery.response_rows({"data": [verifier]}), [verifier])
        with self.assertRaises(recovery.RecoveryFailure):
            recovery.response_rows({"unexpected": True})

    def test_missing_authority_never_writes(self):
        with mock.patch.dict(os.environ, {}, clear=True),              mock.patch.object(recovery, "request") as request:
            out = StringIO()
            with redirect_stdout(out):
                self.assertEqual(recovery.main(), 3)
            request.assert_not_called()
            self.assertIn("BLOCKED_MISSING_AUTHORIZED_CREDENTIALS", out.getvalue())

    def test_hyperdrive_accepts_canonical_origin(self):
        with mock.patch.object(
            recovery, "request", return_value=hyperdrive_result(canonical_origin())
        ):
            self.assertEqual(recovery.assert_hyperdrive("fake"), "canonical")

    def test_known_supabase_pooler_is_migration_source_only(self):
        receipt = hyperdrive_result(migration_origin())
        with mock.patch.object(recovery, "request", return_value=receipt):
            with self.assertRaisesRegex(
                recovery.RecoveryFailure, "unexpected_hyperdrive_origin"
            ):
                recovery.assert_hyperdrive("fake")
        with mock.patch.object(recovery, "request", return_value=receipt):
            self.assertEqual(
                recovery.assert_hyperdrive("fake", allow_migration_source=True),
                "migration_source",
            )

    def test_arbitrary_origin_is_never_reconciled(self):
        origin = migration_origin()
        origin["host"] = "attacker.example"
        with mock.patch.object(
            recovery, "request", return_value=hyperdrive_result(origin)
        ):
            with self.assertRaisesRegex(
                recovery.RecoveryFailure, "unexpected_hyperdrive_origin"
            ):
                recovery.assert_hyperdrive("fake", allow_migration_source=True)

    def test_patch_reconciles_full_direct_origin_from_foundation(self):
        with mock.patch.object(
            recovery, "request", return_value={"success": True}
        ) as request:
            recovery.patch_hyperdrive("fake-cf", "synthetic-secret")
        method, url, token, payload = request.call_args.args
        self.assertEqual((method, token), ("PATCH", "fake-cf"))
        self.assertTrue(url.endswith("/hyperdrive/configs/" + recovery.HYPERDRIVE))
        self.assertEqual(payload["origin"], {
            "host": recovery.HOST,
            "port": recovery.PORT,
            "database": recovery.DATABASE,
            "scheme": "postgres",
            "user": recovery.ROLE,
            "password": "synthetic-secret",
        })
        self.assertEqual(payload["mtls"], {"sslmode": recovery.SSLMODE})
        self.assertEqual(payload["caching"], {"disabled": True})
        self.assertEqual(
            payload["origin_connection_limit"], recovery.CONNECTION_LIMIT
        )

    def test_cf_400_logs_numeric_code_only_never_secret_or_message(self):
        unsafe = b'{"errors":[{"code":10042,"message":"password=mock-private-secret"}]}'
        error = urllib.error.HTTPError(
            recovery.CF_ROOT + "/hyperdrive/configs/" + recovery.HYPERDRIVE,
            400, "password=mock-private-secret", {}, BytesIO(unsafe),
        )
        with mock.patch.object(recovery.OPENER, "open", side_effect=error):
            with self.assertRaises(recovery.RecoveryFailure) as captured:
                recovery.request(
                    "PATCH",
                    recovery.CF_ROOT + "/hyperdrive/configs/" + recovery.HYPERDRIVE,
                    "mock-cf-token",
                    {},
                )
        self.assertEqual(
            str(captured.exception), "provider_http_400_cf_10042"
        )
        self.assertNotIn("mock-private-secret", str(captured.exception))

    def run_recovery(self, cf_patch_error=None, readied=True):
        actions = []

        def update(_token, credential):
            actions.append(("db", credential))

        def patch(_token, credential):
            actions.append(("cf", credential))
            if cf_patch_error:
                raise recovery.RecoveryFailure(cf_patch_error)

        output = StringIO()
        with mock.patch.dict(os.environ, {
                "CLOUDFLARE_API_TOKEN": "fake-cf",
                "SUPABASE_ACCESS_TOKEN": "fake-db",
             }, clear=True),              mock.patch.object(
                 recovery, "assert_hyperdrive",
                 side_effect=["migration_source", "canonical"],
             ),              mock.patch.object(
                 recovery, "inspect_role",
                 return_value="SCRAM-SHA-256$old-verifier",
             ),              mock.patch.object(
                 recovery.secrets, "token_urlsafe",
                 return_value="new-test-password",
             ),              mock.patch.object(recovery, "update_role", side_effect=update),              mock.patch.object(recovery, "patch_hyperdrive", side_effect=patch),              mock.patch.object(recovery, "restart_hyperdrive"),              mock.patch.object(recovery, "ready", return_value=readied),              mock.patch.object(recovery.time, "sleep"),              redirect_stdout(output):
            status = recovery.main()
        text = output.getvalue()
        self.assertNotIn("new-test-password", text)
        self.assertNotIn("old-verifier", text)
        return status, actions, text

    def test_success_reconciles_origin_before_readiness(self):
        status, actions, output = self.run_recovery()
        self.assertEqual(status, 0)
        self.assertEqual(actions, [
            ("db", "new-test-password"),
            ("cf", "new-test-password"),
        ])
        self.assertIn("ORDAX_HYPERDRIVE_ORIGIN_RECONCILED=PASS", output)
        self.assertIn("ORDAX_MCP_POSTGRES_READY=PASS", output)

    def test_definitive_cloudflare_rejection_restores_database_verifier(self):
        status, actions, output = self.run_recovery(
            cf_patch_error="provider_http_400_cf_10042"
        )
        self.assertEqual(status, 5)
        self.assertEqual(actions, [
            ("db", "new-test-password"),
            ("cf", "new-test-password"),
            ("db", "SCRAM-SHA-256$old-verifier"),
        ])
        self.assertIn("ROLLED_BACK_AFTER_CLOUDFLARE_REJECTION", output)

    def test_ambiguous_cloudflare_error_never_rolls_back_one_side(self):
        status, actions, output = self.run_recovery(
            cf_patch_error="provider_connection_unavailable"
        )
        self.assertEqual(status, 5)
        self.assertEqual([kind for kind, _ in actions], ["db", "cf"])
        self.assertIn("AMBIGUOUS_WRITE_REQUIRES_OPERATOR_REVIEW", output)

    def test_readiness_failure_keeps_synchronized_direct_credentials(self):
        status, actions, output = self.run_recovery(readied=False)
        self.assertEqual(status, 4)
        self.assertEqual([kind for kind, _ in actions], ["db", "cf"])
        self.assertIn("FAIL_AFTER_SYNCHRONIZATION", output)

    def test_healthy_canonical_mcp_skips_rotation(self):
        output = StringIO()
        with mock.patch.dict(os.environ, {
                "CLOUDFLARE_API_TOKEN": "fake-cf",
                "SUPABASE_ACCESS_TOKEN": "fake-db",
             }, clear=True),              mock.patch.object(
                 recovery, "assert_hyperdrive", return_value="canonical"
             ),              mock.patch.object(recovery, "ready", return_value=True),              mock.patch.object(recovery, "inspect_role") as inspect,              mock.patch.object(recovery, "update_role") as update,              mock.patch.object(recovery, "patch_hyperdrive") as patch,              redirect_stdout(output):
            self.assertEqual(recovery.main(), 0)
        inspect.assert_not_called()
        update.assert_not_called()
        patch.assert_not_called()
        self.assertIn("ALREADY_HEALTHY_NO_ROTATION", output.getvalue())

    def test_healthy_migration_source_is_still_reconciled(self):
        # A responsive MCP must not preserve origin drift.
        status, actions, output = self.run_recovery(readied=True)
        self.assertEqual(status, 0)
        self.assertEqual([kind for kind, _ in actions], ["db", "cf"])
        self.assertIn("ORIGIN_RECONCILED", output)

    def test_workflow_runs_only_reviewed_recovery(self):
        workflow = (
            ROOT / ".github/workflows/hyperdrive-secure-recovery.yml"
        ).read_text("utf-8")
        self.assertIn("environment: cloudflare-v3", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("tests.test_hyperdrive_credential_recovery", workflow)
        self.assertIn("recover_mcp_hyperdrive.py", workflow)


if __name__ == "__main__":
    unittest.main()
