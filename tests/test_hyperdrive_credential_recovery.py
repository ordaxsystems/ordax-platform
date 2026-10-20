"""Test the canonical recovery without writing credentials to either provider."""
from contextlib import redirect_stdout
import importlib.util
import io
import os
import urllib.error
from pathlib import Path
import unittest
from unittest import mock

FILE = Path(__file__).resolve().parents[1] / "scripts/cloudflare/recover_mcp_hyperdrive.py"
spec = importlib.util.spec_from_file_location("ordax_hyperdrive_recovery", FILE)
recovery = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(recovery)


class RecoveryContracts(unittest.TestCase):
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
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(recovery, "request") as request:
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(recovery.main(), 3)
            request.assert_not_called()
            self.assertIn("BLOCKED_MISSING_AUTHORIZED_CREDENTIALS", out.getvalue())

    def test_hyperdrive_guard_rejects_wrong_identity(self):
        wrong = {"success": True, "result": {"origin": {
            "host": "legacy.example.org", "port": 5432,
            "user": recovery.POOLER_USER, "database": "postgres"},
            "mtls": {"sslmode": "require"}}}
        with mock.patch.object(recovery, "request", return_value=wrong):
            with self.assertRaisesRegex(recovery.RecoveryFailure, "unexpected_hyperdrive_origin"):
                recovery.assert_hyperdrive("not-a-real-token")

    def run_recovery(self, cf_patch_error=None, readied=True):
        action_order = []
        def update(db_token, credential):
            action_order.append(("db", credential))
        def patch(cf_token, credential):
            action_order.append(("cf", credential))
            if cf_patch_error:
                raise recovery.RecoveryFailure(cf_patch_error)
        fake_socket = mock.MagicMock()
        fake_socket.__enter__.return_value = fake_socket
        output = io.StringIO()
        with mock.patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": "fake-cf-token",
                                           "SUPABASE_ACCESS_TOKEN": "fake-db-token"}), \
             mock.patch.object(recovery, "assert_hyperdrive"), \
             mock.patch.object(recovery, "inspect_role", return_value="SCRAM-SHA-256$old-verifier"), \
             mock.patch.object(recovery.shutil, "which", return_value="/usr/bin/psql"), \
             mock.patch.object(recovery, "verify_pooler_credential"), \
             mock.patch.object(recovery.socket, "create_connection", return_value=fake_socket), \
             mock.patch.object(recovery.secrets, "token_urlsafe", return_value="new-test-password"), \
             mock.patch.object(recovery, "update_role", side_effect=update), \
             mock.patch.object(recovery, "patch_hyperdrive", side_effect=patch), \
             mock.patch.object(recovery, "restart_hyperdrive"), \
             mock.patch.object(recovery, "ready", side_effect=([False, True] if readied else [False] * 12)), \
             mock.patch.object(recovery.time, "sleep"), \
             redirect_stdout(output):
            status = recovery.main()
        self.assertNotIn("new-test-password", output.getvalue())
        self.assertNotIn("old-verifier", output.getvalue())
        return status, action_order, output.getvalue()

    def test_password_only_patch_preserves_existing_origin(self):
        with mock.patch.object(recovery, "request", return_value={"success": True}) as request:
            recovery.patch_hyperdrive("fake-cf-token", "fake-new-password")
        method, url, token, payload = request.call_args.args
        self.assertEqual(method, "PATCH")
        self.assertEqual(token, "fake-cf-token")
        self.assertEqual(payload, {"origin": {"password": "fake-new-password"}})
        self.assertTrue(url.endswith("/hyperdrive/configs/" + recovery.HYPERDRIVE))

    def test_cf_400_logs_numeric_code_only_never_secret_or_message(self):
        from io import BytesIO
        unsafe = b'{"errors":[{"code":10042,"message":"password=mock-private-secret"}]}'
        error = urllib.error.HTTPError(
            recovery.CF_ROOT + "/hyperdrive/configs/" + recovery.HYPERDRIVE,
            400, "password=mock-private-secret", {}, BytesIO(unsafe)
        )
        with mock.patch.object(recovery.OPENER, "open", side_effect=error):
            with self.assertRaises(recovery.RecoveryFailure) as captured:
                recovery.request("PATCH", recovery.CF_ROOT + "/hyperdrive/configs/"
                                 + recovery.HYPERDRIVE, "mock-cf-token", {})
        self.assertEqual(str(captured.exception), "provider_http_400_cf_10042")
        self.assertNotIn("mock-private-secret", str(captured.exception))

    def test_definitive_400_numeric_code_keeps_safe_rollback(self):
        status, actions, output = self.run_recovery(
            cf_patch_error="provider_http_400_cf_10042"
        )
        self.assertEqual(status, 5)
        self.assertEqual([name for name, _ in actions], ["db", "cf", "db"])
        self.assertIn("ROLLED_BACK", output)

    def test_pooler_probe_uses_exact_origin_and_never_logs_credential(self):
        sample = mock.Mock(returncode=0, stdout=b"1\\n", stderr=b"")
        with mock.patch.object(recovery.shutil, "which", return_value="/usr/bin/psql"), \
             mock.patch.object(recovery.subprocess, "run", return_value=sample) as run:
            recovery.verify_pooler_credential("synthetic-auth-secret")
        args, kwargs = run.call_args
        self.assertNotIn("synthetic-auth-secret", str(args))
        self.assertEqual(kwargs["env"]["PGPASSWORD"], "synthetic-auth-secret")
        self.assertEqual(kwargs["env"]["PGUSER"], recovery.POOLER_USER)
        self.assertEqual(kwargs["env"]["PGHOST"], recovery.HOST)
        self.assertEqual(kwargs["env"]["PGSSLMODE"], "require")
        self.assertEqual(kwargs["stdout"], recovery.subprocess.PIPE)
        self.assertEqual(kwargs["stderr"], recovery.subprocess.PIPE)

    def test_pooler_probe_exhaustion_fails_without_echoing_secret(self):
        rejected = mock.Mock(returncode=2, stdout=b"", stderr=b"password=synthetic-auth-secret")
        with mock.patch.object(recovery.shutil, "which", return_value="/usr/bin/psql"), \
             mock.patch.object(recovery.subprocess, "run", return_value=rejected) as run, \
             mock.patch.object(recovery.time, "sleep"):
            with self.assertRaisesRegex(
                recovery.RecoveryFailure, "pooler_new_credential_not_authenticated"
            ) as caught:
                recovery.verify_pooler_credential("synthetic-auth-secret")
        self.assertEqual(run.call_count, 18)
        self.assertNotIn("synthetic-auth-secret", str(caught.exception))

    def test_pooler_auth_failed_restores_role_before_cloudflare_write(self):
        actions = []
        fake_socket = mock.MagicMock()
        fake_socket.__enter__.return_value = fake_socket
        output = io.StringIO()
        with mock.patch.dict(os.environ, {
                "CLOUDFLARE_API_TOKEN": "fake-cf", "SUPABASE_ACCESS_TOKEN": "fake-db"}), \
             mock.patch.object(recovery, "assert_hyperdrive"), \
             mock.patch.object(recovery, "ready", return_value=False), \
             mock.patch.object(recovery, "inspect_role", return_value="SCRAM-SHA-256$old-verifier"), \
             mock.patch.object(recovery.shutil, "which", return_value="/usr/bin/psql"), \
             mock.patch.object(recovery.socket, "create_connection", return_value=fake_socket), \
             mock.patch.object(recovery.secrets, "token_urlsafe", return_value="synthetic-auth-secret"), \
             mock.patch.object(recovery, "update_role",
                               side_effect=lambda _, v: actions.append(v)), \
             mock.patch.object(recovery, "verify_pooler_credential",
                               side_effect=recovery.RecoveryFailure("pooler_new_credential_not_authenticated")), \
             mock.patch.object(recovery, "patch_hyperdrive") as patch_cf, \
             redirect_stdout(output):
            self.assertEqual(recovery.main(), 5)
        self.assertEqual(actions, ["synthetic-auth-secret", "SCRAM-SHA-256$old-verifier"])
        patch_cf.assert_not_called()
        self.assertIn("ROLLED_BACK_AFTER_POOLER_AUTH_FAILURE", output.getvalue())
        self.assertNotIn("synthetic-auth-secret", output.getvalue())

    def test_healthy_mcp_skips_rotation(self):
        output = io.StringIO()
        with mock.patch.dict(os.environ, {"CLOUDFLARE_API_TOKEN": "fake-cf",
                                           "SUPABASE_ACCESS_TOKEN": "fake-db"}), \
             mock.patch.object(recovery, "assert_hyperdrive"), \
             mock.patch.object(recovery, "ready", return_value=True), \
             mock.patch.object(recovery, "inspect_role") as inspect, \
             mock.patch.object(recovery, "update_role") as update, \
             mock.patch.object(recovery, "patch_hyperdrive") as patch, \
             redirect_stdout(output):
            self.assertEqual(recovery.main(), 0)
        inspect.assert_not_called()
        update.assert_not_called()
        patch.assert_not_called()
        self.assertIn("ALREADY_HEALTHY_NO_ROTATION", output.getvalue())

    def test_success_synchronizes_before_readiness(self):
        status, actions, output = self.run_recovery()
        self.assertEqual(status, 0)
        self.assertEqual(actions, [("db", "new-test-password"), ("cf", "new-test-password")])
        self.assertIn("ORDAX_MCP_POSTGRES_READY=PASS", output)

    def test_definitive_cloudflare_rejection_rolls_back_database(self):
        status, actions, output = self.run_recovery(cf_patch_error="provider_http_403")
        self.assertEqual(status, 5)
        self.assertEqual(actions, [("db", "new-test-password"), ("cf", "new-test-password"),
                                   ("db", "SCRAM-SHA-256$old-verifier")])
        self.assertIn("ROLLED_BACK", output)

    def test_ambiguous_cloudflare_error_does_not_break_synced_authority_by_rollback(self):
        status, actions, output = self.run_recovery(cf_patch_error="provider_connection_unavailable")
        self.assertEqual(status, 5)
        self.assertEqual([a[0] for a in actions], ["db", "cf"])
        self.assertIn("AMBIGUOUS_WRITE_REQUIRES_OPERATOR_REVIEW", output)

    def test_readiness_failure_never_unsynchronizes_valid_credential(self):
        status, actions, output = self.run_recovery(readied=False)
        self.assertEqual(status, 4)
        self.assertEqual([a[0] for a in actions], ["db", "cf"])
        self.assertIn("FAIL_AFTER_SYNCHRONIZATION", output)


if __name__ == "__main__":
    unittest.main()
