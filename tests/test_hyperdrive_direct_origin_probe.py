"""Isolated direct IPv6 origin probe: security, fail-closed cleanup and isolation."""
from contextlib import redirect_stdout
from io import BytesIO, StringIO
import importlib.util
import json
from pathlib import Path
import urllib.error
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "scripts/cloudflare/probe_hyperdrive_direct_origin.py"
spec = importlib.util.spec_from_file_location("ordax_direct_origin_probe", FILE)
assert spec and spec.loader
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class DirectOriginProbeContracts(unittest.TestCase):
    def test_unique_run_identity_and_origin(self):
        self.assertEqual(probe.identifiers("39478283587"),
                         ("ordax-direct-ipv6-diag-39478283587", "ordax_direct_diag_39478283587"))
        for bad in ("main", "0", "1", "11;drop role", "1234", "12345-foo"):
            with self.assertRaises(probe.ProbeError):
                probe.identifiers(bad)
        self.assertEqual(probe.ORIGIN, "db.jhfphsjptrpmtnzkpwud.supabase.co")

    def test_config_pinned_to_one_ephemeral_hyperdrive(self):
        config = probe.worker_config("ordax-direct-ipv6-diag-39478283587", "a" * 32)
        self.assertIn('binding = "POSTGRES"', config)
        self.assertIn('id = "' + "a" * 32 + '"', config)
        self.assertIn('src/hyperdrive_direct_probe.ts', config)
        self.assertNotIn("ordax-control-plane-postgres", config)
        with self.assertRaises(probe.ProbeError):
            probe.worker_config("ordax-mcp", "a" * 32)

    def test_role_is_login_only_and_ddl_empty_receipts_allowed(self):
        with mock.patch.object(probe, "api", return_value=None) as api:
            probe.create_role("fake-db-token", "ordax_direct_diag_39478283587", "mock-secret")
            probe.delete_role("fake-db-token", "ordax_direct_diag_39478283587")
        self.assertEqual(api.call_count, 2)
        first_sql = api.call_args_list[0].args[3]["query"]
        self.assertEqual(first_sql, "create role ordax_direct_diag_39478283587 login password 'mock-secret'")
        self.assertNotIn("superuser", first_sql.lower())
        self.assertNotIn("grant", first_sql.lower())

    def test_hyperdrive_uses_direct_origin_only(self):
        with mock.patch.object(probe, "api", return_value={
            "success": True, "result": {"id": "a" * 32},
        }) as call:
            self.assertEqual("a" * 32, probe.create_hyperdrive(
                "fake-token", "ordax-direct-ipv6-diag-39478283587",
                "ordax_direct_diag_39478283587", "mock-secret"))
        payload = call.call_args.args[3]
        self.assertEqual(payload["origin"]["host"], probe.ORIGIN)
        self.assertEqual(payload["origin"]["port"], 5432)
        self.assertEqual(payload["origin"]["user"], "ordax_direct_diag_39478283587")
        self.assertEqual(payload["origin_connection_limit"], 5)
        self.assertEqual(payload["caching"], {"disabled": True})
        self.assertEqual(payload["mtls"], {"sslmode": "require"})

    def test_isolated_pooler_modes_pin_hostname_port_and_tenant_user(self):
        role = "ordax_direct_diag_39478283587"
        self.assertEqual(probe.ORIGIN_MODES, ("direct_ipv6", "pooler_session", "pooler_transaction"))
        self.assertEqual(probe.origin_for_mode("direct_ipv6", role), {
            "scheme": "postgres", "database": "postgres", "user": role,
            "host": probe.ORIGIN, "port": 5432})
        for mode, port in (("pooler_session", 5432), ("pooler_transaction", 6543)):
            with self.subTest(mode=mode):
                origin = probe.origin_for_mode(mode, role)
                self.assertEqual(origin["host"], "aws-1-sa-east-1.pooler.supabase.com")
                self.assertEqual(origin["port"], port)
                self.assertEqual(origin["user"], role + "." + probe.PROJECT)
                self.assertNotIn("password", origin)
                with mock.patch.object(probe, "api", return_value={
                    "success": True, "result": {"id": "a" * 32},
                }) as call:
                    self.assertEqual("a" * 32, probe.create_hyperdrive(
                        "fake-token", "ordax-direct-ipv6-diag-39478283587",
                        role, "mock-secret", mode))
                payload = call.call_args.args[3]
                self.assertEqual(payload["origin"]["port"], port)
                self.assertEqual(payload["origin"]["user"], role + "." + probe.PROJECT)
                self.assertEqual(payload["origin"]["password"], "mock-secret")
                self.assertEqual(payload["mtls"]["sslmode"], "require")
                self.assertEqual(payload["caching"], {"disabled": True})

    def test_pooler_preflight_uses_exact_tenant_credentials_without_argv_leak(self):
        for mode, port in (("pooler_session", "5432"), ("pooler_transaction", "6543")):
            with self.subTest(mode=mode), \
                 mock.patch.object(probe.shutil, "which", return_value="/usr/bin/psql"), \
                 mock.patch.object(probe.subprocess, "run", return_value=mock.Mock(
                     returncode=0, stdout=b"1\\n")) as runner:
                probe.verify_pooler_credential(
                    mode, "ordax_direct_diag_39478283587", "mock-secret")
            command = runner.call_args.args[0]
            env = runner.call_args.kwargs["env"]
            self.assertNotIn("mock-secret", " ".join(command))
            self.assertEqual(env["PGPASSWORD"], "mock-secret")
            self.assertEqual(env["PGPORT"], port)
            self.assertEqual(env["PGUSER"],
                             "ordax_direct_diag_39478283587." + probe.PROJECT)
            self.assertEqual(env["PGSSLMODE"], "require")
            self.assertEqual(env["PGHOST"], probe.POOLER_ORIGIN)
            self.assertEqual(runner.call_args.kwargs["input"], b"")

    def test_pooler_preflight_denies_failure_without_dumping_stderr(self):
        failed = mock.Mock(returncode=2, stdout=b"",
                           stderr=b"private-secret-not-for-logs")
        with mock.patch.object(probe.shutil, "which", return_value="/usr/bin/psql"), \
             mock.patch.object(probe.subprocess, "run", return_value=failed) as runner, \
             mock.patch.object(probe.time, "sleep") as wait:
            with self.assertRaisesRegex(probe.ProbeError, "pooler_credential_not_authenticated") as caught:
                probe.verify_pooler_credential(
                    "pooler_transaction", "ordax_direct_diag_39478283587", "mock-secret")
        self.assertEqual(runner.call_count, 8)
        self.assertEqual(wait.call_count, 7)
        self.assertNotIn("private-secret", str(caught.exception))
        with self.assertRaisesRegex(probe.ProbeError, "pooler_preflight_mode_invalid"):
            probe.verify_pooler_credential(
                "direct_ipv6", "ordax_direct_diag_39478283587", "mock-secret")

    def test_failed_origin_credential_stops_before_cloudflare_resources(self):
        fake_env = {"CLOUDFLARE_API_TOKEN": "fake-cf",
                    "SUPABASE_ACCESS_TOKEN": "fake-db",
                    "GITHUB_RUN_ID": "39478283587",
                    "ORDAX_HYPERDRIVE_PROBE_MODE": "pooler_session"}
        with mock.patch.dict(probe.os.environ, fake_env), \
             mock.patch.object(probe, "require_unique_role"), \
             mock.patch.object(probe, "create_role"), \
             mock.patch.object(probe, "verify_pooler_credential",
                               side_effect=probe.ProbeError("pooler_credential_not_authenticated")), \
             mock.patch.object(probe, "find_hyperdrive", return_value=None), \
             mock.patch.object(probe, "create_hyperdrive") as create_hd, \
             mock.patch.object(probe, "delete_role") as drop, \
             redirect_stdout(StringIO()) as output:
            with self.assertRaisesRegex(probe.ProbeError, "gate_failed"):
                probe.run()
        create_hd.assert_not_called()
        drop.assert_called_once()
        self.assertIn("ORDAX_DIRECT_ROLE_CLEANUP=PASS", output.getvalue())
        self.assertNotIn("fake-db", output.getvalue())

    def test_unknown_origin_refused_before_creating_any_resource(self):
        with self.assertRaisesRegex(probe.ProbeError, "origin_mode_not_allowlisted"):
            probe.origin_for_mode("attacker.host:5432", "ordax_direct_diag_39478283587")
        env = {"CLOUDFLARE_API_TOKEN": "fake-cf",
               "SUPABASE_ACCESS_TOKEN": "fake-db",
               "GITHUB_RUN_ID": "39478283587",
               "ORDAX_HYPERDRIVE_PROBE_MODE": "unknown_mode"}
        with mock.patch.dict(probe.os.environ, env), \
             mock.patch.object(probe, "require_unique_role") as preflight, \
             mock.patch.object(probe, "create_role") as create:
            with self.assertRaisesRegex(probe.ProbeError, "origin_mode_not_allowlisted"):
                probe.run()
        preflight.assert_not_called()
        create.assert_not_called()

    def test_workflow_requires_reviewed_mode_and_protected_main(self):
        workflow = (ROOT / ".github/workflows/hyperdrive-direct-origin-probe.yml").read_text("utf-8")
        self.assertIn("origin_mode:", workflow)
        self.assertIn("pooler_transaction", workflow)
        self.assertIn("pooler_session", workflow)
        self.assertIn("ORDAX_HYPERDRIVE_PROBE_MODE: ${{ inputs.origin_mode }}", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("environment: cloudflare-v3", workflow)

    def test_cf_error_never_logs_provider_message_or_sql_secret(self):
        uri = probe.CF_API + "/hyperdrive/configs"
        error = urllib.error.HTTPError(
            uri, 400, "password=mock-secret", {},
            BytesIO(b'{"errors":[{"code":2013,"message":"password=mock-secret"}]}'))
        with mock.patch.object(probe.OPENER, "open", side_effect=error):
            with self.assertRaises(probe.ProbeError) as caught:
                probe.api("POST", uri, "fake-token", {"password": "mock-secret"})
        self.assertEqual(str(caught.exception), "provider_http_400_cf_2013")
        self.assertNotIn("mock-secret", str(caught.exception))

    def test_worker_failure_diagnostic_is_strictly_allowlisted(self):
        uri = "https://ordax-direct-ipv6-diag-39478283587.ordaxsystems.workers.dev/"
        error = urllib.error.HTTPError(uri, 503, "private trace", {}, BytesIO(
            b'{"ok":false,"phase":"connect","classification":"connection_terminated",'
            b'"secret":"mock-secret"}'))
        with mock.patch.object(probe.OPENER, "open", side_effect=error):
            status = probe.api("GET", uri)
        self.assertEqual(status, {"ok": False, "phase": "connect",
                                  "classification": "connection_terminated"})
        self.assertNotIn("mock-secret", json.dumps(status))

    def test_successful_probe_always_deletes_every_ephemeral_resource(self):
        calls = []
        fake_env = {"CLOUDFLARE_API_TOKEN": "fake-cf-secret",
                    "SUPABASE_ACCESS_TOKEN": "fake-db-secret",
                    "GITHUB_RUN_ID": "39478283587"}
        def api(method, uri, *rest):
            calls.append((method, uri))
        with mock.patch.dict(probe.os.environ, fake_env), \
             mock.patch.object(probe, "require_unique_role"), \
             mock.patch.object(probe, "create_role"), \
             mock.patch.object(probe, "create_hyperdrive", return_value="a"*32), \
             mock.patch.object(probe, "deploy_worker"), \
             mock.patch.object(probe, "check_worker", return_value={"ok": True, "phase": "complete"}), \
             mock.patch.object(probe, "delete_role") as drop, \
             mock.patch.object(probe, "api", side_effect=api), \
             redirect_stdout(StringIO()) as output:
            probe.run()
        self.assertEqual([m for m, _ in calls], ["DELETE", "DELETE"])
        self.assertIn("/workers/scripts/ordax-direct-ipv6-diag-39478283587", calls[0][1])
        self.assertIn("/hyperdrive/configs/" + "a"*32, calls[1][1])
        drop.assert_called_once()
        self.assertIn("ORDAX_DIRECT_POSTGRES_SELECT_1=PASS", output.getvalue())
        self.assertNotIn("fake-db-secret", output.getvalue())
        self.assertNotIn("fake-cf-secret", output.getvalue())

    def test_hyperdrive_refusal_cleans_role_and_does_not_deploy(self):
        fake_env = {"CLOUDFLARE_API_TOKEN": "fake-cf",
                    "SUPABASE_ACCESS_TOKEN": "fake-db",
                    "GITHUB_RUN_ID": "39478283587"}
        with mock.patch.dict(probe.os.environ, fake_env), \
             mock.patch.object(probe, "require_unique_role"), \
             mock.patch.object(probe, "create_role"), \
             mock.patch.object(probe, "create_hyperdrive",
                               side_effect=probe.ProbeError("provider_http_400_cf_2013")), \
             mock.patch.object(probe, "find_hyperdrive", return_value=None), \
             mock.patch.object(probe, "deploy_worker") as deploy, \
             mock.patch.object(probe, "delete_role") as drop, \
             redirect_stdout(StringIO()) as out:
            with self.assertRaisesRegex(probe.ProbeError, "gate_failed"):
                probe.run()
        deploy.assert_not_called()
        drop.assert_called_once()
        self.assertIn("ORDAX_DIRECT_ROLE_CLEANUP=PASS", out.getvalue())

    def test_curl_probe_parses_only_safe_select_one_response(self):
        good = mock.Mock(returncode=0, stdout=(
            b'{"ok":true,"phase":"complete"}' + bytes([10]) + b"200"), stderr=b"")
        with mock.patch.object(probe.shutil, "which", return_value="/usr/bin/curl"), \
             mock.patch.object(probe.subprocess, "run", return_value=good) as runner:
            result = probe.check_worker("ordax-direct-ipv6-diag-39478283587")
        self.assertEqual(result, {"ok": True, "phase": "complete"})
        self.assertEqual(runner.call_args.args[0][0], "curl")
        self.assertNotIn("--location", runner.call_args.args[0])

    def test_curl_worker_503_returns_only_safe_postgres_phase(self):
        failure = mock.Mock(returncode=0, stdout=(
            b'{"ok":false,"phase":"connect","classification":"connection_terminated",'
            b'"secret":"mock-secret"}' + bytes([10]) + b"503"), stderr=b"")
        with mock.patch.object(probe.shutil, "which", return_value="/usr/bin/curl"), \
             mock.patch.object(probe.subprocess, "run", return_value=failure):
            result = probe.check_worker("ordax-direct-ipv6-diag-39478283587")
        self.assertEqual(result, {"ok": False, "phase": "connect",
                                  "classification": "connection_terminated"})
        self.assertNotIn("mock-secret", json.dumps(result))

    def test_worker_http_403_is_bounded_no_secrets(self):
        denied = mock.Mock(returncode=0, stdout=b"private content" + bytes([10]) + b"403",
                           stderr=b"mock-private-secret")
        with mock.patch.object(probe.shutil, "which", return_value="/usr/bin/curl"), \
             mock.patch.object(probe.subprocess, "run", return_value=denied) as runner, \
             mock.patch.object(probe.time, "sleep") as sleep:
            with self.assertRaisesRegex(probe.ProbeError, "probe_http_403") as caught:
                probe.check_worker("ordax-direct-ipv6-diag-39478283587")
        self.assertEqual(runner.call_count, 6)
        self.assertEqual(sleep.call_count, 5)
        self.assertNotIn("mock-private-secret", str(caught.exception))

    def test_source_has_only_read_only_query(self):
        text = (ROOT / "control-plane/cloudflare/src/hyperdrive_direct_probe.ts").read_text("utf-8")
        self.assertIn("select 1::int as ok", text)
        self.assertIn('openPostgresSession(env.POSTGRES.connectionString)', text)
        self.assertNotIn('from "pg"', text)
        for forbidden in ("INSERT INTO", "UPDATE ", "DELETE FROM", "CREATE TABLE",
                          "ordax_", "/mcp", "oauth", "product_device", "env.DB"):
            self.assertNotIn(forbidden, text)
        workflow = (ROOT / ".github/workflows/hyperdrive-direct-origin-probe.yml").read_text("utf-8")
        self.assertIn("workflow_dispatch", workflow)
        self.assertIn("environment: cloudflare-v3", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertNotIn("schedule:", workflow)


if __name__ == "__main__":
    unittest.main()
