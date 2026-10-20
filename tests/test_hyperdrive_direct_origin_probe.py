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
