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
        config = probe.worker_config(
            "ordax-direct-ipv6-diag-39478283587", "a" * 32, probe.ORIGIN, 5432)
        self.assertIn('binding = "POSTGRES"', config)
        self.assertIn('id = "' + "a" * 32 + '"', config)
        self.assertIn('src/hyperdrive_direct_probe.ts', config)
        self.assertIn('ORDAX_PROBE_ORIGIN_HOST = "' + probe.ORIGIN + '"', config)
        self.assertIn('ORDAX_PROBE_ORIGIN_PORT = "5432"', config)
        self.assertIn('compatibility_flags = ["nodejs_compat"]', config)
        compat_v2 = probe.worker_config(
            "ordax-direct-ipv6-diag-39478283587", "a" * 32,
            probe.ORIGIN, 5432, compatibility_flag="nodejs_compat_v2")
        self.assertIn('compatibility_flags = ["nodejs_compat_v2"]', compat_v2)
        with self.assertRaisesRegex(
                probe.ProbeError, "worker_compatibility_flag_invalid"):
            probe.worker_config(
                "ordax-direct-ipv6-diag-39478283587", "a" * 32,
                probe.ORIGIN, 5432, compatibility_flag="legacy")
        self.assertNotIn("ordax-control-plane-postgres", config)
        with self.assertRaises(probe.ProbeError):
            probe.worker_config("ordax-mcp", "a" * 32, probe.ORIGIN, 5432)
        with self.assertRaisesRegex(probe.ProbeError, "worker_origin_invalid"):
            probe.worker_config(
                "ordax-direct-ipv6-diag-39478283587", "a" * 32,
                "attacker.example", 5432)
        with self.assertRaisesRegex(probe.ProbeError, "worker_origin_invalid"):
            probe.worker_config(
                "ordax-direct-ipv6-diag-39478283587", "a" * 32,
                "2600:1f18::5", 5432)
        literal = probe.worker_config(
            "ordax-direct-ipv6-diag-39478283587", "a" * 32,
            "2600:1f18::5", 5432, allow_direct_ipv6_literal=True)
        self.assertIn('ORDAX_PROBE_ORIGIN_HOST = "2600:1f18::5"', literal)
        for invalid in ("127.0.0.1", "::1", "2001:db8::5", "not-an-ip"):
            with self.subTest(invalid=invalid), \
                 self.assertRaisesRegex(probe.ProbeError, "worker_origin_invalid"):
                probe.worker_config(
                    "ordax-direct-ipv6-diag-39478283587", "a" * 32,
                    invalid, 5432, allow_direct_ipv6_literal=True)

    def test_direct_worker_config_has_no_hyperdrive_or_password(self):
        name = "ordax-direct-ipv6-diag-39478283587"
        user = "ordax_direct_diag_39478283587." + probe.PROJECT
        config = probe.worker_config(
            name, None, probe.POOLER_ORIGIN, 5432,
            direct_postgres=True, db_user=user)
        self.assertIn('ORDAX_PROBE_DIRECT_POSTGRES = "1"', config)
        self.assertIn('ORDAX_PROBE_DB_USER = "' + user + '"', config)
        self.assertIn('ORDAX_PROBE_DRIVER = "node_postgres"', config)
        self.assertIn('[secrets]', config)
        self.assertIn('required = ["ORDAX_PROBE_DB_PASSWORD"]', config)
        self.assertNotIn("[[hyperdrive]]", config)
        self.assertNotIn('binding = "POSTGRES"', config)
        self.assertNotIn("synthetic-private-password", config)
        self.assertNotIn("mock-secret", config)
        with self.assertRaisesRegex(probe.ProbeError, "direct_worker_config_invalid"):
            probe.worker_config(
                name, "a" * 32, probe.POOLER_ORIGIN, 5432,
                direct_postgres=True, db_user=user)
        with self.assertRaisesRegex(probe.ProbeError, "direct_worker_config_invalid"):
            probe.worker_config(
                name, None, probe.POOLER_ORIGIN, 5432,
                direct_postgres=True, db_user="postgres")
        for mode in ("worker_direct_pooler", "worker_direct_pooler_transaction",
                     "worker_direct_pooler_transaction_nodejs_compat_v2",
                     "worker_direct_pooler_transaction_postgres_js",
                     "worker_direct_ipv6", "worker_direct_ipv6_custom_ca"):
            with self.subTest(mode=mode), self.assertRaisesRegex(
                    probe.ProbeError, "hyperdrive_for_direct_worker_forbidden"):
                probe.create_hyperdrive(
                    "fake-token", name, "ordax_direct_diag_39478283587",
                    "mock-secret", mode)
        direct_config = probe.worker_config(
            name, None, probe.ORIGIN, 5432,
            direct_postgres=True, db_user="ordax_direct_diag_39478283587")
        self.assertIn('ORDAX_PROBE_DB_USER = "ordax_direct_diag_39478283587"',
                      direct_config)
        self.assertNotIn('ORDAX_PROBE_TLS_CA = "1"', direct_config)
        self.assertNotIn("[[hyperdrive]]", direct_config)
        direct_ca_config = probe.worker_config(
            name, None, probe.ORIGIN, 5432,
            direct_postgres=True, db_user="ordax_direct_diag_39478283587",
            tls_ca=True)
        self.assertIn('ORDAX_PROBE_TLS_CA = "1"', direct_ca_config)
        self.assertNotIn("[[hyperdrive]]", direct_ca_config)
        postgres_js_config = probe.worker_config(
            name, None, probe.POOLER_ORIGIN, 6543,
            direct_postgres=True, db_user=user, direct_driver="postgres_js")
        self.assertIn('ORDAX_PROBE_DRIVER = "postgres_js"', postgres_js_config)
        self.assertNotIn("[[hyperdrive]]", postgres_js_config)
        with self.assertRaisesRegex(probe.ProbeError, "direct_worker_driver_invalid"):
            probe.worker_config(
                name, None, probe.POOLER_ORIGIN, 6543,
                direct_postgres=True, db_user=user, direct_driver="unknown")

    def test_direct_worker_secret_is_atomic_tempfile_only(self):
        deploy_ok = mock.Mock(returncode=0, stdout=b"", stderr=b"")
        name = "ordax-direct-ipv6-diag-39478283587"
        user = "ordax_direct_diag_39478283587." + probe.PROJECT
        seen = {}

        def run(command, **kwargs):
            self.assertIn("--secrets-file", command)
            secret_path = Path(command[command.index("--secrets-file") + 1])
            config_path = Path(command[command.index("--config") + 1])
            seen["secret_path"] = secret_path
            seen["config_path"] = config_path
            seen["payload"] = json.loads(secret_path.read_text("utf-8"))
            seen["command"] = tuple(command)
            seen["env"] = kwargs["env"]
            return deploy_ok

        with mock.patch.object(probe.subprocess, "run", side_effect=run) as runner:
            probe.deploy_worker(
                name, None, probe.POOLER_ORIGIN, 5432,
                direct_postgres_password="synthetic-private-password",
                db_user=user)
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(seen["payload"], {
            "ORDAX_PROBE_DB_PASSWORD": "synthetic-private-password"
        })
        self.assertNotIn("synthetic-private-password", " ".join(seen["command"]))
        self.assertNotIn("synthetic-private-password", str(seen["env"]))
        self.assertNotIn("SUPABASE_ACCESS_TOKEN", seen["env"])
        self.assertFalse(seen["secret_path"].exists())
        self.assertFalse(seen["config_path"].exists())

    def test_direct_worker_run_never_creates_or_searches_hyperdrive(self):
        env = {
            "CLOUDFLARE_API_TOKEN": "fake-cf",
            "SUPABASE_ACCESS_TOKEN": "fake-db",
            "GITHUB_RUN_ID": "39478283587",
            "ORDAX_HYPERDRIVE_PROBE_MODE": "worker_direct_pooler",
        }
        with mock.patch.dict(probe.os.environ, env, clear=True), \
             mock.patch.object(probe, "require_unique_role"), \
             mock.patch.object(probe, "create_role"), \
             mock.patch.object(probe, "verify_pooler_credential") as preflight, \
             mock.patch.object(probe, "create_hyperdrive") as create_hd, \
             mock.patch.object(probe, "find_hyperdrive") as find_hd, \
             mock.patch.object(probe, "deploy_worker") as deploy, \
             mock.patch.object(
                 probe, "check_worker",
                 return_value={"ok": True, "phase": "complete"}), \
             mock.patch.object(probe, "delete_role"), \
             mock.patch.object(probe, "api", return_value=None) as api, \
             redirect_stdout(StringIO()) as output:
            probe.run()
        preflight.assert_called_once_with(
            "worker_direct_pooler", "ordax_direct_diag_39478283587",
            mock.ANY)
        create_hd.assert_not_called()
        find_hd.assert_not_called()
        deploy.assert_called_once()
        args = deploy.call_args.args
        kwargs = deploy.call_args.kwargs
        self.assertIsNone(args[1])
        self.assertEqual(args[2], probe.POOLER_ORIGIN)
        self.assertEqual(args[3], 5432)
        self.assertEqual(kwargs["db_user"],
                         "ordax_direct_diag_39478283587." + probe.PROJECT)
        self.assertTrue(kwargs["direct_postgres_password"])
        self.assertEqual(api.call_count, 1)
        self.assertIn("/workers/scripts/ordax-direct-ipv6-diag-39478283587",
                      api.call_args.args[1])
        self.assertIn("ORDAX_DIRECT_HYPERDRIVE=NOT_USED", output.getvalue())
        self.assertIn("ORDAX_DIRECT_HYPERDRIVE_CLEANUP=NOT_CREATED",
                      output.getvalue())

    def test_direct_transaction_pooler_uses_6543_without_hyperdrive(self):
        env = {
            "CLOUDFLARE_API_TOKEN": "fake-cf",
            "SUPABASE_ACCESS_TOKEN": "fake-db",
            "GITHUB_RUN_ID": "39478283587",
            "ORDAX_HYPERDRIVE_PROBE_MODE": "worker_direct_pooler_transaction",
        }
        with mock.patch.dict(probe.os.environ, env, clear=True), \
             mock.patch.object(probe, "require_unique_role"), \
             mock.patch.object(probe, "create_role"), \
             mock.patch.object(probe, "verify_pooler_credential") as preflight, \
             mock.patch.object(probe, "create_hyperdrive") as create_hd, \
             mock.patch.object(probe, "find_hyperdrive") as find_hd, \
             mock.patch.object(probe, "deploy_worker") as deploy, \
             mock.patch.object(
                 probe, "check_worker",
                 return_value={"ok": True, "phase": "complete"}), \
             mock.patch.object(probe, "delete_role"), \
             mock.patch.object(probe, "api", return_value=None), \
             redirect_stdout(StringIO()):
            probe.run()
        preflight.assert_called_once_with(
            "worker_direct_pooler_transaction",
            "ordax_direct_diag_39478283587", mock.ANY)
        create_hd.assert_not_called()
        find_hd.assert_not_called()
        deploy.assert_called_once()
        args = deploy.call_args.args
        kwargs = deploy.call_args.kwargs
        self.assertIsNone(args[1])
        self.assertEqual(args[2], probe.POOLER_ORIGIN)
        self.assertEqual(args[3], 6543)
        self.assertEqual(kwargs["db_user"],
                         "ordax_direct_diag_39478283587." + probe.PROJECT)
        self.assertTrue(kwargs["direct_postgres_password"])

    def test_direct_transaction_nodejs_compat_v2_changes_only_runtime_flag(self):
        env = {
            "CLOUDFLARE_API_TOKEN": "fake-cf",
            "SUPABASE_ACCESS_TOKEN": "fake-db",
            "GITHUB_RUN_ID": "39478283587",
            "ORDAX_HYPERDRIVE_PROBE_MODE":
                "worker_direct_pooler_transaction_nodejs_compat_v2",
        }
        with mock.patch.dict(probe.os.environ, env, clear=True), \
             mock.patch.object(probe, "require_unique_role"), \
             mock.patch.object(probe, "create_role"), \
             mock.patch.object(probe, "verify_pooler_credential") as preflight, \
             mock.patch.object(probe, "create_hyperdrive") as create_hd, \
             mock.patch.object(probe, "find_hyperdrive") as find_hd, \
             mock.patch.object(probe, "deploy_worker") as deploy, \
             mock.patch.object(
                 probe, "check_worker",
                 return_value={"ok": True, "phase": "complete"}), \
             mock.patch.object(probe, "delete_role"), \
             mock.patch.object(probe, "api", return_value=None), \
             redirect_stdout(StringIO()):
            probe.run()
        preflight.assert_called_once_with(
            "worker_direct_pooler_transaction_nodejs_compat_v2",
            "ordax_direct_diag_39478283587", mock.ANY)
        create_hd.assert_not_called()
        find_hd.assert_not_called()
        args = deploy.call_args.args
        kwargs = deploy.call_args.kwargs
        self.assertIsNone(args[1])
        self.assertEqual(args[2], probe.POOLER_ORIGIN)
        self.assertEqual(args[3], 6543)
        self.assertEqual(kwargs["direct_driver"], "node_postgres")
        self.assertEqual(kwargs["compatibility_flag"], "nodejs_compat_v2")

    def test_direct_transaction_postgres_js_uses_same_6543_without_hyperdrive(self):
        env = {
            "CLOUDFLARE_API_TOKEN": "fake-cf",
            "SUPABASE_ACCESS_TOKEN": "fake-db",
            "GITHUB_RUN_ID": "39478283587",
            "ORDAX_HYPERDRIVE_PROBE_MODE":
                "worker_direct_pooler_transaction_postgres_js",
        }
        with mock.patch.dict(probe.os.environ, env, clear=True), \
             mock.patch.object(probe, "require_unique_role"), \
             mock.patch.object(probe, "create_role"), \
             mock.patch.object(probe, "verify_pooler_credential") as preflight, \
             mock.patch.object(probe, "create_hyperdrive") as create_hd, \
             mock.patch.object(probe, "find_hyperdrive") as find_hd, \
             mock.patch.object(probe, "deploy_worker") as deploy, \
             mock.patch.object(
                 probe, "check_worker",
                 return_value={"ok": True, "phase": "complete"}), \
             mock.patch.object(probe, "delete_role"), \
             mock.patch.object(probe, "api", return_value=None), \
             redirect_stdout(StringIO()):
            probe.run()
        preflight.assert_called_once_with(
            "worker_direct_pooler_transaction_postgres_js",
            "ordax_direct_diag_39478283587", mock.ANY)
        create_hd.assert_not_called()
        find_hd.assert_not_called()
        deploy.assert_called_once()
        args = deploy.call_args.args
        kwargs = deploy.call_args.kwargs
        self.assertIsNone(args[1])
        self.assertEqual(args[2], probe.POOLER_ORIGIN)
        self.assertEqual(args[3], 6543)
        self.assertEqual(kwargs["direct_driver"], "postgres_js")
        self.assertEqual(kwargs["db_user"],
                         "ordax_direct_diag_39478283587." + probe.PROJECT)
        self.assertTrue(kwargs["direct_postgres_password"])

    def test_direct_ipv6_worker_skips_pooler_and_hyperdrive(self):
        env = {
            "CLOUDFLARE_API_TOKEN": "fake-cf",
            "SUPABASE_ACCESS_TOKEN": "fake-db",
            "GITHUB_RUN_ID": "39478283587",
            "ORDAX_HYPERDRIVE_PROBE_MODE": "worker_direct_ipv6",
        }
        with mock.patch.dict(probe.os.environ, env, clear=True), \
             mock.patch.object(probe, "require_unique_role"), \
             mock.patch.object(probe, "create_role"), \
             mock.patch.object(probe, "verify_pooler_credential") as preflight, \
             mock.patch.object(probe, "create_hyperdrive") as create_hd, \
             mock.patch.object(probe, "find_hyperdrive") as find_hd, \
             mock.patch.object(probe, "deploy_worker") as deploy, \
             mock.patch.object(
                 probe, "check_worker",
                 return_value={"ok": True, "phase": "complete"}), \
             mock.patch.object(probe, "delete_role"), \
             mock.patch.object(probe, "api", return_value=None):
            probe.run()
        preflight.assert_not_called()
        create_hd.assert_not_called()
        find_hd.assert_not_called()
        args = deploy.call_args.args
        kwargs = deploy.call_args.kwargs
        self.assertIsNone(args[1])
        self.assertEqual(args[2], probe.ORIGIN)
        self.assertEqual(args[3], 5432)
        self.assertEqual(kwargs["db_user"], "ordax_direct_diag_39478283587")
        self.assertTrue(kwargs["direct_postgres_password"])
        self.assertFalse(kwargs["tls_ca"])

    def test_direct_ipv6_worker_with_ca_skips_pooler_and_hyperdrive(self):
        env = {
            "CLOUDFLARE_API_TOKEN": "fake-cf",
            "SUPABASE_ACCESS_TOKEN": "fake-db",
            "GITHUB_RUN_ID": "39478283587",
            "ORDAX_HYPERDRIVE_PROBE_MODE": "worker_direct_ipv6_custom_ca",
        }
        with mock.patch.dict(probe.os.environ, env, clear=True), \
             mock.patch.object(probe, "require_unique_role"), \
             mock.patch.object(probe, "create_role"), \
             mock.patch.object(probe, "verify_pooler_credential") as preflight, \
             mock.patch.object(probe, "create_hyperdrive") as create_hd, \
             mock.patch.object(probe, "find_hyperdrive") as find_hd, \
             mock.patch.object(probe, "deploy_worker") as deploy, \
             mock.patch.object(
                 probe, "check_worker",
                 return_value={"ok": True, "phase": "complete"}), \
             mock.patch.object(probe, "delete_role"), \
             mock.patch.object(probe, "api", return_value=None):
            probe.run()
        preflight.assert_not_called()
        create_hd.assert_not_called()
        find_hd.assert_not_called()
        args = deploy.call_args.args
        kwargs = deploy.call_args.kwargs
        self.assertIsNone(args[1])
        self.assertEqual(args[2], probe.ORIGIN)
        self.assertEqual(args[3], 5432)
        self.assertEqual(kwargs["db_user"], "ordax_direct_diag_39478283587")
        self.assertTrue(kwargs["direct_postgres_password"])
        self.assertTrue(kwargs["tls_ca"])

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

        with mock.patch.object(probe, "api", return_value={
            "success": True, "result": {"id": "b" * 32},
        }) as default_tls:
            self.assertEqual("b" * 32, probe.create_hyperdrive(
                "fake-token", "ordax-direct-ipv6-diag-39478283587",
                "ordax_direct_diag_39478283587", "mock-secret",
                "direct_ipv6_default_tls"))
        default_payload = default_tls.call_args.args[3]
        self.assertNotIn("mtls", default_payload)
        self.assertEqual(default_payload["origin"]["host"], probe.ORIGIN)
        self.assertEqual(default_payload["origin"]["port"], 5432)

        with mock.patch.object(probe, "api", return_value={
            "success": True, "result": {"id": "c" * 32},
        }) as custom_ca:
            self.assertEqual("c" * 32, probe.create_hyperdrive(
                "fake-token", "ordax-direct-ipv6-diag-39478283587",
                "ordax_direct_diag_39478283587", "mock-secret",
                "direct_ipv6_custom_ca"))
        ca_payload = custom_ca.call_args.args[3]
        self.assertEqual(ca_payload["origin"]["host"], probe.ORIGIN)
        self.assertEqual(ca_payload["origin"]["user"],
                         "ordax_direct_diag_39478283587")
        self.assertEqual(ca_payload["mtls"], {
            "sslmode": "verify-full",
            "ca_certificate_id": "00ed2880-f686-4831-ba18-b8981d6ed48a",
        })

        with mock.patch.object(probe, "api", return_value={
            "success": True, "result": {"id": "d" * 32},
        }) as verify_ca:
            self.assertEqual("d" * 32, probe.create_hyperdrive(
                "fake-token", "ordax-direct-ipv6-diag-39478283587",
                "ordax_direct_diag_39478283587", "mock-secret",
                "direct_ipv6_custom_ca_verify_ca"))
        verify_ca_payload = verify_ca.call_args.args[3]
        self.assertEqual(verify_ca_payload["origin"]["host"], probe.ORIGIN)
        self.assertEqual(verify_ca_payload["mtls"], {
            "sslmode": "verify-ca",
            "ca_certificate_id": "00ed2880-f686-4831-ba18-b8981d6ed48a",
        })

        with mock.patch.object(probe, "api", return_value={
            "success": True, "result": {"id": "e" * 32},
        }) as direct_ip:
            self.assertEqual("e" * 32, probe.create_hyperdrive(
                "fake-token", "ordax-direct-ipv6-diag-39478283587",
                "ordax_direct_diag_39478283587", "mock-secret",
                "direct_ip_custom_ca_verify_ca",
                origin_host_override="2600:1f18::5"))
        direct_ip_payload = direct_ip.call_args.args[3]
        self.assertEqual(direct_ip_payload["origin"]["host"], "2600:1f18::5")
        self.assertEqual(direct_ip_payload["mtls"], {
            "sslmode": "verify-ca",
            "ca_certificate_id": "00ed2880-f686-4831-ba18-b8981d6ed48a",
        })
        with self.assertRaisesRegex(probe.ProbeError, "origin_override_forbidden"):
            probe.create_hyperdrive(
                "fake-token", "ordax-direct-ipv6-diag-39478283587",
                "ordax_direct_diag_39478283587", "mock-secret",
                "direct_ipv6", origin_host_override="2600:1f18::5")
        for invalid in ("127.0.0.1", "::", "::1", "2001:db8::5", "not-an-ip"):
            with self.subTest(invalid=invalid), self.assertRaises(probe.ProbeError):
                probe.create_hyperdrive(
                    "fake-token", "ordax-direct-ipv6-diag-39478283587",
                    "ordax_direct_diag_39478283587", "mock-secret",
                    "direct_ip_custom_ca_verify_ca",
                    origin_host_override=invalid)

    def test_current_direct_ipv6_is_read_only_and_ipv6_only(self):
        with mock.patch.object(probe, "sql",
                               return_value=[{"address": "2600:1f18:abcd::1234"}]) as query:
            self.assertEqual(probe.current_direct_ipv6("fake-db-token"),
                             "2600:1f18:abcd::1234")
        query.assert_called_once_with(
            "fake-db-token", "select host(inet_server_addr()) as address")
        for rows in (
            [],
            [{"address": "127.0.0.1"}],
            [{"address": "::1"}],
            [{"address": "not-an-ip"}],
            [{"wrong": "2600:1f18::1"}],
        ):
            with self.subTest(rows=rows), \
                 mock.patch.object(probe, "sql", return_value=rows), \
                 self.assertRaises(probe.ProbeError):
                probe.current_direct_ipv6("fake-db-token")

    def test_isolated_pooler_modes_pin_hostname_port_and_tenant_user(self):
        role = "ordax_direct_diag_39478283587"
        self.assertEqual(probe.ORIGIN_MODES, (
            "direct_ipv6", "direct_ipv6_default_tls", "direct_ipv6_custom_ca",
            "direct_ipv6_custom_ca_verify_ca", "direct_ip_custom_ca_verify_ca",
            "pooler_session", "pooler_transaction", "worker_direct_pooler",
            "worker_direct_pooler_transaction",
            "worker_direct_pooler_transaction_nodejs_compat_v2",
            "worker_direct_pooler_transaction_postgres_js",
            "worker_direct_ipv6", "worker_direct_ipv6_custom_ca"))
        for mode in ("direct_ipv6", "direct_ipv6_default_tls", "direct_ipv6_custom_ca",
                     "direct_ipv6_custom_ca_verify_ca", "direct_ip_custom_ca_verify_ca",
                     "worker_direct_ipv6", "worker_direct_ipv6_custom_ca"):
            self.assertEqual(probe.origin_for_mode(mode, role), {
                "scheme": "postgres", "database": "postgres", "user": role,
                "host": probe.ORIGIN, "port": 5432})
        self.assertEqual(probe.origin_for_mode("worker_direct_pooler", role), {
            "scheme": "postgres", "database": "postgres",
            "user": role + "." + probe.PROJECT,
            "host": probe.POOLER_ORIGIN, "port": 5432})
        self.assertEqual(probe.origin_for_mode("worker_direct_pooler_transaction", role), {
            "scheme": "postgres", "database": "postgres",
            "user": role + "." + probe.PROJECT,
            "host": probe.POOLER_ORIGIN, "port": 6543})
        self.assertEqual(
            probe.origin_for_mode("worker_direct_pooler_transaction_nodejs_compat_v2", role),
            {"scheme": "postgres", "database": "postgres",
             "user": role + "." + probe.PROJECT,
             "host": probe.POOLER_ORIGIN, "port": 6543})
        self.assertEqual(
            probe.origin_for_mode("worker_direct_pooler_transaction_postgres_js", role),
            {"scheme": "postgres", "database": "postgres",
             "user": role + "." + probe.PROJECT,
             "host": probe.POOLER_ORIGIN, "port": 6543})
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
        for mode, port in (("pooler_session", "5432"),
                           ("pooler_transaction", "6543"),
                           ("worker_direct_pooler", "5432"),
                           ("worker_direct_pooler_transaction", "6543"),
                           ("worker_direct_pooler_transaction_nodejs_compat_v2", "6543"),
                           ("worker_direct_pooler_transaction_postgres_js", "6543")):
            with self.subTest(mode=mode), \
                 mock.patch.object(probe.shutil, "which", return_value="/usr/bin/psql"), \
                 mock.patch.object(probe.subprocess, "run", return_value=mock.Mock(
                     returncode=0, stdout=bytes([49, 10]))) as runner:
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
        self.assertIn("direct_ipv6_default_tls", workflow)
        self.assertIn("direct_ipv6_custom_ca", workflow)
        self.assertIn("direct_ipv6_custom_ca_verify_ca", workflow)
        self.assertIn("worker_direct_pooler", workflow)
        self.assertIn("worker_direct_pooler_transaction", workflow)
        self.assertIn("worker_direct_pooler_transaction_nodejs_compat_v2", workflow)
        self.assertIn("worker_direct_pooler_transaction_postgres_js", workflow)
        self.assertIn("worker_direct_ipv6", workflow)
        self.assertIn("worker_direct_ipv6_custom_ca", workflow)
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

    def test_worker_tcp_failure_diagnostic_is_strictly_allowlisted(self):
        uri = "https://ordax-direct-ipv6-diag-39478283587.ordaxsystems.workers.dev/"
        error = urllib.error.HTTPError(uri, 503, "private trace", {}, BytesIO(
            b'{"ok":false,"phase":"tcp","classification":"origin_tcp_unreachable",'
            b'"secret":"mock-secret"}'))
        with mock.patch.object(probe.OPENER, "open", side_effect=error):
            status = probe.api("GET", uri)
        self.assertEqual(status, {"ok": False, "phase": "tcp",
                                  "classification": "origin_tcp_unreachable"})
        self.assertNotIn("mock-secret", json.dumps(status))

    def test_worker_tls_failure_diagnostic_is_strictly_allowlisted(self):
        uri = "https://ordax-direct-ipv6-diag-39478283587.ordaxsystems.workers.dev/"
        error = urllib.error.HTTPError(uri, 503, "private trace", {}, BytesIO(
            b'{"ok":false,"phase":"tls","classification":"tls_upgrade_failed",'
            b'"secret":"mock-secret"}'))
        with mock.patch.object(probe.OPENER, "open", side_effect=error):
            status = probe.api("GET", uri)
        self.assertEqual(status, {"ok": False, "phase": "tls",
                                  "classification": "tls_upgrade_failed"})
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

    def test_curl_worker_503_retries_bounded_then_returns_only_safe_postgres_phase(self):
        failure = mock.Mock(returncode=0, stdout=(
            b'{"ok":false,"phase":"connect","classification":"connection_terminated",'
            b'"secret":"mock-secret"}' + bytes([10]) + b"503"), stderr=b"")
        with mock.patch.object(probe.shutil, "which", return_value="/usr/bin/curl"), \
             mock.patch.object(probe.subprocess, "run", return_value=failure) as runner, \
             mock.patch.object(probe.time, "sleep") as sleep:
            result = probe.check_worker("ordax-direct-ipv6-diag-39478283587")
        self.assertEqual(result, {"ok": False, "phase": "connect",
                                  "classification": "connection_terminated"})
        self.assertEqual(runner.call_count, 6)
        self.assertEqual(sleep.call_count, 5)
        self.assertNotIn("mock-secret", json.dumps(result))

    def test_curl_worker_accepts_postgres_js_connect_or_query_phase(self):
        failure = mock.Mock(returncode=0, stdout=(
            b'{"ok":false,"phase":"connect_or_query","classification":"connection_closed"}'
            + bytes([10]) + b"503"), stderr=b"")
        with mock.patch.object(probe.shutil, "which", return_value="/usr/bin/curl"), \
             mock.patch.object(probe.subprocess, "run", return_value=failure) as runner, \
             mock.patch.object(probe.time, "sleep") as sleep:
            result = probe.check_worker("ordax-direct-ipv6-diag-39478283587")
        self.assertEqual(result, {"ok": False, "phase": "connect_or_query",
                                  "classification": "connection_closed"})
        self.assertEqual(runner.call_count, 6)
        self.assertEqual(sleep.call_count, 5)

    def test_curl_worker_accepts_bounded_sqlstate_classification(self):
        failure = mock.Mock(returncode=0, stdout=(
            b'{"ok":false,"phase":"connect","classification":"sqlstate_58000"}'
            + bytes([10]) + b"503"), stderr=b"")
        with mock.patch.object(probe.shutil, "which", return_value="/usr/bin/curl"), \
             mock.patch.object(probe.subprocess, "run", return_value=failure) as runner, \
             mock.patch.object(probe.time, "sleep") as sleep:
            result = probe.check_worker("ordax-direct-ipv6-diag-39478283587")
        self.assertEqual(result, {"ok": False, "phase": "connect",
                                  "classification": "sqlstate_58000"})
        self.assertEqual(runner.call_count, 6)
        self.assertEqual(sleep.call_count, 5)

    def test_curl_worker_503_can_recover_within_bounded_warmup_window(self):
        failure = mock.Mock(returncode=0, stdout=(
            b'{"ok":false,"phase":"connect","classification":"unclassified"}'
            + bytes([10]) + b"503"), stderr=b"")
        good = mock.Mock(returncode=0, stdout=(
            b'{"ok":true,"phase":"complete"}' + bytes([10]) + b"200"), stderr=b"")
        with mock.patch.object(probe.shutil, "which", return_value="/usr/bin/curl"), \
             mock.patch.object(probe.subprocess, "run",
                               side_effect=[failure, failure, good]) as runner, \
             mock.patch.object(probe.time, "sleep") as sleep:
            result = probe.check_worker("ordax-direct-ipv6-diag-39478283587")
        self.assertEqual(result, {"ok": True, "phase": "complete"})
        self.assertEqual(runner.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

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
        self.assertIn("openPostgresSession(connectionString, probeTlsTrust(env))", text)
        self.assertIn("ORDAX_PROBE_DIRECT_POSTGRES", text)
        self.assertIn("ORDAX_PROBE_DB_PASSWORD", text)
        self.assertIn("ORDAX_PROBE_TLS_CA", text)
        self.assertIn("ORDAX_PROBE_DRIVER", text)
        self.assertIn('import postgres from "postgres"', text)
        self.assertIn('env.ORDAX_PROBE_DRIVER === "postgres_js"', text)
        self.assertIn("fetch_types: false", text)
        self.assertIn('"--secrets-file"', (ROOT / "scripts/cloudflare/probe_hyperdrive_direct_origin.py").read_text("utf-8"))
        self.assertIn("secret_path.unlink(missing_ok=True)", (ROOT / "scripts/cloudflare/probe_hyperdrive_direct_origin.py").read_text("utf-8"))
        self.assertNotIn('["npx", "--yes", "wrangler@4.141.0", "secret", "put"', (ROOT / "scripts/cloudflare/probe_hyperdrive_direct_origin.py").read_text("utf-8"))
        self.assertIn("SUPABASE_2021_CA_CHAIN", text)
        self.assertIn("rejectUnauthorized: true", text)
        self.assertIn("servername", text)
        self.assertIn("encodeURIComponent(password)", text)
        self.assertIn('host.includes(":") ? `[${host}]` : host', text)
        self.assertIn('from "cloudflare:sockets"', text)
        self.assertIn("socket.opened", text)
        self.assertIn('if (env.ORDAX_PROBE_DIRECT_POSTGRES === "1")', text)
        self.assertIn("origin_tcp_unreachable", text)
        self.assertIn('secureTransport: "starttls"', text)
        self.assertIn("socket.startTls()", text)
        self.assertIn("new Uint8Array([0, 0, 0, 8, 4, 210, 22, 47])", text)
        self.assertIn("ssl_request_rejected", text)
        self.assertIn("tls_upgrade_failed", text)
        self.assertIn("hyperdrive_internal_error", text)
        self.assertIn("hyperdrive_generic_error", text)
        self.assertIn("hyperdrive_pool_acquire_failed", text)
        self.assertIn("hyperdrive_server_connection_failed", text)
        self.assertIn("hyperdrive_database_connect_failed", text)
        self.assertIn('"hyperdrive_code_" + providerCode', text)
        self.assertIn('/^20(?:08|09|10|11|12|13|14|15|16)$/.test(providerCode)', text)
        self.assertIn('"sqlstate_" + code', text)
        self.assertIn('/^[0-9A-Z]{5}$/.test(code)', text)
        self.assertLess(text.index("hyperdrive_internal_error"),
                        text.index('"sqlstate_" + code'))
        self.assertNotIn("return msg", text)
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
