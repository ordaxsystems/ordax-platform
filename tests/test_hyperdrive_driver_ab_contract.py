"""Regression tests for isolated Hyperdrive driver A/B proof and cleanup."""
import importlib.util
import json
import os
from pathlib import Path
from unittest import TestCase, main, mock

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "scripts/cloudflare/probe_hyperdrive_driver_ab.py"
SPEC = importlib.util.spec_from_file_location("ordax_driver_ab", TARGET)
assert SPEC is not None and SPEC.loader is not None
ab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ab)


class HyperdriveDriverAbTest(TestCase):
    def test_one_existing_canonical_binding_without_new_authority(self):
        conf = ab.config("ordax-hyperdrive-ab-39494974328")
        self.assertIn('id = "4b601ec5815f43259bd8040053825d2a"', conf)
        self.assertIn('main = "labs/hyperdrive_driver_ab.ts"', conf)
        self.assertNotIn("db.jhfphsjptrpmtnzkpwud", conf)
        self.assertNotIn("secret", conf.lower())
        for value in ("ordax-mcp", "test-run", "ordax-hyperdrive-ab-1"):
            with self.assertRaises(ab.ProbeFailure):
                ab.config(value)

    def test_worker_compares_only_two_sql_drivers_read_only(self):
        worker = (ROOT / "control-plane/cloudflare/labs/hyperdrive_driver_ab.ts").read_text("utf8")
        self.assertIn("openPostgresSession", worker)
        self.assertIn('from "postgres"', worker)
        self.assertEqual(worker.count("select 1::int as ok"), 2)
        for forbidden in ("INSERT INTO", "DELETE FROM", "UPDATE ", "DROP TABLE", "CREATE TABLE", "/mcp", "env.DB", "service_role"):
            self.assertNotIn(forbidden, worker)
        self.assertIn('"/pg"', worker)
        self.assertIn('"/postgres-js"', worker)

    def test_error_only_whitelisted(self):
        mockproc = mock.Mock(returncode=0, stdout=json.dumps({
            "driver": "node_postgres", "ok": False, "phase": "connect",
            "classification": "terminated_unexpectedly",
            "error_details": "hidden private password",
        }).encode() + bytes([10]) + b"503", stderr=b"hidden secret")
        with mock.patch.object(ab.subprocess, "run", return_value=mockproc):
            report = ab.probe("ordax-hyperdrive-ab-39494974328", "/pg")
        self.assertEqual(report, {"driver": "node_postgres", "ok": False, "phase": "connect",
                                  "classification": "terminated_unexpectedly"})
        self.assertNotIn("hidden", json.dumps(report))

    def test_machine_codes_are_bounded_and_secret_strings_never_escape(self):
        raw = {"driver": "postgres_js", "ok": False,
               "phase": "connect_or_query", "classification": "other",
               "code": "CONNECTION_CLOSED", "error_class": "PostgresError",
               "secret": "postgres://mock-secret"}
        response = mock.Mock(returncode=0, stdout=json.dumps(raw).encode() + bytes([10]) + b"503", stderr=b"password hidden")
        with mock.patch.object(ab.subprocess, "run", return_value=response):
            report = ab.probe("ordax-hyperdrive-ab-39494974328", "/postgres-js")
        self.assertEqual(report.get("code"), "CONNECTION_CLOSED")
        self.assertEqual(report.get("error_class"), "PostgresError")
        self.assertNotIn("mock-secret", json.dumps(report))
        raw["code"] = "bad token mock-secret"
        raw["error_class"] = "SecretError"
        response.stdout = json.dumps(raw).encode() + bytes([10]) + b"503"
        with mock.patch.object(ab.subprocess, "run", return_value=response):
            report = ab.probe("ordax-hyperdrive-ab-39494974328", "/postgres-js")
        self.assertNotIn("code", report)
        self.assertNotIn("error_class", report)

    def test_success_and_protected_path(self):
        mockproc = mock.Mock(returncode=0, stdout=b'{"driver":"postgres_js","ok":true,"phase":"complete"}' + bytes([10]) + b"200", stderr=b"")
        with mock.patch.object(ab.subprocess, "run", return_value=mockproc):
            self.assertEqual(ab.probe("ordax-hyperdrive-ab-39494974328", "/postgres-js"),
                             {"driver": "postgres_js", "ok": True, "phase": "complete"})
        with self.assertRaises(ab.ProbeFailure):
            ab.probe("ordax-hyperdrive-ab-39494974328", "/other")

    def test_403_is_bounded_never_replays_sql_mutation(self):
        mockproc = mock.Mock(returncode=0, stdout=b"private error" + bytes([10]) + b"403", stderr=b"private")
        with mock.patch.object(ab.subprocess, "run", return_value=mockproc) as called, mock.patch.object(ab.time, "sleep") as sleep:
            result = ab.probe("ordax-hyperdrive-ab-39494974328", "/pg")
        self.assertEqual(result["classification"], "http_403")
        self.assertEqual(called.call_count, 5)
        self.assertEqual(sleep.call_count, 4)

    def test_cleanup_even_when_deploy_fails(self):
        with mock.patch.dict(os.environ, {
                "CLOUDFLARE_API_TOKEN": "fake-admin-token", "GITHUB_RUN_ID": "39494974328"}), \
             mock.patch.object(ab, "deploy", side_effect=ab.ProbeFailure("deploy_failed")), \
             mock.patch.object(ab, "delete_worker", return_value=True) as remove:
            with self.assertRaises(ab.ProbeFailure):
                ab.run()
        remove.assert_called_once_with("ordax-hyperdrive-ab-39494974328", "fake-admin-token")

    def test_cleanup_after_both_fail(self):
        failures = [
            {"driver": "node_postgres", "ok": False, "phase": "connect",
             "classification": "terminated_unexpectedly"},
            {"driver": "postgres_js", "ok": False, "phase": "connect_or_query",
             "classification": "connection_closed"},
        ]
        with mock.patch.dict(os.environ, {
                "CLOUDFLARE_API_TOKEN": "fake-admin-token", "GITHUB_RUN_ID": "39494974328"}), \
             mock.patch.object(ab, "deploy"), \
             mock.patch.object(ab, "probe", side_effect=failures), \
             mock.patch.object(ab, "delete_worker", return_value=True) as remove:
            with self.assertRaisesRegex(ab.ProbeFailure, "both_drivers_unavailable"):
                ab.run()
        remove.assert_called_once()

    def test_workflow_must_be_manual_and_protected(self):
        workflow = (ROOT / ".github/workflows/hyperdrive-driver-ab.yml").read_text("utf8")
        self.assertIn("workflow_dispatch", workflow)
        self.assertIn("environment: cloudflare-v3", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertNotIn("schedule:", workflow)
        self.assertIn("postgres@3.4.5", workflow)
        self.assertIn('- name: "Dry-run only: no deployed Worker"', workflow)
        self.assertNotIn("SUPABASE_ACCESS_TOKEN", workflow)


if __name__ == "__main__":
    main()
