"""Proof that the P0 repair preserves restrictions and fails closed."""
import importlib.util
import ipaddress
import json
from contextlib import redirect_stdout
from io import StringIO
import os
from pathlib import Path
from unittest import TestCase, main, mock

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "scripts/cloudflare/reconcile_hyperdrive_cloudflare_egress.py"
SPEC = importlib.util.spec_from_file_location("ordax_hyperdrive_egress", FILE)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

OLD = {"dbAllowedCidrs": ["203.0.113.4/32"], "dbAllowedCidrsV6": ["2001:db8::1/128"]}


class HyperdriveEgressRepairTests(TestCase):
    def test_official_snapshot_has_no_default_route(self):
        self.assertEqual(len(mod.CF_V4), 15)
        self.assertEqual(len(mod.CF_V6), 7)
        for value in mod.CF_V4 | mod.CF_V6:
            network = ipaddress.ip_network(value, strict=True)
            self.assertGreater(network.prefixlen, 0)

    def test_vendor_snapshot_verified_through_official_api(self):
        import io
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps({
            "success": True, "result": {
                "ipv4_cidrs": sorted(mod.CF_V4), "ipv6_cidrs": sorted(mod.CF_V6),
            },
        }).encode()
        with mock.patch.object(mod.urllib.request, "urlopen", return_value=response) as fetch:
            mod.official_cloudflare_networks()
        self.assertEqual(fetch.call_args.args[0], "https://api.cloudflare.com/client/v4/ips")
        bad = mock.MagicMock()
        bad.__enter__.return_value.read.return_value = json.dumps({
            "success": True, "result": {
                "ipv4_cidrs": [], "ipv6_cidrs": sorted(mod.CF_V6),
            },
        }).encode()
        with mock.patch.object(mod.urllib.request, "urlopen", return_value=bad):
            with self.assertRaisesRegex(mod.RepairFailure, "official_cloudflare_ip_list_mismatch"):
                mod.official_cloudflare_networks()

    def test_merge_preserves_original_allowed_cidrs(self):
        added = mod.merge(OLD)
        self.assertTrue(set(OLD["dbAllowedCidrs"]).issubset(added["dbAllowedCidrs"]))
        self.assertTrue(set(OLD["dbAllowedCidrsV6"]).issubset(added["dbAllowedCidrsV6"]))
        self.assertEqual(len(added["dbAllowedCidrs"]), 16)
        self.assertEqual(len(added["dbAllowedCidrsV6"]), 8)
        self.assertNotIn("0.0.0.0/0", added["dbAllowedCidrs"])
        self.assertNotIn("::/0", added["dbAllowedCidrsV6"])
        self.assertEqual(OLD["dbAllowedCidrs"], ["203.0.113.4/32"])

    def test_policy_reads_current_shape_and_never_logs_cidrs(self):
        response = {"entitlement": "allowed", "status": "applied",
                    "config": OLD}
        with mock.patch.object(mod, "request", return_value=response) as request:
            data, status = mod.policy("synthetic-secret")
        self.assertEqual(data, OLD)
        self.assertEqual(status, "applied")
        self.assertEqual(request.call_args.args[0], "GET")
        self.assertEqual(request.call_args.args[1], mod.API)

    def test_policy_rejects_unexpected_shapes(self):
        for cfg in (None, {}, {"dbAllowedCidrs": ["not a CIDR"], "dbAllowedCidrsV6": []}):
            with mock.patch.object(mod, "request", return_value={
                "entitlement": "allowed", "status": "applied", "config": cfg,
            }):
                with self.assertRaises(mod.RepairFailure):
                    mod.policy("synthetic")

    def test_policy_acl_only_when_active(self):
        with mock.patch.object(mod, "request", return_value={
            "entitlement": "disallowed", "status": "stored", "config": OLD,
        }):
            with self.assertRaises(mod.RepairFailure):
                mod.policy("synthetic")

    def test_if_already_covered_no_mutation_on_unavailable_backend(self):
        old = mod.merge(OLD)
        with mock.patch.dict(os.environ, {"SUPABASE_ACCESS_TOKEN": "synthetic"}), \
             mock.patch.object(mod, "policy", return_value=(old, "applied")), \
             mock.patch.object(mod, "official_cloudflare_networks"), \
             mock.patch.object(mod, "ready", return_value=False), \
             mock.patch.object(mod, "update_policy") as update:
            with self.assertRaisesRegex(mod.RepairFailure, "covered_network_but_postgres_unavailable"):
                mod.run()
            update.assert_not_called()

    def test_ready_failure_restores_original_acl_only_when_ours(self):
        expected = mod.merge(OLD)
        calls = []
        with mock.patch.dict(os.environ, {"SUPABASE_ACCESS_TOKEN": "synthetic"}), \
             mock.patch.object(mod, "policy", side_effect=[(OLD, "applied"), (expected, "applied")]), \
             mock.patch.object(mod, "official_cloudflare_networks"), \
             mock.patch.object(mod, "ready", return_value=False), \
             mock.patch.object(mod, "wait_for_applied", return_value=True), \
             mock.patch.object(mod.time, "sleep"), \
             mock.patch.object(mod, "update_policy", side_effect=lambda _, acl: calls.append(acl)):
            with self.assertRaisesRegex(mod.RepairFailure, "mcp_remains_unavailable_after_network_repair"):
                mod.run()
        self.assertEqual(len(calls), 2)
        self.assertTrue(mod.equal_acl(calls[0], expected))
        self.assertEqual(calls[1], OLD)

    def test_ready_success_keeps_explicit_acl(self):
        expected = mod.merge(OLD)
        calls = []
        with mock.patch.dict(os.environ, {"SUPABASE_ACCESS_TOKEN": "synthetic"}), \
             mock.patch.object(mod, "policy", return_value=(OLD, "applied")), \
             mock.patch.object(mod, "official_cloudflare_networks"), \
             mock.patch.object(mod, "ready", return_value=True), \
             mock.patch.object(mod, "wait_for_applied", return_value=True), \
             mock.patch.object(mod, "update_policy", side_effect=lambda _, acl: calls.append(acl)):
            mod.run()
        self.assertEqual(len(calls), 1)
        self.assertTrue(mod.equal_acl(calls[0], expected))

    def test_concurrent_changes_are_never_overwritten(self):
        updated = mod.merge(OLD)
        other = {"dbAllowedCidrs": updated["dbAllowedCidrs"] + ["192.0.2.34/32"],
                 "dbAllowedCidrsV6": updated["dbAllowedCidrsV6"]}
        with mock.patch.object(mod, "policy", return_value=(other, "applied")), \
             mock.patch.object(mod, "update_policy") as update:
            with self.assertRaisesRegex(mod.RepairFailure, "rollback_blocked_concurrent_change"):
                mod.rollback_if_ours("synthetic", OLD, updated)
            update.assert_not_called()

    def test_inspection_reports_bans_without_leaking_addresses_or_mutation(self):
        acl = mod.merge(OLD)
        receipt = {"banned_ipv4_addresses": ["173.245.48.3", "198.51.100.12"]}
        with mock.patch.object(mod, "policy", return_value=(acl, "applied")), \
             mock.patch.object(mod, "request", return_value=receipt) as read, \
             mock.patch.object(mod, "update_policy") as update, \
             redirect_stdout(StringIO()) as capture:
            mod.inspect_only("synthetic-token")
        output = capture.getvalue()
        self.assertIn("ORDAX_NETWORK_INSPECTION=COMPLETE_NO_CHANGES", output)
        self.assertIn("ORDAX_NETWORK_CLOUDFLARE_IPV4_COVERED=true", output)
        self.assertIn("ORDAX_NETWORK_BANS_IPV4_COUNT=2", output)
        self.assertIn("ORDAX_NETWORK_BANS_CLOUDFLARE_OVERLAP=1", output)
        self.assertNotIn("173.245.48.3", output)
        self.assertNotIn("198.51.100.12", output)
        self.assertNotIn("synthetic-token", output)
        self.assertEqual(read.call_args.args[:2], (
            "POST", "https://api.supabase.com/v1/projects/" + mod.PROJECT + "/network-bans/retrieve"))
        update.assert_not_called()

    def test_inspection_accepts_one_documented_response_envelope(self):
        with mock.patch.object(mod, "policy", return_value=(OLD, "applied")), \
             mock.patch.object(mod, "request", return_value={
                 "result": {"banned_ipv4_addresses": []}}), \
             mock.patch.object(mod, "update_policy") as update, \
             redirect_stdout(StringIO()) as capture:
            mod.inspect_only("synthetic")
        self.assertIn("ORDAX_NETWORK_BANS_IPV4_COUNT=0", capture.getvalue())
        update.assert_not_called()

    def test_inspection_rejects_malformed_bans_without_writes(self):
        with mock.patch.object(mod, "policy", return_value=(OLD, "applied")), \
             mock.patch.object(mod, "request", return_value={"banned_ipv4_addresses": ["nonsense"]}), \
             mock.patch.object(mod, "update_policy") as update, \
             redirect_stdout(StringIO()):
            with self.assertRaisesRegex(mod.RepairFailure, "network_bans_response_invalid"):
                mod.inspect_only("synthetic")
        update.assert_not_called()

    def test_unknown_provider_receipt_logs_keys_only_without_values(self):
        with mock.patch.object(mod, "policy", return_value=(OLD, "applied")), \
             mock.patch.object(mod, "request", return_value={
                 "unsupported": "private-credential-abcdef"}), \
             mock.patch.object(mod, "update_policy") as update, \
             redirect_stdout(StringIO()) as capture:
            with self.assertRaisesRegex(mod.RepairFailure, "network_bans_response_invalid"):
                mod.inspect_only("synthetic")
        self.assertIn("ORDAX_NETWORK_BANS_RESPONSE_KEYS=", capture.getvalue())
        self.assertNotIn("private-credential-abcdef", capture.getvalue())
        update.assert_not_called()

    def test_manual_protected_workflow_only(self):
        c = (ROOT / ".github/workflows/hyperdrive-egress-repair.yml").read_text("utf8")
        self.assertIn("workflow_dispatch", c)
        self.assertIn("environment: cloudflare-v3", c)
        self.assertIn("github.ref == 'refs/heads/main'", c)
        self.assertNotIn("schedule:", c)
        self.assertIn("default: inspect", c)
        self.assertIn("ORDAX_NETWORK_DIAGNOSTIC_MODE: ${{ inputs.mode }}", c)


if __name__ == "__main__":
    main()
