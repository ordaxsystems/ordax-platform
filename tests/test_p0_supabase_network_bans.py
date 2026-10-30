import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

TARGET = Path(__file__).resolve().parents[1] / "scripts/cloudflare/audit_supabase_network_bans.py"
spec = importlib.util.spec_from_file_location("ordax_ban_audit", TARGET)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class NetworkBanAuditTests(unittest.TestCase):
    def test_read_only_post_and_canonical_project(self):
        obj = mock.MagicMock()
        obj.__enter__.return_value.read.return_value = json.dumps({
            "banned_ipv4_addresses": [{"banned_address": "192.0.2.88",
                                       "type": "pooler", "identifier": "private"}],
        }).encode()
        with mock.patch.object(mod.urllib.request, "urlopen", return_value=obj) as fetch:
            result = mod.inspect("fake-admin-token")
        req = fetch.call_args.args[0]
        self.assertEqual(req.get_method(), "POST")
        self.assertIn("/projects/jhfphsjptrpmtnzkpwud/network-bans/retrieve/enriched", req.full_url)
        self.assertEqual(result, {"banned_ipv4_count": 1, "has_active_bans": True})
        self.assertNotIn("192.0.2.88", str(result))
        self.assertNotIn("fake-admin-token", str(result))

    def test_overlap_returns_counts_not_ip_addresses(self):
        from io import BytesIO
        bans = mock.MagicMock()
        bans.__enter__.return_value.read.return_value = json.dumps({
            "banned_ipv4_addresses": [
                {"banned_address": "173.245.48.12/32"},
                {"banned_address": "192.0.2.12"},
            ],
        }).encode()
        cf = mock.MagicMock()
        cf.__enter__.return_value.read.return_value = json.dumps({
            "success": True,
            "result": {"ipv4_cidrs": [
                "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
                "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
                "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
                "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
                "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
            ]},
        }).encode()
        with mock.patch.object(mod.urllib.request, "urlopen", side_effect=[bans, cf]):
            report = mod.inspect("synthetic", include_cloudflare_overlap=True)
        self.assertEqual(report["cloudflare_banned_ipv4_count"], 1)
        self.assertEqual(report["other_banned_ipv4_count"], 1)
        self.assertEqual(report["unparsed_ban_count"], 0)
        self.assertNotIn("173.245.48.12", str(report))
        self.assertNotIn("192.0.2.12", str(report))

    def test_empty_list_and_invalid_shape(self):
        obj = mock.MagicMock()
        obj.__enter__.return_value.read.return_value = b'{"banned_ipv4_addresses":[]}'
        with mock.patch.object(mod.urllib.request, "urlopen", return_value=obj):
            self.assertEqual(mod.inspect("synthetic")["banned_ipv4_count"], 0)
        obj.__enter__.return_value.read.return_value = b'{"banned_ipv4_addresses":["bad"]}'
        with mock.patch.object(mod.urllib.request, "urlopen", return_value=obj):
            with self.assertRaises(mod.BanAuditFailure):
                mod.inspect("synthetic")


if __name__ == "__main__":
    unittest.main()
