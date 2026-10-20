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
