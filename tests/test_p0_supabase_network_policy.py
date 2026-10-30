import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
src = ROOT / "scripts/cloudflare/audit_supabase_network_policy.py"
spec = importlib.util.spec_from_file_location("ordax_supabase_policy", src)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class PolicyAuditTests(unittest.TestCase):
    def test_canonical_project_and_read_only_route(self):
        self.assertTrue(mod.URL.endswith("/projects/jhfphsjptrpmtnzkpwud/network-restrictions"))
        self.assertNotIn("/apply", mod.URL)
        self.assertNotIn("password", src.read_text(encoding="utf-8").lower())

    def test_preserves_empty_policy_vs_unknown(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = (
            b'{"entitlement":"allowed","status":"stored","config":{"dbAllowedCidrs":[],"dbAllowedCidrsV6":[]}}'
        )
        with mock.patch.object(mod.urllib.request, "urlopen", return_value=response) as call:
            r = mod.inspect("synthetic-bearer")
        self.assertIs(r["applied"], False)
        self.assertEqual(r["ipv4_count"], 0)
        self.assertEqual(r["ipv6_count"], 0)
        self.assertEqual(call.call_args.args[0].method, "GET")
        self.assertNotIn("synthetic-bearer", str(r))

    def test_never_prints_allowlist_or_raw_body(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = (
            b'{"entitlement":"allowed","status":"applied","config":{"dbAllowedCidrs":["192.0.2.1/24"],'
            b'"dbAllowedCidrsV6":["2001:db8::/64"]}}'
        )
        with mock.patch.object(mod.urllib.request, "urlopen", return_value=response):
            r = mod.inspect("synthetic-bearer")
        self.assertIs(r["applied"], True)
        self.assertNotIn("192.0.2.1", str(r))
        self.assertNotIn("2001:db8", str(r))

    def test_unknown_schema_is_unknown_not_unrestricted(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"new_policy_version":4}'
        with mock.patch.object(mod.urllib.request, "urlopen", return_value=response):
            r = mod.inspect("synthetic-bearer")
        self.assertEqual(r["applied"], "unknown")
        self.assertIsNone(r["ipv4_count"])


if __name__ == "__main__":
    unittest.main()
