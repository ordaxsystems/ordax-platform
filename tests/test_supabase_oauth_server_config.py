from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "scripts" / "supabase" / "reconcile_oauth_server_config.py"
SPEC = importlib.util.spec_from_file_location("oauth_config", PATH)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class Response:
    def __init__(self, body):
        self.body = json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, _limit):
        return self.body


class OAuthConfigTests(unittest.TestCase):
    def test_check_reports_only_canonical_drift_keys(self):
        current = {**mod.EXPECTED, "site_url": "https://legacy.invalid"}
        with patch.object(mod.urllib.request, "urlopen", return_value=Response(current)):
            result = mod.reconcile("token", apply=False)
        self.assertEqual(result["state"], "drift")
        self.assertEqual(result["drift_keys"], ["site_url"])

    def test_apply_patches_exact_fields_and_verifies(self):
        current = {
            **mod.EXPECTED,
            "site_url": "https://legacy.invalid",
            "oauth_server_authorization_path": "/legacy",
        }
        final = dict(mod.EXPECTED)
        calls = []

        def fake_open(req, timeout=0):
            calls.append((req.method, req.data))
            if req.method == "GET" and len(calls) == 1:
                return Response(current)
            if req.method == "PATCH":
                body = json.loads(req.data)
                self.assertEqual(body, mod.EXPECTED)
                return Response(final)
            return Response(final)

        with patch.object(mod.urllib.request, "urlopen", side_effect=fake_open):
            result = mod.reconcile("token", apply=True)

        self.assertEqual(result["state"], "applied")
        self.assertEqual(result["config"], mod.EXPECTED)
        self.assertEqual([method for method, _ in calls], ["GET", "PATCH", "GET"])

    def test_in_sync_never_writes(self):
        with patch.object(mod.urllib.request, "urlopen", return_value=Response(mod.EXPECTED)) as mocked:
            result = mod.reconcile("token", apply=True)
        self.assertEqual(result["state"], "in_sync")
        self.assertEqual(mocked.call_count, 1)


if __name__ == "__main__":
    unittest.main()
