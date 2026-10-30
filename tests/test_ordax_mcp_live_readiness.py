"""Contract tests for the external, read-only MCP release gate."""
import importlib.util
from pathlib import Path
import unittest

import httpx

PATH = Path(__file__).resolve().parents[1] / "scripts/verify_ordax_mcp_live.py"
spec = importlib.util.spec_from_file_location("ordax_mcp_live_check", PATH)
probe = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(probe)


class MCPReadinessGateTests(unittest.TestCase):
    def http(self, data, status=200, headers=None):
        return httpx.Client(transport=httpx.MockTransport(
            lambda req: httpx.Response(status, json=data, headers=headers)
        ))

    def test_healthy_requires_both_auth_and_database_and_actions(self):
        body = {
            "ok": True, "service": "ordax-platform-mcp",
            "oauth_discovery_ready": True, "postgres_ready": True,
            "supports_attested_remote_reads": True, "supports_remote_actions": True,
        }
        with self.http(body) as client:
            self.assertTrue(probe.check("https://mcp.ordax.com.br", client=client)["ok"])
        for key in ["ok", "oauth_discovery_ready", "postgres_ready",
                    "supports_attested_remote_reads", "supports_remote_actions"]:
            with self.subTest(missing=key), self.http({**body, key: None}) as client:
                with self.assertRaises(probe.MCPNotReady):
                    probe.check("https://mcp.ordax.com.br", client=client)

    def test_postgres_connect_failure_is_not_reported_as_ready(self):
        body = {"ok": False, "service": "ordax-platform-mcp",
                "oauth_discovery_ready": True, "postgres_ready": False,
                "error": "product_postgres_unavailable", "postgres_failure_stage": "connect"}
        with self.http(body, 503) as client:
            with self.assertRaisesRegex(probe.MCPNotReady, "^product_postgres_unavailable:connect$"):
                probe.check("https://mcp.ordax.com.br", client=client)

    def test_service_redirect_and_unsafe_origin_fail_closed(self):
        with self.http({"ok": True}, 302, {"Location": "https://evil.invalid"}) as client:
            with self.assertRaises(probe.MCPNotReady):
                probe.check("https://mcp.ordax.com.br", client=client)
        for origin in ("http://mcp.ordax.com.br", "https://user:token@mcp.ordax.com.br",
                       "https://mcp.ordax.com.br/other", "https://mcp.ordax.com.br?a=1"):
            with self.subTest(origin=origin):
                with self.assertRaisesRegex(probe.MCPNotReady, "invalid_mcp_origin"):
                    probe.check(origin)

    def test_public_errors_do_not_expose_sensitive_upstream_errors(self):
        with self.http({"service": "ordax-platform-mcp", "error": "password=secret"},503) as client:
            with self.assertRaisesRegex(probe.MCPNotReady, "^mcp_dependencies_not_ready$"):
                probe.check("https://mcp.ordax.com.br", client=client)


if __name__ == "__main__":
    unittest.main()
