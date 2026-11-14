from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOUNDATION = ROOT / "control-plane" / "cloudflare" / "production-foundation.json"
MCP = ROOT / "plugins" / "forge-chatgpt" / "mcp.json"
DOC = ROOT / "docs" / "CHATGPT-CUSTOM-MCP-SERVER.md"


class ForgeChatGptMcpConfigTests(unittest.TestCase):
    def setUp(self):
        self.foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        self.mcp = json.loads(MCP.read_text(encoding="utf-8"))

    def test_config_uses_foundation_custom_domain(self):
        forge = self.foundation["forge_mcp_gateway"]
        server = self.mcp["mcpServers"]["forge"]
        self.assertEqual(server["type"], "streamable-http")
        self.assertEqual(server["url"], f"https://{forge['hostname']}{forge['path']}")
        self.assertEqual(server["url"], "https://forge-mcp.ordax.com.br/mcp")

    def test_forge_and_ordax_share_worker_and_oauth_but_not_public_endpoint(self):
        forge = self.foundation["forge_mcp_gateway"]
        ordax = self.foundation["mcp_release"]
        self.assertEqual(forge["worker_name"], ordax["worker_name"])
        self.assertEqual(forge["oauth_issuer"], ordax["oauth_issuer"])
        self.assertNotEqual(forge["hostname"], ordax["hostname"])

    def test_user_documentation_forbids_per_machine_tunnel_setup(self):
        doc = DOC.read_text(encoding="utf-8")
        self.assertIn("https://forge-mcp.ordax.com.br/mcp", doc)
        self.assertIn("mesmo OAuth OrdaX/Supabase", doc)
        self.assertIn("não** instala `cloudflared`", doc)
        self.assertIn("conecta **outbound** à Platform", doc)
        self.assertIn("Não recriá-los como fallback", doc)


if __name__ == "__main__":
    unittest.main()
