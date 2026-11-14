from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOUNDATION = ROOT / "control-plane" / "cloudflare" / "production-foundation.json"


class ForgeMcpGatewayFoundationTests(unittest.TestCase):
    def setUp(self):
        self.foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        self.forge = self.foundation["forge_mcp_gateway"]
        self.ordax = self.foundation["mcp_release"]

    def test_forge_uses_same_worker_and_supabase_oauth_without_local_tunnel(self):
        self.assertEqual(self.forge["worker_name"], "ordax-mcp")
        self.assertEqual(self.forge["worker_name"], self.ordax["worker_name"])
        self.assertEqual(self.forge["hostname"], "forge-mcp.ordax.com.br")
        self.assertEqual(self.forge["path"], "/mcp")
        self.assertEqual(self.forge["transport"], "streamable-http")
        self.assertEqual(self.forge["authority"], "postgresql")
        self.assertEqual(self.forge["oauth_issuer"], self.ordax["oauth_issuer"])
        self.assertEqual(self.forge["oauth_audience"], "authenticated")
        self.assertTrue(self.forge["custom_domain_required"])
        self.assertFalse(self.forge["local_tunnel_required"])
        self.assertFalse(self.forge["cloudflare_access_required"])
        self.assertFalse(self.forge["model_relay"])

    def test_forge_keeps_app_catalog_as_ssot_and_platform_only_adds_meta_tools(self):
        self.assertEqual(
            self.forge["catalog_authority"],
            "forge_instance_published_catalog_sha256",
        )
        self.assertEqual(
            self.forge["meta_tools"],
            ["forge_connection_status", "forge_action_status"],
        )
        self.assertEqual(
            self.forge["binding_authority"],
            "owner_user_plus_oauth_client_to_forge_instance",
        )
        self.assertEqual(
            self.forge["instance_connection"],
            "outbound_https_long_poll",
        )

    def test_legacy_per_machine_forge_transport_is_explicitly_forbidden(self):
        legacy = self.forge["legacy"]
        for key in (
            "allow_per_machine_cloudflare_tunnel",
            "allow_cloudflare_access_login",
            "allow_cfargotunnel_cname",
            "allow_second_worker",
        ):
            self.assertIs(legacy[key], False)
        self.assertEqual(
            legacy["retired_tunnel_id"],
            "f785d1da-cca0-4f39-abd8-b51458c1ea62",
        )
        self.assertEqual(
            legacy["retired_access_app_id"],
            "0e56773b-e7cc-41ed-b08f-ad230fc74e2e",
        )

    def test_live_evidence_pins_the_verified_worker_cutover(self):
        evidence = self.forge["live_evidence"]
        self.assertEqual(evidence["platform_source_commit"], "f2391a56c016b47f7b8d25041f923d352e7ee9e3")
        self.assertEqual(evidence["worker_deployment_id"], "5c846fc9-3147-4204-bdb3-4a06498321ea")
        self.assertEqual(evidence["worker_version_id"], "8a5cb3c9-4aa1-4561-b04c-a73a92d0354f")
        self.assertEqual(evidence["health_status"], 200)
        self.assertEqual(evidence["oauth_metadata_status"], 200)
        self.assertEqual(evidence["unauthenticated_mcp_status"], 401)


if __name__ == "__main__":
    unittest.main()
