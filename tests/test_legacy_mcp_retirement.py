"""Legacy D1 Worker must never expose Product MCP or writable action routes.

This is a source retirement, NOT proof that the old external Cloudflare
account was redeployed or disabled. New MCP uses separate PostgreSQL entry.
"""
from pathlib import Path
import json
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
LEGACY=(ROOT/"control-plane/cloudflare/src/index.ts").read_text("utf-8")
NEW=(ROOT/"control-plane/cloudflare/src/product_mcp_entry.ts").read_text("utf-8")
D1_MAP=json.loads((ROOT/"control-plane/cloudflare/d1-cutover-authority-map.json").read_text("utf-8"))

class RetiredLegacyMcp(unittest.TestCase):
    def test_old_source_no_longer_has_executable_mcp_dispatch(self):
        self.assertNotIn('import { handleOrdaxMcp }',LEGACY)
        self.assertNotIn('handleOrdaxMcp(request',LEGACY)
        self.assertIn('if (url.pathname === "/mcp")',LEGACY)
        self.assertIn('error: "legacy_mcp_retired"',LEGACY)
        self.assertIn('error: "legacy_oauth_route_retired"',LEGACY)

    def test_old_source_no_longer_has_write_action_handler(self):
        self.assertNotIn('async function createProductAction(',LEGACY)
        self.assertNotIn('return createProductAction(',LEGACY)
        self.assertIn('error: "legacy_product_action_retired"',LEGACY)
        self.assertEqual(D1_MAP['legacy_source_callsite_ceilings']['index.ts'],37)

    def test_new_source_is_disjoint_and_denies_mutation(self):
        self.assertNotIn('src/index.ts',NEW)
        self.assertNotIn('D1Database',NEW)
        self.assertIn('createCanonicalProductMcpReadHandlers',NEW)
        self.assertIn('trusted_operation_required',NEW)
        self.assertIn('supports_remote_actions: false',NEW)

    def test_legacy_routes_explicitly_fail_in_dispatch(self):
        # Ensure branches return 410 instead of a hidden fallback.
        cases=[
            ('if (url.pathname === "/mcp")', 'legacy_mcp_retired'),
            ('if (request.method === "POST" && url.pathname === "/v3/product/actions")',
             'legacy_product_action_retired'),
            ('if (request.method === "GET" && url.pathname === "/oauth/consent")',
             'legacy_oauth_route_retired'),
            ('if (request.method === "GET" && url.pathname === "/.well-known/oauth-protected-resource")',
             'legacy_mcp_retired'),
        ]
        for start,error in cases:
            self.assertIn(start,LEGACY)
            body=LEGACY.split(start,1)[1].split("\n    }",1)[0]
            self.assertIn(f'error: "{error}"',body)
            self.assertIn("410",body)

if __name__=="__main__":
    unittest.main()
