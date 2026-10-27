"""Contract: advisory-only Owner target read uses the ONE SQL grant predicate."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / "control-plane/supabase/proposals/owner_central_session_targets_v1.sql"
OWNER = ROOT / "control-plane/cloudflare/src/product_owner_grant_admin.ts"
ENTRY = ROOT / "control-plane/cloudflare/src/product_mcp_entry.ts"

class OwnerCentralTargetsContract(unittest.TestCase):
    def test_no_second_grant_authority(self):
        sql = SQL.read_text(encoding="utf-8").lower()
        self.assertIn("private.ordax_central_device_grant_eligible_v1(", sql)
        self.assertIn("owner_central_client_not_consented", sql)
        self.assertIn("auth.oauth_consents", sql)
        for forbidden in ("insert into public.ordax_remote_capability_grants",
                          "update public.ordax_remote_capability_grants",
                          "delete from public.ordax_remote_capability_grants",
                          "ordax_bind_central_conversation_v1(",
                          "ordax_confirm_central_device_session_v1(",
                          "create table"):
            self.assertNotIn(forbidden, sql)
        self.assertIn("to ordax_edge_executor",sql)
        self.assertIn("revoke all on function public.ordax_owner_central_session_targets_v1",sql)
        self.assertIn("owner_choice_performed',false",sql)
        self.assertIn("dispatch_authorized',false",sql)

    def test_owner_pkce_pin_is_only_on_production_mcp_worker(self):
        import re
        import tomllib
        mcp_config = tomllib.loads((ROOT /
            "control-plane/cloudflare/wrangler.mcp.toml").read_text("utf-8"))
        other_config = tomllib.loads((ROOT /
            "control-plane/cloudflare/wrangler.toml").read_text("utf-8"))
        self.assertEqual(mcp_config["name"], "ordax-mcp")
        self.assertEqual(mcp_config["main"], "src/product_mcp_entry.ts")
        pinned = mcp_config["vars"].get("PRODUCT_OWNER_OAUTH_CLIENT_ID")
        self.assertIsInstance(pinned, str)
        self.assertRegex(pinned, r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
        # Do not put Owner-session authority on the unshipped legacy Worker.
        self.assertNotIn("PRODUCT_OWNER_OAUTH_CLIENT_ID", other_config["vars"])
        source = OWNER.read_text(encoding="utf-8")
        self.assertIn("env.PRODUCT_OWNER_OAUTH_CLIENT_ID", source)
        self.assertIn("identity.clientId.toLowerCase() !== pinned", source)
        self.assertIn("owner_primary_session_required", source)
        self.assertIn('CENTRAL_OWNER_SELECTION_ENABLED !== "enabled"', source)

    def test_disabled_owner_only_exact_client_route(self):
        source = OWNER.read_text(encoding="utf-8")
        entry = ENTRY.read_text(encoding="utf-8")
        self.assertIn('CENTRAL_OWNER_TARGET_PREFLIGHT_ENABLED !== "enabled"',source)
        self.assertIn('url.searchParams.getAll("client_id").length !== 1',source)
        self.assertIn('inspectOwnerCentralSessionTargets',source)
        self.assertIn('const ownerId = await owner(request, env)',source)
        self.assertIn('pathname === PRODUCT_OWNER_CENTRAL_SESSION_TARGETS_PATH',entry)
        self.assertNotIn('replaceOwnerMcpGrantGroup(env, {\n        ownerUserId: ownerId, deviceId: input',source)

if __name__ == "__main__":
    unittest.main()
