from __future__ import annotations
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ROOT / "control-plane/cloudflare/src/product_action_scope.ts"
MCP = ROOT / "control-plane/cloudflare/src/mcp_http.ts"
WORKER = ROOT / "control-plane/cloudflare/src/index.ts"

class ComputerProfileContractTests(unittest.TestCase):
    def test_profiles_are_in_canonical_scope_not_d1(self):
        scope = SCOPE.read_text(encoding="utf-8")
        self.assertIn("OWNER_DEVICE_COMPUTER_GRANT_PROFILES", scope)
        for value in ("interactive-computer-control", "computer-filesystem", "computer-clipboard", "computer-process-control"):
            self.assertIn(value, scope)
        block = scope.split("[INTERACTIVE_COMPUTER_CONTROL_MODE]: [", 1)[1].split("],", 1)[0]
        self.assertIn('"computer.hotkey"', block)
        self.assertNotIn('"computer.clipboard_read"', block)
        self.assertNotIn('"computer.terminate_process"', block)

    def test_no_legacy_mcp_grant_writer(self):
        mcp = MCP.read_text(encoding="utf-8")
        worker = WORKER.read_text(encoding="utf-8")
        self.assertIn('from "./product_action_scope.ts"', mcp)
        for action in ("createOwnerDeviceComputerGrant", "revokeOwnerDeviceComputerGrant", "listOwnerDeviceComputerGrants"):
            self.assertNotIn(action, mcp)
            self.assertNotIn(action, worker)
        self.assertIn('error: "legacy_product_grants_retired"', worker)

if __name__ == "__main__":
    unittest.main()
