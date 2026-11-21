"""No global-operator job executor survives in the MCP production entrypoint."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "control-plane/cloudflare/src/product_mcp_entry.ts"
TRANSPORT = ROOT / "control-plane/cloudflare/src/product_device_transport.ts"


class OrphanedLegacyHelpersTests(unittest.TestCase):
    def test_no_operator_executor_or_duplicated_job_queue(self):
        entry = ENTRY.read_text(encoding="utf-8")
        for legacy in ("ACTION_PREFIXES", "actionAllowed(", "ORDAX_OPERATOR_TOKEN",
                       "async function enqueueJob(", "async function recoverTerminalReport(",
                       "operatorAuthorized("):
            self.assertNotIn(legacy, entry)

    def test_native_transport_reuses_postgres_leases_and_reports(self):
        entry = ENTRY.read_text(encoding="utf-8")
        transport = TRANSPORT.read_text(encoding="utf-8")
        self.assertIn("handleProductDeviceTransport(request, env, context)", entry)
        self.assertIn("claimProductAction", transport)
        self.assertIn("renewProductActionLease", transport)
        self.assertIn("reportProductAction", transport)
        self.assertIn("authenticateProductDevice", transport)
        self.assertNotIn("env.DB", transport)


if __name__ == "__main__":
    unittest.main()
