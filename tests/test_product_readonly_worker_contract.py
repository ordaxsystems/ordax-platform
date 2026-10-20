"""Current Product Worker boundary contracts.

The old D1/WebSocket product implementation was retired. These checks protect
the canonical PostgreSQL/OAuth and Runtime-attested paths, not the retired
standalone worker routes.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "control-plane/cloudflare/src/index.ts"
READS = ROOT / "control-plane/cloudflare/src/product_mcp_reads.ts"
ENTRY = ROOT / "control-plane/cloudflare/src/product_mcp_entry.ts"
TRANSPORT = ROOT / "control-plane/cloudflare/src/product_device_transport.ts"
AUTHORITY = ROOT / "control-plane/supabase/migrations/20261007150000_product_remote_authority_v1.sql"


class ProductReadonlyWorkerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.worker = WORKER.read_text(encoding="utf-8")
        cls.reads = READS.read_text(encoding="utf-8")
        cls.entry = ENTRY.read_text(encoding="utf-8")
        cls.transport = TRANSPORT.read_text(encoding="utf-8")
        cls.authority = AUTHORITY.read_text(encoding="utf-8").lower()

    def test_legacy_mutation_route_is_retired_instead_of_parallel_authority(self):
        self.assertIn('path === "/v3/product/actions" && request.method === "POST"', self.worker)
        self.assertIn('error: "legacy_product_action_retired"', self.worker)
        self.assertIn('product_typed_actions_v2', self.worker)
        self.assertNotIn("'ordax.product.invoke'", self.worker)
        self.assertNotIn("env.DB", self.worker)

    def test_canonical_targets_use_signed_owner_and_exact_oauth_client(self):
        for required in (
            "authenticateProductMcpClientRequest(request, env)",
            "listCanonicalProductTargets", "getProductAction",
            "ownerUserId: identity.ownerUserId",
            "clientKind: identity.clientKind",
            "clientId: identity.clientId",
            "ensureProductMcpTargetDiscovery",
        ):
            self.assertIn(required, self.reads)
        self.assertNotIn("env.DB", self.reads)

    def test_action_status_requires_signed_client_and_rejects_foreign_result(self):
        self.assertIn("async getAction(request, requestId)", self.reads)
        self.assertIn("authenticateProductMcpClientRequest(request, env)", self.reads)
        self.assertIn("if (!isCanonicalUuid(requestId))", self.reads)
        self.assertIn('error: "product_action_not_found"', self.reads)
        self.assertIn("validAction(result, requestId)", self.reads)
        self.assertIn("clientId: identity.clientId", self.reads)

    def test_device_transport_authenticates_before_canonical_postgres_work(self):
        self.assertIn("authenticateDeviceRequest(request, env)", self.transport)
        self.assertIn("authenticateProductDevice(env,", self.transport)
        self.assertIn('x-ordax-device-token', self.transport)
        self.assertIn("claimProductAction", self.transport)
        self.assertIn("renewProductActionLease", self.transport)
        self.assertIn("reportProductAction", self.transport)
        self.assertNotIn("env.DB", self.transport)

    def test_mcp_action_requires_server_resolved_attested_device(self):
        self.assertIn("resolveOrBootstrapAttestedSession", self.entry)
        self.assertIn("createAttestedDeviceActionHandler(env, trusted)", self.entry)
        self.assertIn("createAttestedProjectActionHandler(env, trusted)", self.entry)
        self.assertIn("ownerUserId: resolved.ownerUserId", self.entry)
        self.assertIn("clientId: resolved.clientId", self.entry)
        self.assertIn("deviceId: resolved.deviceId", self.entry)
        self.assertNotIn("ORDAX_OPERATOR_TOKEN", self.entry)

    def test_product_audit_is_private_not_an_anonymous_worker_route(self):
        self.assertIn('path === "/v3/product/audit"', self.worker)
        self.assertIn('error: "legacy_endpoint_retired"', self.worker)
        self.assertIn("revoke all on table private.ordax_product_action_audit", self.authority)


if __name__ == "__main__":
    unittest.main()
