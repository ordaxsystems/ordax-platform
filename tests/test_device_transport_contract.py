"""Canonical Platform Worker transport and legacy-retirement contracts."""

from pathlib import Path
import json
import tomllib
import unittest
from tests.test_cloudflare_deploy_gate import gate


class DeviceTransportContractTests(unittest.TestCase):
    def test_product_heartbeat_distinguishes_native_os_from_windows_without_grants(self):
        """Authenticated heartbeat provenance is metadata, not action authority."""
        root = Path(__file__).resolve().parents[1]
        source = (
            root / "control-plane/cloudflare/src/product_device_transport.ts"
        ).read_text(encoding="utf-8")
        block = source.split("async function heartbeat(", 1)[1].split(
            "async function claim(", 1
        )[0]
        self.assertIn(
            'const runtimeKind = body.runtime_kind === undefined ? "desktop-agent" : body.runtime_kind',
            block,
        )
        self.assertIn("RUNTIME_KINDS.has(runtimeKind as RuntimeKind)", block)
        self.assertIn(
            'Object.prototype.hasOwnProperty.call(body, "capabilities_digest")',
            block,
        )
        self.assertIn("runtimeKind: runtimeKind as RuntimeKind", block)
        self.assertIn("const capabilityDigest = await canonicalDeviceHeartbeatDigest(body)", block)
        self.assertIn("recordProductPresence(env,", block)
        self.assertNotIn("createProductGrant", block)
        self.assertNotIn("dispatch", block)
        self.assertIn('new Set<RuntimeKind>(["ordax-os", "desktop-agent", "mobile-client", "other"])', source)


    def test_legacy_d1_and_websocket_implementation_is_deleted(self):
        root = Path(__file__).resolve().parents[1]
        worker = (root / "control-plane/cloudflare/src/index.ts").read_text(encoding="utf-8")
        with (root / "control-plane/cloudflare/wrangler.toml").open("rb") as handle:
            wrangler = tomllib.load(handle)
        self.assertNotIn("d1_databases", wrangler)
        self.assertNotIn("env.DB", worker)
        self.assertNotIn("this.env.DB", worker)
        self.assertNotIn("createMultipartUpload", worker)
        self.assertNotIn("recoverTerminalReport", worker)
        self.assertNotIn("fenceExpiredForeignRunningJobs", worker)
        self.assertNotIn("ordax_jobs", worker)
        self.assertNotIn("ordax_artifact_uploads", worker)
        self.assertIn("legacy_endpoint_retired", worker)

    def test_only_canonical_postgres_device_authority_is_routed(self):
        root = Path(__file__).resolve().parents[1]
        worker = (root / "control-plane/cloudflare/src/index.ts").read_text(encoding="utf-8")
        self.assertIn("handleProductDeviceTransport(request,env)", worker)
        self.assertIn("handleProductDevicePresence(request, env)", worker)
        self.assertIn("enrollProductDevice(env,", worker)
        self.assertIn("identifyProductDevice(env,", worker)
        self.assertNotIn("env.DEVICE_SESSIONS.get(", worker)
        self.assertIn('error:"legacy_device_session_retired"', worker)

    def test_retired_operator_and_artifact_routes_fail_closed(self):
        root = Path(__file__).resolve().parents[1]
        worker = (root / "control-plane/cloudflare/src/index.ts").read_text(encoding="utf-8")
        self.assertIn('path === "/v3/device/ws"', worker)
        self.assertIn('path === "/v3/device/recover-report"', worker)
        self.assertIn('path.startsWith("/v3/artifacts/")', worker)
        self.assertIn('path === "/v3/jobs"', worker)
        self.assertNotIn("const ACTION_PREFIXES", worker)
        self.assertNotIn("function actionAllowed", worker)
        self.assertIn('error:"legacy_endpoint_retired"', worker)

    def test_artifact_retention_remains_a_canonical_deployment_blocker(self) -> None:
        root = Path(__file__).resolve().parents[1]
        cloudflare = root / "control-plane/cloudflare"
        foundation = json.loads((cloudflare / "production-foundation.json").read_text(encoding="utf-8"))
        with (cloudflare / "wrangler.toml").open("rb") as stream:
            wrangler = tomllib.load(stream)
        worker = (cloudflare / "src/index.ts").read_text(encoding="utf-8")
        # The retired D1 prototype's retention implementation is not present.
        # Check the current canonical gate instead of claiming a scheduled
        # deletion service or restoring a second persistence authority.
        self.assertIn("artifact_retention_authority_not_ready", foundation["readiness_blockers"])
        self.assertIs(foundation["deployment_ready"], False)
        self.assertIs(foundation["policy"]["allow_d1"], False)
        self.assertIs(foundation["policy"]["allow_dual_write"], False)
        self.assertFalse(gate.validate(foundation, wrangler, worker, foundation["account_id"]))
        foundation["deployment_ready"] = True
        with self.assertRaises(gate.DeployGateError):
            gate.validate(foundation, wrangler, worker, foundation["account_id"])


if __name__ == "__main__":
    unittest.main()
