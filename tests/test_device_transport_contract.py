"""Native/desktop device transport remains PostgreSQL-owned and fail-closed."""
from pathlib import Path
import json
import tomllib
import unittest

from scripts.cloudflare.check_mcp_release import (
    d1_source_names, worker_source_texts, validate, McpReleaseError,
)

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "control-plane/cloudflare/src"
CONFIG = ROOT / "control-plane/cloudflare/wrangler.mcp.toml"
FOUNDATION = ROOT / "control-plane/cloudflare/production-foundation.json"


class DeviceTransportContractTests(unittest.TestCase):
    def test_product_heartbeat_distinguishes_native_os_from_windows_without_grants(self):
        source = (SRC / "product_device_transport.ts").read_text(encoding="utf-8")
        block = source.split("async function heartbeat(", 1)[1].split(
            "async function claim(", 1
        )[0]
        for required in (
            'const runtimeKind = body.runtime_kind === undefined ? "desktop-agent" : body.runtime_kind',
            "RUNTIME_KINDS.has(runtimeKind as RuntimeKind)",
            'Object.prototype.hasOwnProperty.call(body, "capabilities_digest")',
            "runtimeKind: runtimeKind as RuntimeKind",
            "const capabilityDigest = canonicalDeviceHeartbeatDigest(body)",
            "recordProductHeartbeat(env,",
        ):
            self.assertIn(required, block)
        self.assertNotIn("createProductGrant", block)
        self.assertNotIn("dispatch", block)
        self.assertIn(
            'new Set<RuntimeKind>(["ordax-os", "desktop-agent", "mobile-client", "other"])',
            source,
        )

    def test_retired_d1_websocket_and_worker_entry_are_physically_absent(self):
        self.assertFalse((SRC / "index.ts").exists())
        self.assertFalse((ROOT / "control-plane/cloudflare/wrangler.toml").exists())
        self.assertEqual(d1_source_names(worker_source_texts(SRC)), set())
        with CONFIG.open("rb") as stream:
            config = tomllib.load(stream)
        self.assertEqual(config["main"], "src/product_mcp_entry.ts")
        self.assertNotIn("d1_databases", config)
        self.assertNotIn("r2_buckets", config)
        entry = (SRC / "product_mcp_entry.ts").read_text(encoding="utf-8")
        for forbidden in ("createMultipartUpload", "recoverTerminalReport",
                          "fenceExpiredForeignRunningJobs", "ordax_artifact_uploads"):
            self.assertNotIn(forbidden, entry)

    def test_only_canonical_postgres_device_authority_is_routed(self):
        entry = (SRC / "product_mcp_entry.ts").read_text(encoding="utf-8")
        setup = (SRC / "product_device_setup.ts").read_text(encoding="utf-8")
        transport = (SRC / "product_device_transport.ts").read_text(encoding="utf-8")
        self.assertIn("handleProductDeviceTransport(request, env)", entry)
        self.assertIn("handleProductDevicePresence(request, env)", entry)
        self.assertIn("handleProductDeviceSetup(request, env)", entry)
        self.assertIn("enrollProductDevice(env,", setup)
        self.assertIn("identifyProductDevice(env,", setup)
        self.assertIn("authenticateProductDevice(env,", transport)
        self.assertNotIn("env.DEVICE_SESSIONS.get(", entry)
        self.assertNotIn("class DeviceSession", entry)
        self.assertNotIn("env.DB", entry)

    def test_retired_operator_and_artifact_routes_are_not_mounted(self):
        entry = (SRC / "product_mcp_entry.ts").read_text(encoding="utf-8")
        for forbidden in ("/v3/device/ws", "/v3/device/recover-report",
                          "/v3/artifacts/", "/v3/jobs", "const ACTION_PREFIXES",
                          "function actionAllowed", "legacy_endpoint_retired"):
            self.assertNotIn(forbidden, entry)
        self.assertIn('error: "not_found"', entry)

    def test_artifact_authority_is_not_an_implicit_mcp_grant(self):
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        with CONFIG.open("rb") as stream:
            config = tomllib.load(stream)
        self.assertFalse(foundation["policy"]["allow_d1"])
        self.assertFalse(foundation["policy"]["allow_dual_write"])
        self.assertNotIn("r2_buckets", config)
        self.assertNotIn("deployment_ready", foundation)
        self.assertNotIn("readiness_blockers", foundation)
        self.assertFalse(validate(foundation, config))
        f = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        f["policy"]["allow_d1"] = True
        with self.assertRaisesRegex(McpReleaseError, "mcp_foundation_forbids_d1"):
            validate(f, config)


if __name__ == "__main__":
    unittest.main()
