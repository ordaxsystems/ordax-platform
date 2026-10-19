"""Platform-owned Worker contract tests, moved from Runtime 573984b.
No production source is copied across owners.
"""
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

    def test_worker_fences_expired_running_job_after_runtime_identity_changes(self) -> None:
        root = Path(__file__).resolve().parents[1]
        worker = (
            root / "control-plane" / "cloudflare" / "src" / "index.ts"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "status = 'queued' OR (status = 'leased' AND lease_expires_at < ?2)",
            worker,
        )
        self.assertNotIn(
            "status IN ('leased','running') AND lease_expires_at < ?2",
            worker,
        )
        self.assertIn(
            "status = 'running' OR (status = 'leased' AND lease_expires_at >= ?2)",
            worker,
        )
        self.assertIn("if (activeExecution) return;", worker)
        self.assertIn("fenceExpiredForeignRunningJobs", worker)
        self.assertIn("error_code = 'execution_context_lost'", worker)
        self.assertIn("lease_expires_at < ?1", worker)
        self.assertIn("agent_instance_id != ?3 OR boot_id != ?4", worker)
        self.assertIn(
            "await this.fenceExpiredForeignRunningJobs(deviceId, agentInstanceId, bootId);",
            worker,
        )
        self.assertIn("/v3/device/recover-report", worker)
        self.assertIn("execution_context_superseded", worker)
        self.assertIn("AND status IN ('leased','running') AND report_id IS NULL", worker)
        self.assertIn('error: "start_rejected"', worker)
        self.assertIn("X-Ordax-Target-Agent-Instance", worker)
        self.assertIn("X-Ordax-Target-Boot-Id", worker)
        self.assertIn("function stableJson", worker)
        self.assertIn(
            "canonicalStoredJson(terminal.result_json) === resultJson",
            worker,
        )


    def test_worker_supports_integrity_checked_multipart_artifacts(self) -> None:
        root = Path(__file__).resolve().parents[1]
        worker = (
            root / "control-plane" / "cloudflare" / "src" / "index.ts"
        ).read_text(encoding="utf-8")
        migration = (
            root
            / "control-plane"
            / "cloudflare"
            / "migrations"
            / "0004_artifact_multipart_uploads.sql"
        ).read_text(encoding="utf-8")

        self.assertIn("createMultipartUpload", worker)
        self.assertIn("resumeMultipartUpload", worker)
        self.assertIn('new crypto.DigestStream("SHA-256")', worker)
        self.assertIn('action === "mpu-create"', worker)
        self.assertIn('action === "mpu-uploadpart"', worker)
        self.assertIn('action === "mpu-complete"', worker)
        self.assertIn("multipart_part_checksum_mismatch", worker)
        self.assertIn("ordax_artifact_uploads", worker)
        self.assertIn("CREATE TABLE IF NOT EXISTS ordax_artifact_uploads", migration)
        self.assertIn("FOREIGN KEY(job_id)", migration)
        self.assertIn("FOREIGN KEY(device_id)", migration)


    def test_worker_product_grant_store_is_admin_only_and_read_only_scoped(self) -> None:
        root = Path(__file__).resolve().parents[1]
        worker = (
            root / "control-plane" / "cloudflare" / "src" / "index.ts"
        ).read_text(encoding="utf-8")
        migration = (
            root
            / "control-plane"
            / "cloudflare"
            / "migrations"
            / "0005_product_grants_audit.sql"
        ).read_text(encoding="utf-8")

        # The historical D1 migrations stay as evidence, but the old
        # runtime must neither advertise nor execute D1 Product grant CRUD.
        self.assertNotIn('"product_grant_store_v1"', worker)
        self.assertNotIn('"product_grant_resolution_v1"', worker)
        for obsolete in (
            "async function createProductGrant(",
            "async function createProductGrantFromLink(",
            "async function resolveProductGrantForContext(",
            "async function resolveProductGrantAdmin(",
            "async function listProductGrants(",
            "async function revokeProductGrant(",
            "async function recordProductAudit(",
        ):
            self.assertNotIn(obsolete, worker)
        product_block = worker.split(
            "const PRODUCT_READ_ONLY_ACTIONS = new Set([", 1
        )[1].split("]);", 1)[0]
        for action in (
            "projects.list",
            "workspace.repository_catalog",
            "project.inventory",
            "project.text_read",
            "project.search_text",
            "project.text_read_batch",
            "project.preview_status",
            "agent.project_health",
            "agent.project_briefing",
            "continuity.get",
            "git.status",
            "git.diff",
            "artifact.preview",
            "browser.status",
            "browser.screenshot",
            "computer.windows",
            "computer.screenshot",
            "computer.access_status",
            "computer.file_stat",
            "computer.text_read",
            "computer.search",
            "computer.processes",
        ):
            self.assertIn(f'"{action}"', product_block)
        typed_block = worker.split(
            "const PRODUCT_TYPED_ACTIONS_V2 = new Set([", 1
        )[1].split("]);", 1)[0]
        self.assertIn('"workspace.project_create"', typed_block)
        self.assertIn('"workspace.bind_project"', typed_block)
        self.assertIn('"browser.start"', typed_block)
        self.assertIn('"browser.click"', typed_block)
        self.assertIn('"computer.click"', typed_block)
        self.assertIn('"computer.text_write"', typed_block)
        self.assertIn('"computer.text_patch"', typed_block)
        self.assertIn('"computer.path_remove"', typed_block)
        self.assertIn('"computer.terminate_process"', typed_block)

        for mutation in (
            "project.text_write",
            "project.text_patch",
            "continuity.update",
            "git.sync",
            "artifact.read_chunk",
            "blender.live_run_script",
            "unity.run_method",
        ):
            self.assertNotIn(f'"{mutation}"', product_block)

        self.assertIn("CREATE TABLE IF NOT EXISTS ordax_product_grants", migration)
        self.assertIn("CREATE TABLE IF NOT EXISTS ordax_product_audit", migration)
        self.assertIn("revoked_at TEXT", migration)
        self.assertIn("payload_fields_json TEXT", migration)
        self.assertIn('url.pathname === "/v3/product-grants/resolve"', worker)
        self.assertIn('error: "legacy_product_grants_retired"', worker)
        self.assertNotIn("/v3/product-execute", worker)
        self.assertNotIn("/v3/product-actions", worker)
        self.assertNotIn("UPDATE ordax_product_grants SET revoked_at", worker)


    def test_product_project_scope_distinguishes_global_project_creation(self) -> None:
        root = Path(__file__).resolve().parents[1]
        worker = (
            root / "control-plane" / "cloudflare" / "src" / "index.ts"
        ).read_text(encoding="utf-8")
        project_block = worker.split(
            "const PRODUCT_PROJECT_ACTIONS = new Set([", 1
        )[1].split("]);", 1)[0]
        self.assertNotIn('"workspace.project_create"', project_block)
        self.assertNotIn('"workspace.bind_project"', project_block)
        self.assertIn('"continuity.update"', project_block)
        self.assertIn('"agent.project_briefing"', project_block)
        self.assertIn("...PROJECT_BROWSER_ACTIONS", project_block)
        scope_source = (root / "control-plane/cloudflare/src/product_action_scope.ts").read_text(encoding="utf-8")
        browser_block = scope_source.split("export const PROJECT_BROWSER_ACTIONS = new Set<string>([", 1)[1].split("]);", 1)[0]
        self.assertIn('"browser.screenshot"', browser_block)
        self.assertIn('"browser.start"', browser_block)
        self.assertIn('"terminal.exec"', project_block)
        self.assertIn('"git.command"', project_block)
        self.assertIn('"process.start"', project_block)
        for action in (
            "computer.screenshot",
            "computer.click",
            "computer.access_status",
            "computer.file_stat",
            "computer.text_read",
            "computer.text_write",
            "computer.path_remove",
            "computer.processes",
            "computer.terminate_process",
        ):
            self.assertNotIn(f'"{action}"', project_block)


    def test_retired_operator_job_prefixes_cannot_be_resurrected(self) -> None:
        root = Path(__file__).resolve().parents[1]
        worker = (
            root / "control-plane" / "cloudflare" / "src" / "index.ts"
        ).read_text(encoding="utf-8")
        # Global-operator D1 enqueue has been retired. No prefix-based
        # capability authorization may be reintroduced in this Worker.
        self.assertNotIn("const ACTION_PREFIXES = [", worker)
        self.assertNotIn("function actionAllowed(", worker)
        self.assertIn('error: "legacy_operator_job_enqueue_retired"', worker)


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
