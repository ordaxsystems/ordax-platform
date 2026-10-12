import json
import re
import tomllib
import unittest
from pathlib import Path

from scripts.cloudflare.check_deploy_readiness import (
    D1_TABLE_RE,
    d1_access_count,
    d1_source_names,
    worker_source_texts,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "cloudflare-v3-deploy.yml"
BOOTSTRAP = ROOT / "scripts" / "cloudflare" / "deploy-v3.sh"
ROUTINE_DEPLOY = ROOT / "scripts" / "cloudflare" / "deploy-production-v3.sh"
FOUNDATION = ROOT / "control-plane" / "cloudflare" / "production-foundation.json"
WRANGLER = ROOT / "control-plane" / "cloudflare" / "wrangler.toml"
WORKER_PACKAGE = ROOT / "control-plane" / "cloudflare" / "package.json"
POSTGRES_ADAPTER = ROOT / "control-plane" / "cloudflare" / "src" / "product_postgres_store.ts"
WORKER_SOURCE = ROOT / "control-plane" / "cloudflare" / "src" / "index.ts"
CLOUDFLARE_SRC = ROOT / "control-plane" / "cloudflare" / "src"
CLOUDFLARE_MIGRATIONS = ROOT / "control-plane" / "cloudflare" / "migrations"
D1_CUTOVER_MAP = ROOT / "control-plane" / "cloudflare" / "d1-cutover-authority-map.json"
def d1_worker_sources() -> dict[str, str]:
    return worker_source_texts(CLOUDFLARE_SRC)

OLD_ACCOUNT_ID = "ac1ca1b50d09c7a4cb81274d2aa1e78f"
DEDICATED_ACCOUNT_ID = "42586bf13b61436219d21def299833e4"

LEGACY_D1_MIGRATION_ALLOWLIST = {
    "0001_initial.sql",
    "0002_device_enrollment.sql",
    "0003_terminal_report_replay.sql",
    "0004_artifact_multipart_uploads.sql",
    "0005_product_grants_audit.sql",
    "0006_product_action_requests.sql",
    "0007_product_device_pairing.sql",
    "0008_product_device_owner.sql",
}
LEGACY_OPERATOR_HANDLER_ALLOWLIST = {
    "provisionDevice",
    "enqueueJob",
    "getJob",
}


class CloudflareAccountResolutionContractTests(unittest.TestCase):
    def test_production_foundation_is_canonical_and_forbids_legacy_persistence(self):
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        self.assertEqual(foundation["account_id"], DEDICATED_ACCOUNT_ID)
        self.assertEqual(foundation["authorities"]["persistent"], "postgresql")
        self.assertEqual(foundation["authorities"]["artifacts"], "r2")
        self.assertEqual(
            foundation["authorities"]["realtime_session_coordination"],
            "durable_objects",
        )
        self.assertFalse(foundation["policy"]["allow_d1"])
        self.assertFalse(foundation["policy"]["allow_dual_write"])
        self.assertTrue(foundation["security"]["require_two_factor"])
        security = foundation["live_evidence"]["security"]
        self.assertTrue(security["member_two_factor_enabled"])
        self.assertTrue(security["account_enforce_twofactor"])
        self.assertEqual(security["account_name"], "ordax-platform")
        self.assertNotIn("cloudflare_2fa_not_enabled", foundation["readiness_blockers"])
        self.assertEqual(foundation["postgres"]["runtime_role"], "ordax_edge_runtime")
        self.assertEqual(foundation["postgres"]["executor_role"], "ordax_edge_executor")
        self.assertEqual(foundation["postgres"]["runtime_transport"], "hyperdrive")
        self.assertEqual(foundation["postgres"]["hyperdrive_binding"], "POSTGRES")
        with WRANGLER.open("rb") as handle:
            wrangler = tomllib.load(handle)
        hyperdrive_bindings = wrangler.get("hyperdrive") or []
        self.assertEqual(len(hyperdrive_bindings), 1)
        self.assertEqual(hyperdrive_bindings[0]["binding"], "POSTGRES")
        self.assertEqual(
            hyperdrive_bindings[0]["id"],
            foundation["live_evidence"]["hyperdrive"]["id"],
        )
        self.assertEqual(foundation["postgres"]["query_cache"], "disabled")
        self.assertIn(
            "SUPABASE_SERVER_KEY",
            foundation["policy"]["forbidden_runtime_secrets"],
        )
        self.assertIn(
            "SUPABASE_SERVICE_ROLE_KEY",
            foundation["policy"]["forbidden_runtime_secrets"],
        )
        self.assertEqual(foundation["workers_dev_subdomain"], "ordaxsystems")
        self.assertNotIn(
            "workers_dev_subdomain_not_initialized",
            foundation["readiness_blockers"],
        )
        self.assertNotIn(
            "product_auth_metadata_not_repointed",
            foundation["readiness_blockers"],
        )
        deployment = foundation["deployment"]
        self.assertEqual(deployment["bootstrap"]["scope"], "workers_product")
        self.assertEqual(deployment["bootstrap"]["role"], "admin")
        self.assertTrue(deployment["bootstrap"]["temporary"])
        self.assertEqual(deployment["routine"]["scope"], "individual_worker")
        self.assertEqual(deployment["routine"]["role"], "editor")
        self.assertEqual(deployment["routine"]["worker_name"], foundation["worker_name"])
        self.assertTrue(deployment["routine"]["requires_existing_worker"])
        self.assertFalse(deployment["zone_workers_routes_write_required"])
        self.assertFalse(deployment["bound_resource_direct_access_required"])
        blockers = set(foundation["readiness_blockers"])
        self.assertEqual(foundation["r2_bucket"], "ordax-device-artifacts")
        self.assertNotIn("cloudflare_r2_not_enabled", blockers)
        self.assertNotIn("postgres_runtime_login_not_provisioned", blockers)
        self.assertNotIn("hyperdrive_not_provisioned", blockers)
        hyperdrive = foundation["live_evidence"]["hyperdrive"]
        self.assertEqual(hyperdrive["name"], foundation["hyperdrive_name"])
        self.assertEqual(hyperdrive["runtime_role"], foundation["postgres"]["runtime_role"])
        self.assertEqual(hyperdrive["origin_connection_limit"], 10)
        self.assertTrue(hyperdrive["query_cache_disabled"])
        self.assertEqual(hyperdrive["sslmode"], "require")
        runtime = foundation["live_evidence"]["postgres_runtime"]
        self.assertTrue(runtime["login"])
        self.assertTrue(runtime["has_password"])
        self.assertTrue(runtime["inherits_executor"])
        self.assertEqual(runtime["direct_table_grants"], 0)
        self.assertEqual(runtime["direct_routine_grants"], 0)
        self.assertEqual(runtime["security_advisor_findings"], 0)
        self.assertNotIn("r2_bucket_not_provisioned", blockers)
        r2 = foundation["live_evidence"]["r2"]
        self.assertTrue(r2["enabled"])
        self.assertEqual(r2["bucket_name"], foundation["r2_bucket"])
        self.assertEqual(r2["storage_class"], "Standard")
        self.assertEqual(r2["jurisdiction"], "default")
        self.assertIn(r2["location"].lower(), {"apac", "eeur", "enam", "weur", "wnam", "oc"})
        self.assertIn("worker_not_provisioned", blockers)
        self.assertIn(
            "cloudflare_ci_worker_editor_token_not_provisioned",
            blockers,
        )
        self.assertNotIn("cloudflare_ci_token_not_rotated", blockers)

    def test_legacy_d1_surface_is_frozen_while_cutover_is_incomplete(self):
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        blockers = set(foundation["readiness_blockers"])
        cutover = json.loads(D1_CUTOVER_MAP.read_text(encoding="utf-8"))
        ceilings = cutover["legacy_source_callsite_ceilings"]
        sources = d1_worker_sources()
        d1_sources = d1_source_names(sources)
        mapped_tables = {
            table
            for domain in cutover["domains"]
            for table in domain["legacy_tables"]
        }
        referenced_tables = {
            match.lower()
            for name in d1_sources
            for match in D1_TABLE_RE.findall(sources[name])
        }
        migrations = {path.name for path in CLOUDFLARE_MIGRATIONS.glob("*.sql")}

        self.assertEqual(CLOUDFLARE_SRC, ROOT / cutover["source_root"])
        self.assertTrue(
            d1_sources.issubset(set(ceilings)),
            f"untracked D1 source files are forbidden: {sorted(d1_sources - set(ceilings))}",
        )
        self.assertTrue(
            migrations.issubset(LEGACY_D1_MIGRATION_ALLOWLIST),
            f"new D1 migrations are forbidden: {sorted(migrations - LEGACY_D1_MIGRATION_ALLOWLIST)}",
        )
        self.assertTrue(
            referenced_tables.issubset(mapped_tables),
            f"new D1 tables are forbidden: {sorted(referenced_tables - mapped_tables)}",
        )
        if d1_sources or migrations:
            self.assertFalse(foundation["policy"]["allow_d1"])
            self.assertIn("worker_d1_cutover_incomplete", blockers)

    def test_main_worker_json_ingress_uses_shared_byte_bounded_reader(self):
        source = WORKER_SOURCE.read_text(encoding="utf-8")
        bounded = (CLOUDFLARE_SRC / "request_json.ts").read_text(encoding="utf-8")
        self.assertIn('import { readBoundedJsonObject } from "./request_json";', source)
        self.assertIn("return readBoundedJsonObject(request, maxBytes);", source)
        self.assertNotIn("await request.text()", source)
        self.assertIn("bytes += value.byteLength", bounded)
        self.assertIn("if (bytes > maxBytes) return null", bounded)
        self.assertIn("await reader.cancel()", bounded)

    def test_d1_cutover_map_classifies_every_legacy_table_once(self):
        cutover = json.loads(D1_CUTOVER_MAP.read_text(encoding="utf-8"))
        sources = d1_worker_sources()
        referenced_tables = {
            match.lower()
            for source in sources.values()
            if "D1Database" in source or d1_access_count(source) > 0
            for match in D1_TABLE_RE.findall(source)
        }
        mapped_tables = [
            table
            for domain in cutover["domains"]
            for table in domain["legacy_tables"]
        ]
        self.assertEqual(len(mapped_tables), len(set(mapped_tables)))
        self.assertEqual(set(mapped_tables), referenced_tables)
        # Tables retired from ALL Worker source remain traceable as historical
        # migration evidence, but MUST NOT count as active authority.
        retired = [
            name for domain in cutover["domains"]
            for name in domain.get("retired_tables", [])
        ]
        self.assertEqual(set(retired), {"ordax_product_audit", "ordax_product_device_pairings", "ordax_product_grants", "ordax_product_action_requests", "ordax_product_device_links"})
        self.assertEqual(len(retired), len(set(retired)))
        self.assertFalse(set(retired) & referenced_tables)
        self.assertFalse(set(retired) & set(mapped_tables))
        self.assertFalse(cutover["policy"]["allow_callsite_growth"])
        self.assertFalse(cutover["policy"]["allow_schema_copy_1_to_1"])
        self.assertFalse(cutover["policy"]["allow_dual_write"])
        self.assertFalse(cutover["policy"]["durable_objects_as_business_persistence"])

    def test_product_cutover_stays_blocked_until_client_identity_is_enforced(self):
        cutover = json.loads(D1_CUTOVER_MAP.read_text(encoding="utf-8"))
        domain = next(
            item for item in cutover["domains"]
            if item["id"] == "product_remote_authority"
        )
        self.assertEqual(domain["authority_state"], "partial")
        self.assertEqual(
            set(domain["cutover_blockers"]),
            {
                "validated_client_identity_not_propagated_to_product_rpc",
                "product_mcp_consumers_and_route_contracts_not_cut_over",
            },
        )

        # #79 installed an exact client-scoped RPC, but the route still lacks
        # a verified client identity and remains on the legacy D1 handler.
        migration = (
            ROOT / "control-plane/supabase/migrations/"
            "20261007203000_product_client_grant_isolation_v1.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("and g.client_id = p_client_id", migration)
        self.assertIn("and v_existing.client_id = p_client_id", migration)
        self.assertIn("drop function public.ordax_enqueue_product_action_v1(", migration)
        adapter = (
            ROOT / "control-plane/cloudflare/src/product_postgres_store.ts"
        ).read_text(encoding="utf-8")
        self.assertIn("if (!client || client.p_client_id === null)", adapter)
        worker = WORKER_SOURCE.read_text(encoding="utf-8")
        # The legacy D1 product action writer has been DELETED rather than
        # masked by a model-facing route or silently moved to another file.
        self.assertNotIn("async function createProductAction(", worker)
        self.assertNotIn("handleOrdaxMcp(request", worker)
        self.assertIn('error: "legacy_mcp_retired"', worker)
        self.assertIn('error: "legacy_product_action_retired"', worker)

    def test_d1_callsite_count_can_only_shrink(self):
        cutover = json.loads(D1_CUTOVER_MAP.read_text(encoding="utf-8"))
        ceilings = cutover["legacy_source_callsite_ceilings"]
        sources = d1_worker_sources()
        self.assertEqual(cutover["version"], 2)
        self.assertTrue(ceilings)
        self.assertEqual(
            len(ceilings), len(set(ceilings)),
            "duplicate source names are invalid",
        )
        current_total = 0
        for name, ceiling in ceilings.items():
            self.assertRegex(name, r"^[a-z][a-z0-9_]*\.ts$")
            self.assertIs(type(ceiling), int)
            self.assertGreaterEqual(ceiling, 0)
            self.assertIn(name, sources, f"tracked source removed without SSOT cleanup: {name}")
            current = d1_access_count(sources[name])
            self.assertLessEqual(
                current, ceiling, f"D1 references grew in {name}: {current} > {ceiling}"
            )
            current_total += current
        self.assertLessEqual(current_total, sum(ceilings.values()))
        if current_total:
            foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
            self.assertIn("worker_d1_cutover_incomplete", foundation["readiness_blockers"])

    def test_computed_d1_access_and_new_source_are_detected(self):
        self.assertEqual(d1_access_count("env.DB; this.env.DB; env['DB']; env[\"DB\"]"), 4)
        sources = d1_worker_sources()
        cutover = json.loads(D1_CUTOVER_MAP.read_text(encoding="utf-8"))
        tracked = set(cutover["legacy_source_callsite_ceilings"])
        sample = "const row = await env['DB'].prepare('SELECT 1')"
        self.assertEqual(d1_access_count(sample), 1)
        sources["untracked_legacy.ts"] = sample
        self.assertIn("untracked_legacy.ts", d1_source_names(sources) - tracked)

    def test_documented_local_windows_scripts_exist(self):
        readme = (
            ROOT / "control-plane/cloudflare/README.md"
        ).read_text(encoding="utf-8")
        local_scripts = set(
            re.findall(r"`(scripts/windows/[^\s`]+\.ps1)`", readme)
        )
        for relative_path in local_scripts:
            self.assertTrue(
                (ROOT / relative_path).is_file(),
                f"README references a Windows script that does not exist: {relative_path}",
            )
        self.assertIn("product_device_setup_client_contract_not_verified", readme)
        self.assertIn("projeto responsável pelo Device Agent", readme)

    def test_device_websocket_handshake_fails_before_acceptance(self):
        source = WORKER_SOURCE.read_text(encoding="utf-8")
        helper = source.split(
            "function parseRuntimeIdentityHeaders(", 1
        )[1].split("async function wakeDeviceSession(", 1)[0]
        self.assertIn('request.headers.get("X-Ordax-Agent-Instance")', helper)
        self.assertIn('request.headers.get("X-Ordax-Boot-Id")', helper)
        self.assertIn("UUID_RE.test(agentInstanceId)", helper)
        self.assertIn("UUID_RE.test(bootId)", helper)

        outer = source.split(
            'if (request.method === "GET" && url.pathname === "/v3/device/ws")',
            1,
        )[1].split(
            'if (request.method === "POST" && url.pathname === "/v3/device/setup")',
            1,
        )[0]
        self.assertLess(
            outer.index("parseRuntimeIdentityHeaders(request)"),
            outer.index("env.DEVICE_SESSIONS.idFromName(deviceId)"),
        )
        self.assertIn('error: "runtime_identity_invalid"', outer)
        self.assertIn("authenticateDevice(env, deviceId, token)", outer)

        session = source.split('if (url.pathname === "/ws")', 1)[1].split(
            'if (url.pathname === "/wake"', 1
        )[0]
        self.assertIn('request.method !== "GET"', session)
        self.assertLess(
            session.index("parseRuntimeIdentityHeaders(request)"),
            session.index("new WebSocketPair()"),
        )
        self.assertIn(
            "WHERE id = ?2 AND revoked_at IS NULL", session,
        )
        self.assertIn("presence.meta.changes", session)
        self.assertIn('error: "device_revoked_or_missing"', session)
        self.assertLess(
            session.index("presence.meta.changes"),
            session.index("new WebSocketPair()"),
        )
        self.assertLess(
            session.index("new WebSocketPair()"),
            session.index("this.ctx.acceptWebSocket(server)"),
        )
        self.assertNotIn("server.close(1008, \"invalid runtime identity\")", session)

    def test_heartbeat_rejects_revoked_or_deleted_device(self):
        source = WORKER_SOURCE.read_text(encoding="utf-8")
        session = source.split("async webSocketMessage(", 1)[1]
        heartbeat = session.split('if (type === "heartbeat")', 1)[1].split(
            'const jobId = ', 1
        )[0]
        self.assertIn("revoked_at IS NULL", heartbeat)
        self.assertIn("presence.meta.changes", heartbeat)
        self.assertIn('error: "device_revoked_or_missing"', heartbeat)
        self.assertIn("ws.close(1008", heartbeat)
        self.assertLess(
            heartbeat.index("presence.meta.changes"),
            heartbeat.index("this.ack(ws, requestId, true"),
        )
        self.assertLess(
            heartbeat.index("ws.close(1008"),
            heartbeat.index("this.ack(ws, requestId, true"),
        )

    def test_artifact_token_is_not_issued_when_write_loses_a_race(self):
        source = WORKER_SOURCE.read_text(encoding="utf-8")
        replay = source.split("async function existingArtifactGrant(", 1)[1].split(
            "async function artifactJobAuthorized(", 1
        )[0]
        self.assertIn("const tokenUpdate = await env.DB.prepare(", replay)
        self.assertIn("(tokenUpdate.meta.changes ?? 0) !== 1", replay)
        self.assertIn('error: "artifact_replay_conflict"', replay)
        self.assertLess(
            replay.index("tokenUpdate.meta.changes"),
            replay.index("signed_url:"),
        )

        multipart = source.split("async function completeMultipartArtifact(", 1)[1].split(
            "async function abortMultipartArtifact(", 1
        )[0]
        self.assertIn("ON CONFLICT(id) DO NOTHING", multipart)
        self.assertIn("const publishInsert = await env.DB.prepare(", multipart)
        self.assertIn("(publishInsert.meta.changes ?? 0) !== 1", multipart)
        self.assertIn('error: "artifact_publish_conflict"', multipart)
        self.assertLess(
            multipart.index("publishInsert.meta.changes"),
            multipart.index("signed_url:"),
        )

    def test_unsafe_legacy_device_deletion_is_retired_before_first_deploy(self):
        source = WORKER_SOURCE.read_text(encoding="utf-8")
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        cutover = json.loads(D1_CUTOVER_MAP.read_text(encoding="utf-8"))
        self.assertNotIn("async function deleteDevice(", source)
        self.assertNotIn("return deleteDevice(", source)
        self.assertNotIn("artifacts_deleted:", source)
        self.assertNotIn("multipart_uploads_aborted:", source)
        self.assertNotIn("deleteDevice", LEGACY_OPERATOR_HANDLER_ALLOWLIST)
        self.assertEqual(cutover["legacy_source_callsite_ceilings"]["index.ts"], 35)
        self.assertEqual(sum(cutover["legacy_source_callsite_ceilings"].values()), 35)
        self.assertEqual(sum(d1_access_count(x) for x in d1_worker_sources().values()), 35)
        self.assertFalse(foundation["deployment_ready"])
        self.assertIn(
            "engineering_device_deletion_lifecycle_not_ready",
            foundation["readiness_blockers"],
        )
        route = source.split(
            'if (request.method === "POST" && url.pathname === "/v3/devices")', 1
        )[1].split('if (request.method === "GET" && url.pathname === "/oauth/consent")', 1)[0]
        self.assertNotIn('request.method === "DELETE"', route)

    def test_unsafe_legacy_retention_is_retired_before_first_deployment(self):
        cutover = json.loads(D1_CUTOVER_MAP.read_text(encoding="utf-8"))
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        self.assertNotIn("retention.ts", cutover["legacy_source_callsite_ceilings"])
        self.assertFalse((CLOUDFLARE_SRC / "retention.ts").exists())
        # Retiring retention must be a permanent reduction, not a fixed total
        # that blocks future independent D1 cutovers.
        remaining = sum(cutover["legacy_source_callsite_ceilings"].values())
        self.assertLessEqual(remaining, 89)
        self.assertEqual(
            sum(d1_access_count(source) for source in d1_worker_sources().values()),
            remaining,
        )
        for source in d1_worker_sources().values():
            self.assertNotIn("runProductRetention", source)
        self.assertNotIn("async scheduled(", WORKER_SOURCE.read_text(encoding="utf-8"))
        self.assertNotIn(
            '"product_retention_v1"',
            WORKER_SOURCE.read_text(encoding="utf-8"),
            "Retired retention must not be advertised by /health",
        )
        for config_name in ("wrangler.toml", "wrangler.ci.toml"):
            config_path = ROOT / "control-plane/cloudflare" / config_name
            with config_path.open("rb") as handle:
                config = tomllib.load(handle)
            self.assertFalse((config.get("triggers") or {}).get("crons"))
        self.assertFalse(foundation["deployment_ready"])
        self.assertIn(
            "artifact_retention_authority_not_ready",
            foundation["readiness_blockers"],
        )

    def test_d1_cutover_domains_are_explicit_about_authority_readiness(self):
        cutover = json.loads(D1_CUTOVER_MAP.read_text(encoding="utf-8"))
        valid_states = {"available", "partial", "missing", "redesign_required", "retired"}
        for domain in cutover["domains"]:
            self.assertIn(domain["authority_state"], valid_states)
            self.assertTrue(domain["cutover_strategy"])
            if domain["authority_state"] == "available":
                self.assertTrue(domain["target_contracts"])

    def test_product_auth_metadata_is_derived_from_canonical_project_ref(self):
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        with WRANGLER.open("rb") as handle:
            wrangler = tomllib.load(handle)
        project_ref = foundation["postgres"]["project_ref"]
        auth_origin = f"https://{project_ref}.supabase.co/auth/v1"
        self.assertEqual(
            wrangler["vars"]["PRODUCT_AUTH_ISSUER"],
            auth_origin,
        )
        self.assertEqual(
            wrangler["vars"]["PRODUCT_AUTH_JWKS_URL"],
            f"{auth_origin}/.well-known/jwks.json",
        )
        self.assertEqual(wrangler["vars"]["PRODUCT_AUTH_AUDIENCE"], "authenticated")
        self.assertNotIn("eobcxuyvhkvdmkbaihwh", WRANGLER.read_text(encoding="utf-8"))

    def test_legacy_operator_bearer_keeps_production_blocked(self):
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        source = WORKER_SOURCE.read_text(encoding="utf-8")
        blockers = set(foundation["readiness_blockers"])
        forbidden = set(foundation["policy"]["forbidden_runtime_secrets"])
        if "ORDAX_OPERATOR_TOKEN" in source or "operatorAuthorized(" in source:
            self.assertIn("worker_operator_auth_cutover_incomplete", blockers)
            self.assertIn("ORDAX_OPERATOR_TOKEN", forbidden)

    def test_legacy_operator_surface_is_frozen_until_authority_cutover(self):
        source = WORKER_SOURCE.read_text(encoding="utf-8")
        handler_pattern = re.compile(
            r"(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\([^)]*\)[^{]*\{([\s\S]*?)(?=\n(?:async\s+)?function\s+[A-Za-z0-9_]+\s*\(|\Z)"
        )
        operator_handlers = {
            name
            for name, body in handler_pattern.findall(source)
            if "operatorAuthorized(request, env)" in body
        }
        self.assertEqual(
            operator_handlers,
            LEGACY_OPERATOR_HANDLER_ALLOWLIST,
            "ORDAX_OPERATOR_TOKEN surface changed; new legacy bearer usage is forbidden and removals must update the allowlist",
        )

    def test_hyperdrive_adapter_replaces_legacy_rest_boundary(self):
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        adapter = POSTGRES_ADAPTER.read_text(encoding="utf-8")
        package = json.loads(WORKER_PACKAGE.read_text(encoding="utf-8"))
        blockers = set(foundation["readiness_blockers"])

        self.assertNotIn("SUPABASE_SERVER_KEY", adapter)
        self.assertNotIn("/rest/v1/rpc/", adapter)
        self.assertIn('env.POSTGRES?.connectionString', adapter)
        self.assertIn('import postgres from "postgres"', adapter)
        self.assertEqual(package["dependencies"]["postgres"], "3.4.5")
        self.assertNotIn("worker_hyperdrive_adapter_not_implemented", blockers)

        with WRANGLER.open("rb") as handle:
            wrangler = tomllib.load(handle)
        self.assertIn("nodejs_compat", wrangler.get("compatibility_flags") or [])

    def test_routine_workflow_reads_account_from_single_source_of_truth(self):
        workflow = WORKFLOW.read_text(encoding="utf-8-sig")
        self.assertNotIn("secrets.CLOUDFLARE_ACCOUNT_ID", workflow)
        self.assertNotIn(OLD_ACCOUNT_ID, workflow)
        self.assertNotIn(DEDICATED_ACCOUNT_ID, workflow)
        self.assertIn(
            "control-plane/cloudflare/production-foundation.json",
            (ROOT / "scripts/cloudflare/check_deploy_readiness.py").read_text(encoding="utf-8"),
        )
        self.assertIn("needs.foundation.outputs.account_id", workflow)
        self.assertIn("needs.foundation.outputs.deployment_ready == 'true'", workflow)
        self.assertIn("secrets.CLOUDFLARE_API_TOKEN", workflow)
        self.assertNotIn("secrets.ORDAX_OPERATOR_TOKEN", workflow)
        self.assertIn("check_deploy_readiness.py --allow-blocked", workflow)
        self.assertIn('--github-output "$GITHUB_OUTPUT"', workflow)
        self.assertNotIn("python - <<'PY'", workflow)

    def test_not_ready_foundation_skips_deploy_instead_of_creating_false_incident(self):
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        workflow = WORKFLOW.read_text(encoding="utf-8-sig")
        self.assertFalse(foundation["deployment_ready"])
        self.assertTrue(foundation["readiness_blockers"])
        self.assertIn("foundation:", workflow)
        self.assertIn("deploy:", workflow)
        self.assertNotIn("Enforce dedicated-account migration gate", workflow)

    def test_legacy_d1_bootstrap_is_retired_unconditionally(self):
        script = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("Legacy D1/bootstrap deployment has been retired", script)
        self.assertIn("exit 3", script)
        self.assertNotIn("wrangler d1 create", script)
        self.assertNotIn("wrangler deploy", script)
        self.assertNotIn("d1 migrations apply", script)

    def test_routine_script_runs_canonical_gate_before_cloudflare_calls(self):
        script = ROUTINE_DEPLOY.read_text(encoding="utf-8")
        self.assertIn('python "$ROOT/scripts/cloudflare/check_deploy_readiness.py"', script)
        gate_at = script.index("check_deploy_readiness.py")
        self.assertLess(gate_at, script.index('CLOUDFLARE_API_TOKEN:?'))
        self.assertLess(gate_at, script.index('cloudflare_api()'))
        self.assertLess(gate_at, script.index('npx --yes "wrangler@'))

    def test_routine_deploy_has_no_legacy_account_or_workers_dev_url_fallback(self):
        script = ROUTINE_DEPLOY.read_text(encoding="utf-8")
        self.assertNotIn(OLD_ACCOUNT_ID, script)
        self.assertNotIn("ordax-ac1ca1b50d09", script)
        self.assertIn(
            'ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:?CLOUDFLARE_ACCOUNT_ID is required}"',
            script,
        )
        self.assertIn("/workers/subdomain", script)
        self.assertNotIn("workers/subdomain\" -X PUT", script)


if __name__ == "__main__":
    unittest.main()
