"""Canonical MCP: interactive candidate may deploy; production still requires independent E2E proofs."""
import copy
import json
import tomllib
import unittest

from scripts.cloudflare.check_mcp_release import (
    ROOT, FOUNDATION, CONFIG, McpReleaseError, validate, validate_interactive_candidate,
    REQUIRED_PROOFS, VALIDATION_BASELINE_EVIDENCE, TRUSTED_CLIENT_INGRESS,
)


class McpReleaseContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.foundation=json.loads(FOUNDATION.read_text(encoding="utf-8"))
        with CONFIG.open("rb") as f: cls.config=tomllib.load(f)

    def test_canonical_worker_and_domain_exist_in_one_ssot(self):
        f=self.foundation;c=self.config
        self.assertEqual(f["mcp_release"]["worker_name"],"ordax-mcp")
        self.assertEqual(f["mcp_release"]["hostname"],"mcp.ordax.com.br")
        self.assertEqual(c["name"],f["mcp_release"]["worker_name"])
        self.assertEqual(c["main"],"src/product_mcp_entry.ts")
        self.assertNotIn("d1_databases",c)
        self.assertNotIn("durable_objects",c)
        self.assertNotIn("r2_buckets",c)
        self.assertEqual(c["hyperdrive"][0]["binding"],"POSTGRES")

    def test_machine_endpoint_edge_policy_is_explicit_and_hostname_scoped(self):
        edge=self.foundation["mcp_release"].get("edge_machine_endpoint")
        self.assertEqual(edge,{
            "scope":"hostname_only",
            "hostname":"mcp.ordax.com.br",
            "cloudflare_phase":"http_config_settings",
            "cloudflare_rule_ref":"ordax_mcp_disable_bic",
            "browser_integrity_check":False,
            "reason":"machine_to_machine_clients_must_not_require_browser_headers",
        })
        evidence=self.foundation["mcp_release"]["verified_evidence"]
        self.assertEqual(evidence["edge_config_rule_ref"],edge["cloudflare_rule_ref"])
        self.assertRegex(
            evidence["public_read_only_smoke_run_url"],
            r"^https://github\.com/ordaxsystems/ordax-platform/actions/runs/[0-9]+$",
        )

    def test_trusted_client_ingress_is_separate_from_public_mcp_identity(self):
        release=self.foundation["mcp_release"]
        self.assertFalse(release["workers_dev"])
        self.assertTrue(self.config["workers_dev"])
        self.assertFalse(self.config["preview_urls"])
        self.assertEqual(release["trusted_client_ingress"],TRUSTED_CLIENT_INGRESS)
        self.assertFalse(release["trusted_client_ingress"]["public_mcp_exposed"])
        self.assertEqual(release["trusted_client_ingress"]["authority"],"same_worker_postgresql_oauth")
        self.assertNotIn("device_machine_ingress",release)
        self.assertNotEqual(
            release["trusted_client_ingress"]["hostname"],
            release["hostname"],
        )

    def test_candidate_has_actions_but_production_is_still_blocked(self):
        self.assertFalse(validate(self.foundation,self.config))
        release=self.foundation["mcp_release"]
        self.assertFalse(release["deployment_ready"])
        self.assertTrue(release["supports_remote_actions"])
        required_blockers={
            "interactive_computer_grant_not_authorized",
            "attested_interactive_end_to_end_not_verified",
            "canonical_remote_actions_release_not_verified",
        }
        self.assertTrue(required_blockers.issubset(set(release["readiness_blockers"])))
        evidence=release.get("verified_evidence") or {}
        self.assertRegex(
            evidence.get("custom_domain_tls_run_url", ""),
            r"^https://github\.com/ordaxsystems/ordax-platform/actions/runs/[0-9]+$",
        )
        self.assertEqual(evidence.get("worker_version_id"),"e0d2049f-adec-46db-b094-6c9f051964ef")
        self.assertFalse(release["workers_dev"])
        self.assertTrue(self.config["workers_dev"])
        self.assertFalse(self.config["preview_urls"])

    def test_interactive_candidate_is_eligible_while_production_remains_blocked(self):
        self.assertFalse(validate(self.foundation,self.config))
        self.assertTrue(validate_interactive_candidate(self.foundation,self.config))
        release=self.foundation["mcp_release"]
        self.assertEqual(release["validation_mode"],"attested-interactive-candidate")
        self.assertTrue(release["validation_deployment_ready"])
        self.assertTrue(release["supports_remote_actions"])
        evidence=release["oauth_baseline_evidence"]
        self.assertEqual(set(evidence),VALIDATION_BASELINE_EVIDENCE)
        self.assertEqual(evidence["chatgpt_oauth_client_id"],"95d41a8f-0fb8-4c4b-9757-83ba6345062d")

    def test_interactive_candidate_cannot_disable_remote_actions(self):
        f=copy.deepcopy(self.foundation)
        f["mcp_release"]["supports_remote_actions"]=False
        f["mcp_release"]["readiness_blockers"].append("canonical_remote_actions_not_ready")
        with self.assertRaisesRegex(McpReleaseError,"interactive_candidate_remote_actions_required"):
            validate_interactive_candidate(f,self.config)

    def test_interactive_candidate_requires_exact_oauth_baseline(self):
        f=copy.deepcopy(self.foundation)
        f["mcp_release"]["oauth_baseline_evidence"]={}
        with self.assertRaisesRegex(McpReleaseError,"baseline_evidence_incomplete"):
            validate_interactive_candidate(f,self.config)
        f=copy.deepcopy(self.foundation)
        f["mcp_release"]["oauth_baseline_evidence"]["candidate_run_url"]="https://evil.example/run/1"
        with self.assertRaisesRegex(McpReleaseError,"baseline_invalid_candidate_run_url"):
            validate_interactive_candidate(f,self.config)
        f=copy.deepcopy(self.foundation)
        f["mcp_release"]["oauth_baseline_evidence"]["chatgpt_oauth_client_id"]="11111111-1111-4111-8111-111111111111"
        with self.assertRaisesRegex(McpReleaseError,"chatgpt_client_invalid"):
            validate_interactive_candidate(f,self.config)

    def test_candidate_flag_cannot_replace_production_readiness(self):
        f=copy.deepcopy(self.foundation)
        f["mcp_release"]["validation_deployment_ready"]=False
        self.assertFalse(validate(f,self.config))
        with self.assertRaisesRegex(McpReleaseError,"interactive_candidate_not_ready"):
            validate_interactive_candidate(f,self.config)

    def test_candidate_must_keep_real_e2e_blocker_until_proven(self):
        f=copy.deepcopy(self.foundation)
        f["mcp_release"]["readiness_blockers"].remove("attested_interactive_end_to_end_not_verified")
        with self.assertRaisesRegex(McpReleaseError,"interactive_e2e_blocker_missing"):
            validate(f,self.config)
        with self.assertRaisesRegex(McpReleaseError,"interactive_e2e_blocker_missing|candidate_e2e_blocker_missing"):
            validate_interactive_candidate(f,self.config)

    def test_bogus_production_enablement_without_proofs_is_rejected(self):
        f=copy.deepcopy(self.foundation)
        f["mcp_release"]["deployment_ready"]=True
        f["mcp_release"]["supports_remote_actions"]=True
        f["mcp_release"]["readiness_blockers"]=[]
        with self.assertRaisesRegex(McpReleaseError,"independent_proofs"):
            validate(f,self.config)
        f["mcp_release"]["release_evidence"]={p:"not-a-verified-run" for p in REQUIRED_PROOFS}
        with self.assertRaisesRegex(McpReleaseError,"invalid_proof"):
            validate(f,self.config)
        f["mcp_release"]["release_evidence"]={
            p:"https://github.com/ordaxsystems/ordax-platform/actions/runs/38183091421"
            for p in REQUIRED_PROOFS
        }
        with self.assertRaisesRegex(McpReleaseError,"device_dispatch_not_verified"):
            validate(f,self.config)

    def test_ready_release_cannot_disable_remote_actions(self):
        f=copy.deepcopy(self.foundation)
        f["mcp_release"]["deployment_ready"]=True
        f["mcp_release"]["readiness_blockers"]=[]
        f["mcp_release"]["supports_remote_actions"]=False
        with self.assertRaisesRegex(McpReleaseError,"remote_actions_not_ready"):
            validate(f,self.config)

    def test_d1_old_worker_or_broader_bindings_are_never_accepted(self):
        for change in (
            {"name":"ordax-control-plane-v3"},
            {"name":"ordax-control-plane-v3-canary"},
            {"main":"src/index.ts"},
            {"d1_databases":[{"binding":"DB","database_id":"legacy"}]},
            {"durable_objects":{"bindings":[{"name":"DEVICE_SESSIONS"}]}},
            {"r2_buckets":[{"binding":"ARTIFACTS"}]},
            {"routes":["mcp.ordax.com.br/*"]},
            {"workers_dev":False},
            {"preview_urls":True},
            {"vars":{"PRODUCT_AUTH_ISSUER":"https://evil.example.invalid"}},
        ):
            with self.subTest(change=change):
                c=copy.deepcopy(self.config);c.update(change)
                with self.assertRaises(McpReleaseError): validate(self.foundation,c)
                with self.assertRaises(McpReleaseError): validate_interactive_candidate(self.foundation,c)

    def test_trusted_client_ingress_contract_cannot_be_broadened_or_renamed(self):
        for mutate in (
            lambda ingress: ingress.update({"hostname":"evil.example"}),
            lambda ingress: ingress.update({"public_mcp_exposed":True}),
            lambda ingress: ingress.update({"authority":"other_backend"}),
            lambda ingress: ingress["allowed_exact_paths"].append("/mcp"),
            lambda ingress: ingress["allowed_path_prefixes"].append("/v3/product/"),
        ):
            f=copy.deepcopy(self.foundation)
            mutate(f["mcp_release"]["trusted_client_ingress"])
            with self.assertRaisesRegex(McpReleaseError,"trusted_client_ingress_contract_invalid"):
                validate(f,self.config)
            with self.assertRaises(McpReleaseError):
                validate_interactive_candidate(f,self.config)

    def test_obsolete_device_machine_ingress_is_rejected(self):
        f=copy.deepcopy(self.foundation)
        f["mcp_release"]["device_machine_ingress"]={}
        with self.assertRaisesRegex(McpReleaseError,"obsolete_device_machine_ingress"):
            validate(f,self.config)

    def test_alias_or_duplicate_name_is_rejected(self):
        for field,value in (
            ("worker_name","ordax-control-plane-v3"),
            ("hostname","ordax-control-plane-v3.ordaxsystems.workers.dev"),
            ("entrypoint","src/index.ts"),
            ("transport","stdio"),
        ):
            with self.subTest(field=field):
                f=copy.deepcopy(self.foundation)
                f["mcp_release"][field]=value
                with self.assertRaises(McpReleaseError): validate(f,self.config)
                with self.assertRaises(McpReleaseError): validate_interactive_candidate(f,self.config)

    def test_public_deployment_smoke_requires_actual_hyperdrive_sql_readiness(self):
        source = (ROOT / ".github/workflows/ordax-mcp-validation-deploy.yml").read_text(
            encoding="utf-8"
        )
        # The OAuth issuer may be healthy while Hyperdrive is disconnected.
        # A public smoke that only checks OAuth could approve that outage.
        self.assertIn("ready=get('/ready')", source)
        self.assertIn("assert ready.get('oauth_discovery_ready') is True, ready", source)
        self.assertIn("assert ready.get('postgres_ready') is True, ready", source)
        self.assertIn("assert ready.get('supports_remote_actions') is True, ready", source)

    def test_target_discovery_postgres_changes_trigger_every_mcp_release_gate(self):
        # The target-discovery grant RPC is part of the canonical MCP read
        # authority. An edit to this store must never evade canary, bundle,
        # or the explicitly gated interactive validation deployment.
        workflows = (
            (".github/workflows/product-mcp-canary.yml", 2),
            (".github/workflows/ordax-mcp-canonical.yml", 2),
            (".github/workflows/ordax-mcp-validation-deploy.yml", 1),
        )
        for name, expected_path_counts in workflows:
            with self.subTest(workflow=name):
                source = (ROOT / name).read_text(encoding="utf-8")
                self.assertEqual(
                    source.count('- "control-plane/cloudflare/src/product_mcp_discovery_store.ts"'),
                    expected_path_counts,
                )
                self.assertEqual(
                    source.count('- "control-plane/tests/product_mcp_discovery_store.test.mts"'),
                    expected_path_counts,
                )
                self.assertRegex(
                    source,
                    r"(?m)^\s*run: node --test[^\n]*control-plane/tests/product_mcp_discovery_store\.test\.mts",
                )

    def test_new_source_has_one_canonical_attested_action_boundary(self):
        entry=(ROOT/"control-plane/cloudflare/src/product_mcp_entry.ts").read_text("utf-8")
        config=CONFIG.read_text("utf-8")
        self.assertNotIn("src/index.ts",config)
        self.assertNotIn("D1Database",entry)
        self.assertNotIn("env.DB",entry)
        self.assertNotIn("ordax-control-plane-v3",entry)
        self.assertIn('supports_remote_actions: true',entry)
        self.assertIn('supports_attested_remote_reads: true',entry)
        self.assertIn('trusted_operation_required',entry)
        self.assertIn('createCanonicalProductMcpReadHandlers',entry)
        self.assertIn('PRODUCT_MCP_CORE_READ_TOOLS',entry)
        self.assertIn('PRODUCT_MCP_DIRECT_TOOLS',entry)
        self.assertIn('ATTESTED_DEVICE_ACTION_TOOLS',entry)
        self.assertIn('createAttestedDeviceActionHandler',entry)
        self.assertIn('PRODUCT_TRUSTED_CLIENT_HOSTNAME',entry)
        self.assertIn('isProductTrustedClientPath',entry)
        self.assertNotIn('PRODUCT_DEVICE_MACHINE_HOSTNAME',entry)
        self.assertNotIn('isProductDeviceMachinePath',entry)
        self.assertNotIn('createAttestedDeviceReadActionHandler',entry)


if __name__=="__main__":
    unittest.main()
