"""Canonical production release stays blocked; read-only validation is separate."""
import copy
import json
import tomllib
import unittest
from pathlib import Path

from scripts.cloudflare.check_mcp_release import (
    ROOT,FOUNDATION,CONFIG,McpReleaseError,validate,validate_read_only_validation,
    REQUIRED_PROOFS,READ_ONLY_EVIDENCE
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

    def test_real_production_state_is_blocked_not_faked_ready(self):
        self.assertFalse(validate(self.foundation,self.config))
        release=self.foundation["mcp_release"]
        self.assertFalse(release["deployment_ready"])
        self.assertFalse(release["supports_remote_actions"])
        required_blockers={
            "chatgpt_oauth_client_consent_not_verified",
            "product_device_enrollment_and_grants_missing",
            "central_trusted_session_attestor_not_provisioned",
            "canonical_remote_actions_not_ready",
            "legacy_control_plane_v3_runtime_not_retired",
            "end_to_end_chatgpt_to_device_not_verified",
        }
        self.assertTrue(required_blockers.issubset(set(release["readiness_blockers"])))
        evidence=release.get("verified_evidence") or {}
        self.assertRegex(
            evidence.get("custom_domain_tls_run_url", ""),
            r"^https://github\.com/ordaxsystems/ordax-platform/actions/runs/[0-9]+$",
        )
        self.assertEqual(
            evidence.get("worker_version_id"),
            "95c5b0cd-3f65-4cee-8d02-46f6bc1a91bb",
        )
        self.assertFalse(self.config["workers_dev"])
        self.assertFalse(self.config["preview_urls"])

    def test_read_only_validation_is_eligible_while_production_remains_blocked(self):
        self.assertFalse(validate(self.foundation,self.config))
        self.assertTrue(validate_read_only_validation(self.foundation,self.config))
        release=self.foundation["mcp_release"]
        self.assertEqual(release["validation_mode"],"read-only-canary")
        self.assertTrue(release["validation_deployment_ready"])
        self.assertFalse(release["supports_remote_actions"])
        evidence=release["read_only_validation_evidence"]
        self.assertEqual(set(evidence),READ_ONLY_EVIDENCE)
        self.assertEqual(evidence["chatgpt_oauth_client_id"],"95d41a8f-0fb8-4c4b-9757-83ba6345062d")

    def test_read_only_validation_cannot_enable_remote_actions(self):
        f=copy.deepcopy(self.foundation)
        f["mcp_release"]["supports_remote_actions"]=True
        with self.assertRaisesRegex(McpReleaseError,"read_only_remote_actions_must_be_disabled|remote_actions"):
            validate_read_only_validation(f,self.config)

    def test_read_only_validation_requires_exact_independent_evidence(self):
        f=copy.deepcopy(self.foundation)
        f["mcp_release"]["read_only_validation_evidence"]={}
        with self.assertRaisesRegex(McpReleaseError,"evidence_incomplete"):
            validate_read_only_validation(f,self.config)
        f=copy.deepcopy(self.foundation)
        f["mcp_release"]["read_only_validation_evidence"]["candidate_run_url"]="https://evil.example/run/1"
        with self.assertRaisesRegex(McpReleaseError,"evidence_invalid_candidate_run_url"):
            validate_read_only_validation(f,self.config)
        f=copy.deepcopy(self.foundation)
        f["mcp_release"]["read_only_validation_evidence"]["chatgpt_oauth_client_id"]="11111111-1111-4111-8111-111111111111"
        with self.assertRaisesRegex(McpReleaseError,"chatgpt_client_invalid"):
            validate_read_only_validation(f,self.config)

    def test_read_only_validation_flag_cannot_replace_production_readiness(self):
        f=copy.deepcopy(self.foundation)
        f["mcp_release"]["validation_deployment_ready"]=False
        self.assertFalse(validate(f,self.config))
        with self.assertRaisesRegex(McpReleaseError,"read_only_validation_not_ready"):
            validate_read_only_validation(f,self.config)

    def test_bogus_enablement_without_proofs_is_rejected(self):
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
            {"workers_dev":True},
            {"preview_urls":True},
            {"vars":{"PRODUCT_AUTH_ISSUER":"https://evil.example.invalid"}},
        ):
            with self.subTest(change=change):
                c=copy.deepcopy(self.config);c.update(change)
                with self.assertRaises(McpReleaseError):
                    validate(self.foundation,c)
                with self.assertRaises(McpReleaseError):
                    validate_read_only_validation(self.foundation,c)

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
                with self.assertRaises(McpReleaseError):
                    validate(f,self.config)
                with self.assertRaises(McpReleaseError):
                    validate_read_only_validation(f,self.config)

    def test_no_route_to_old_worker_is_published_by_new_source(self):
        entry=(ROOT/"control-plane/cloudflare/src/product_mcp_entry.ts").read_text("utf-8")
        config=CONFIG.read_text("utf-8")
        self.assertNotIn("src/index.ts",config)
        self.assertNotIn("D1Database",entry)
        self.assertNotIn("env.DB",entry)
        self.assertNotIn("ordax-control-plane-v3",entry)
        self.assertIn('supports_remote_actions: false',entry)
        self.assertIn('trusted_operation_required',entry)
        self.assertIn('createCanonicalProductMcpReadHandlers',entry)
        self.assertIn('READ_ONLY_TOOLS',entry)

if __name__=="__main__":
    unittest.main()
