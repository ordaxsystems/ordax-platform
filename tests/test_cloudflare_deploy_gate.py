import copy
import importlib.util
import json
import os
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts/cloudflare/check_deploy_readiness.py"
FOUNDATION = ROOT / "control-plane/cloudflare/production-foundation.json"
WRANGLER = ROOT / "control-plane/cloudflare/wrangler.toml"
LEGACY = ROOT / "scripts/cloudflare/deploy-v3.sh"
ROUTINE = ROOT / "scripts/cloudflare/deploy-production-v3.sh"
BOOTSTRAP = ROOT / "scripts/cloudflare/bootstrap-worker-v3.sh"
PUBLIC_SMOKE = ROOT / "scripts/verify_cloudflare_public.py"

spec = importlib.util.spec_from_file_location("ordax_cloudflare_deploy_gate", GUARD)
gate = importlib.util.module_from_spec(spec)
assert spec is not None and spec.loader is not None
spec.loader.exec_module(gate)


class CloudflareDirectDeployGateTests(unittest.TestCase):
    def setUp(self):
        self.foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        with WRANGLER.open("rb") as stream:
            self.wrangler = tomllib.load(stream)

    def validate(self, source="export default {}"):
        return gate.validate(self.foundation, self.wrangler, source,
                             self.foundation["account_id"])

    def test_existing_foundation_is_blocked(self):
        self.assertFalse(self.validate())
        self.assertIn("worker_d1_cutover_incomplete", self.foundation["readiness_blockers"])

    def test_ready_foundation_requires_no_d1_binding(self):
        self.foundation["deployment_ready"] = True
        self.foundation["readiness_blockers"] = []
        # The canonical configuration has no D1. Reintroducing the old
        # binding must still cause the release gate to fail closed.
        self.wrangler["d1_databases"] = [{"binding": "DB", "database_name": "retired"}]
        with self.assertRaisesRegex(gate.DeployGateError, "D1 binding"):
            self.validate()

    def test_ready_foundation_requires_no_operator_or_d1_source(self):
        self.foundation["deployment_ready"] = True
        self.foundation["readiness_blockers"] = []
        self.wrangler.pop("d1_databases", None)
        with self.assertRaisesRegex(gate.DeployGateError, "D1 access"):
            self.validate("async function x() { return env.DB.prepare('select 1'); }")
        with self.assertRaisesRegex(gate.DeployGateError, "operator bearer"):
            self.validate("return operatorAuthorized(request, env);")
        with self.assertRaisesRegex(gate.DeployGateError, "Supabase server secret"):
            self.validate("const SUPABASE_SERVER_KEY = 'forbidden';")
        self.assertTrue(self.validate("export default {}"))

    def test_direct_and_computed_d1_accesses_share_one_scanner(self):
        forms = (
            "env.DB", "this.env.DB", "env['DB']", 'env["DB"]',
            "env[`DB`]", "env?.DB", "env?.['DB']", "this?.env?.DB",
        )
        self.assertEqual(gate.d1_access_count("; ".join(forms)), len(forms))
        self.assertEqual(
            gate.d1_source_names({"legacy.ts": "env['DB']", "clean.ts": "export {}"}),
            {"legacy.ts"},
        )
        self.foundation["deployment_ready"] = True
        self.foundation["readiness_blockers"] = []
        self.wrangler.pop("d1_databases", None)
        for expression in forms:
            with self.subTest(expression=expression):
                with self.assertRaisesRegex(gate.DeployGateError, "D1 access"):
                    self.validate("const db = " + expression)

    def test_nested_typescript_and_javascript_are_audited_before_deploy(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary) / "src"
            nested = root / "features" / "devices"
            nested.mkdir(parents=True)
            (root / "index.ts").write_text("export default {}", encoding="utf-8")
            (nested / "runtime.mts").write_text(
                "const legacy = env?.['DB']", encoding="utf-8"
            )
            (nested / "feature.mjs").write_text(
                "export const active = true", encoding="utf-8"
            )
            (nested / "documentation.txt").write_text(
                "env.DB", encoding="utf-8"
            )
            sources = gate.worker_source_texts(root)
            self.assertEqual(
                set(sources),
                {"index.ts", "features/devices/runtime.mts", "features/devices/feature.mjs"},
            )
            self.assertEqual(
                gate.d1_source_names(sources),
                {"features/devices/runtime.mts"},
            )
            self.assertIn(
                "source_files = worker_source_texts(WORKER_SOURCES)",
                GUARD.read_text(encoding="utf-8"),
            )
            self.foundation["deployment_ready"] = True
            self.foundation["readiness_blockers"] = []
            self.wrangler.pop("d1_databases", None)
            with self.assertRaisesRegex(gate.DeployGateError, "D1 access"):
                self.validate("\n".join(sources.values()))

    def test_partial_d1_cutover_cannot_omit_its_readiness_blocker(self):
        self.foundation["readiness_blockers"] = [
            blocker for blocker in self.foundation["readiness_blockers"]
            if blocker != "worker_d1_cutover_incomplete"
        ]
        # A deleted D1 authority is not itself a reason to block development;
        # any reintroduced D1 reference without a blocker is forbidden.
        with self.assertRaisesRegex(gate.DeployGateError, "D1 cutover blocker"):
            self.validate("const db = env['DB']")
        self.assertFalse(self.validate("export default {}"))

    def test_forged_readiness_or_missing_blockers_fails_closed(self):
        self.foundation["deployment_ready"] = True
        with self.assertRaisesRegex(gate.DeployGateError, "contradicts"):
            self.validate()
        self.foundation["deployment_ready"] = False
        self.foundation["readiness_blockers"] = []
        with self.assertRaisesRegex(gate.DeployGateError, "contradicts"):
            self.validate()

    def test_account_2fa_enforcement_is_a_hard_deploy_requirement(self):
        self.foundation["live_evidence"]["security"]["account_enforce_twofactor"] = False
        with self.assertRaisesRegex(gate.DeployGateError, "account 2FA enforcement"):
            self.validate()
        self.foundation["live_evidence"]["security"]["account_enforce_twofactor"] = True
        self.foundation["live_evidence"]["security"]["member_two_factor_enabled"] = False
        with self.assertRaisesRegex(gate.DeployGateError, "account 2FA enforcement"):
            self.validate()

    def test_canonical_binding_and_account_are_enforced(self):
        with self.assertRaisesRegex(gate.DeployGateError, "account differs"):
            gate.validate(self.foundation, self.wrangler, "", "0" * 32)
        self.wrangler["hyperdrive"][0]["id"] = "0" * 32
        with self.assertRaisesRegex(gate.DeployGateError, "Hyperdrive binding"):
            self.validate()

    def test_canonical_supabase_identity_is_a_deploy_hard_gate(self):
        auth = self.wrangler["vars"]
        expected = {
            "PRODUCT_AUTH_ISSUER": "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1",
            "PRODUCT_AUTH_JWKS_URL": "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1/.well-known/jwks.json",
            "PRODUCT_AUTH_AUDIENCE": "authenticated",
            "SUPABASE_PUBLISHABLE_KEY": auth["SUPABASE_PUBLISHABLE_KEY"],
        }
        for name, invalid, message in (
            ("PRODUCT_AUTH_ISSUER", "https://eobcxuyvhkvdmkbaihwh.supabase.co/auth/v1", "Product OAuth issuer"),
            ("PRODUCT_AUTH_JWKS_URL", "https://eobcxuyvhkvdmkbaihwh.supabase.co/auth/v1/.well-known/jwks.json", "Product OAuth JWKS"),
            ("PRODUCT_AUTH_AUDIENCE", "legacy-audience", "Product OAuth audience"),
            ("SUPABASE_PUBLISHABLE_KEY", "legacy-public-key", "public browser key"),
        ):
            with self.subTest(field=name):
                auth[name] = invalid
                with self.assertRaisesRegex(gate.DeployGateError, message):
                    self.validate()
                auth[name] = expected[name]
        self.assertFalse(self.validate())

    def test_auth_gate_rejects_mismatched_project_ref_and_missing_key(self):
        self.foundation["postgres"]["project_ref"] = "eobcxuyvhkvdmkbaihwh"
        with self.assertRaisesRegex(gate.DeployGateError, "OAuth issuer"):
            self.validate()
        self.foundation["postgres"]["project_ref"] = "jhfphsjptrpmtnzkpwud"
        self.wrangler["vars"].pop("SUPABASE_PUBLISHABLE_KEY")
        with self.assertRaisesRegex(gate.DeployGateError, "public browser key"):
            self.validate()

    def test_do_and_r2_bindings_are_enforced(self):
        self.wrangler["r2_buckets"][0]["bucket_name"] = "incorrect"
        with self.assertRaisesRegex(gate.DeployGateError, "R2 bucket"):
            self.validate()
        self.wrangler["r2_buckets"][0]["bucket_name"] = self.foundation["r2_bucket"]
        self.wrangler["durable_objects"]["bindings"][0]["class_name"] = "Changed"
        with self.assertRaisesRegex(gate.DeployGateError, "Durable Objects"):
            self.validate()

    def test_direct_guard_rejects_actual_not_ready_foundation(self):
        env = {**os.environ, "CLOUDFLARE_ACCOUNT_ID": self.foundation["account_id"]}
        command = [sys.executable, str(GUARD)]
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("BLOCKED", result.stdout)
        preview = subprocess.run(command + ["--allow-blocked"], cwd=ROOT,
                                 env=env, capture_output=True, text=True)
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertIn("BLOCKED", preview.stdout)

    def test_bootstrap_requires_exact_initial_worker_blockers(self):
        self.foundation["readiness_blockers"] = [
            "worker_not_provisioned",
            "cloudflare_ci_worker_editor_token_not_provisioned",
        ]
        self.wrangler.pop("d1_databases", None)
        self.assertFalse(gate.validate(
            self.foundation, self.wrangler, "export default {}",
            self.foundation["account_id"], bootstrap=True,
        ))
        with self.assertRaisesRegex(gate.DeployGateError, "operator bearer"):
            gate.validate(self.foundation, self.wrangler, "ORDAX_OPERATOR_TOKEN",
                          self.foundation["account_id"], bootstrap=True)
        self.foundation["readiness_blockers"].append("worker_d1_cutover_incomplete")
        with self.assertRaisesRegex(gate.DeployGateError, "exactly the Worker"):
            gate.validate(self.foundation, self.wrangler, "export default {}",
                          self.foundation["account_id"], bootstrap=True)

    def test_bootstrap_script_is_blocked_before_using_admin_credential(self):
        source = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("check_deploy_readiness.py", source)
        self.assertIn("--bootstrap", source)
        self.assertIn("workers/scripts/$WORKER_NAME", source)
        self.assertNotIn("wrangler d1", source)
        self.assertNotIn("d1 migrations apply", source)
        self.assertLess(source.index("check_deploy_readiness.py"),
                        source.index("CLOUDFLARE_API_TOKEN:?"))
        command = ["bash", str(BOOTSTRAP)]
        result = subprocess.run(command, cwd=ROOT,
                                env={**os.environ, "CLOUDFLARE_ACCOUNT_ID": self.foundation["account_id"]},
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("initial Worker bootstrap", result.stderr)
        self.assertNotIn("CLOUDFLARE_API_TOKEN is required", result.stderr)

    def test_routine_deploy_requires_preexisting_worker(self):
        source = ROUTINE.read_text(encoding="utf-8")
        self.assertIn("workers/scripts/$WORKER_NAME", source)
        self.assertIn("Existing Worker identity could not be verified", source)
        self.assertLess(source.index("workers/scripts/$WORKER_NAME"),
                        source.index("npx --yes"))

    def test_public_smoke_must_not_fall_back_to_legacy_account(self):
        source = PUBLIC_SMOKE.read_text(encoding="utf-8")
        self.assertNotIn("ordax-ac1ca1b50d09", source)
        self.assertIn("Pass --base-url or ORDAX_E2E_CONTROL_PLANE_URL", source)

    def test_retired_bootstrap_exits_without_deploy_credentials(self):
        result = subprocess.run(["bash", str(LEGACY)], cwd=ROOT,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 3)
        self.assertIn("retired", result.stderr)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", result.stderr)


if __name__ == "__main__":
    unittest.main()
