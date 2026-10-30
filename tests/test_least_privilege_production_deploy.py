from __future__ import annotations

import json
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class LeastPrivilegeProductionDeployTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (ROOT / ".github/workflows/cloudflare-v3-deploy.yml").read_text(encoding="utf-8")
        cls.deploy = (ROOT / "scripts/cloudflare/deploy-production-v3.sh").read_text(encoding="utf-8")
        cls.wrangler = tomllib.loads(
            (ROOT / "control-plane/cloudflare/wrangler.toml").read_text(encoding="utf-8")
        )
        cls.foundation = json.loads(
            (ROOT / "control-plane/cloudflare/production-foundation.json").read_text(encoding="utf-8")
        )

    def test_routine_workflow_requires_only_cloudflare_deploy_token(self) -> None:
        self.assertIn("CLOUDFLARE_API_TOKEN", self.workflow)
        self.assertNotIn("ORDAX_OPERATOR_TOKEN", self.workflow)
        self.assertNotIn("verify_cloudflare_v3.py", self.workflow)
        self.assertIn("verify_cloudflare_public.py", self.workflow)

    def test_routine_deploy_does_not_provision_bound_infrastructure(self) -> None:
        for forbidden in (
            "d1 create",
            "d1 migrations apply",
            "r2 bucket create",
            "secret put",
            "--secrets-file",
        ):
            self.assertNotIn(forbidden, self.deploy)
        self.assertIn('wrangler@${WRANGLER_VERSION}" deploy', self.deploy)

    def test_canonical_config_has_authorized_bindings_and_auth(self) -> None:
        self.assertEqual(self.wrangler["name"], self.foundation["worker_name"])
        self.assertEqual(
            self.wrangler["vars"]["PRODUCT_AUTH_AUDIENCE"], "authenticated"
        )
        self.assertEqual(
            self.wrangler["vars"]["PRODUCT_AUTH_ISSUER"],
            f"https://{self.foundation['postgres']['project_ref']}.supabase.co/auth/v1",
        )
        self.assertFalse(self.wrangler.get("r2_buckets", []))
        self.assertFalse(self.wrangler.get("durable_objects", {}).get("bindings", []))
        self.assertEqual(
            [(b["binding"], b["id"]) for b in self.wrangler.get("hyperdrive", [])],
            [(
                self.foundation["postgres"]["hyperdrive_binding"],
                self.foundation["live_evidence"]["hyperdrive"]["id"],
            )],
        )

    def test_legacy_d1_binding_is_a_blocker_not_a_requirement(self) -> None:
        self.assertFalse(self.foundation["policy"]["allow_d1"])
        if self.wrangler.get("d1_databases"):
            self.assertIn(
                "worker_d1_cutover_incomplete",
                self.foundation["readiness_blockers"],
            )
            self.assertFalse(self.foundation["deployment_ready"])

    def test_retired_d1_bootstrap_cannot_be_routine_deploy(self) -> None:
        self.assertNotIn("scripts/cloudflare/deploy-v3.sh", self.workflow)
        bootstrap = (ROOT / "scripts/cloudflare/deploy-v3.sh").read_text(encoding="utf-8")
        self.assertIn("Legacy D1/bootstrap deployment has been retired", bootstrap)
        self.assertIn("exit 3", bootstrap)
        self.assertNotIn("wrangler d1 create", bootstrap)
        self.assertNotIn("wrangler deploy", bootstrap)


if __name__ == "__main__":
    unittest.main()
