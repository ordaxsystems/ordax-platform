from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "control-plane" / "supabase" / "migrations" / "20261007154000_product_device_identity_v1.sql"
ADAPTER = ROOT / "control-plane" / "cloudflare" / "src" / "product_postgres_store.ts"


class ProductPostgresDeviceIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sql = MIGRATION.read_text(encoding="utf-8")
        cls.adapter = ADAPTER.read_text(encoding="utf-8")

    def test_owner_device_scope_does_not_require_space_or_project(self) -> None:
        lowered = self.sql.lower()
        self.assertIn(
            "alter table public.ordax_remote_capability_grants\n  alter column space_id drop not null",
            lowered,
        )
        self.assertIn(
            "alter table private.ordax_product_action_requests\n  alter column space_id drop not null",
            lowered,
        )
        self.assertIn("scope_kind = 'device'", lowered)
        self.assertIn("and project_id is null", lowered)
        self.assertIn("scope_kind = 'project'", lowered)
        self.assertIn("and space_id is not null", lowered)
        self.assertIn("d.owner_user_id = p_owner_user_id", lowered)
        self.assertIn("g.space_id is not distinct from p_space_id", lowered)

    def test_product_credentials_are_private_hashes_only(self) -> None:
        lowered = self.sql.lower()
        self.assertIn(
            "create table if not exists private.ordax_product_device_credentials",
            lowered,
        )
        self.assertIn("token_sha256 text not null unique", lowered)
        self.assertIn("machine_binding_sha256 text not null unique", lowered)
        self.assertIn(
            "alter table private.ordax_product_device_credentials enable row level security",
            lowered,
        )
        self.assertIn(
            "revoke all on table private.ordax_product_device_credentials",
            lowered,
        )
        self.assertNotIn("raw_token", lowered)
        self.assertNotIn("token_plaintext", lowered)
        self.assertNotIn("references public.ordax_device_credentials", lowered)

    def test_device_identity_rpcs_are_service_only(self) -> None:
        for rpc in (
            "ordax_enroll_product_device_v1",
            "ordax_identify_product_device_v1",
            "ordax_authenticate_product_device_v1",
        ):
            self.assertIn(f"create or replace function public.{rpc}", self.sql.lower())
            self.assertIn(f"grant execute on function public.{rpc}", self.sql.lower())
        self.assertIn("from public, anon, authenticated", self.sql.lower())
        self.assertIn("to service_role;", self.sql.lower())

    def test_enrollment_is_owner_bound_and_rate_limited(self) -> None:
        lowered = self.sql.lower()
        self.assertIn("device_owner_mismatch", lowered)
        self.assertIn("enrollment_rate_limited", lowered)
        self.assertIn("interval '1 hour'", lowered)
        self.assertIn("v_next_count > 10", lowered)
        self.assertIn("pg_advisory_xact_lock", lowered)

    def test_product_setup_uses_only_canonical_postgres_identity(self) -> None:
        setup = (ROOT / "control-plane/cloudflare/src/product_device_setup.ts").read_text(
            encoding="utf-8",
        )
        entry = (ROOT / "control-plane/cloudflare/src/product_mcp_entry.ts").read_text(
            encoding="utf-8",
        )
        self.assertIn("handleProductDeviceSetup(request, env)", entry)
        self.assertIn("identifyProductDevice(env,", setup)
        self.assertIn("enrollProductDevice(env,", setup)
        self.assertIn("ownerUserId: identity.subjectId", setup)
        self.assertIn("DEVICE_KINDS", setup)
        self.assertIn("CHANNELS", setup)
        self.assertIn("sha256Text(rawToken)", setup)
        self.assertIn("ProductPostgresError", setup)
        self.assertIn("enrollment_rate_limited: 429", setup)
        self.assertNotIn("env.DB", setup)
        self.assertNotIn("ENROLLMENT_SESSIONS", entry)

    def test_product_enrollment_uses_one_canonical_worker_and_no_database_d1(self):
        import tomllib
        self.assertFalse((ROOT / "control-plane/cloudflare/wrangler.toml").exists())
        self.assertFalse((ROOT / "control-plane/cloudflare/wrangler.ci.toml").exists())
        with (ROOT / "control-plane/cloudflare/wrangler.mcp.toml").open("rb") as stream:
            config = tomllib.load(stream)
        self.assertEqual(config["name"], "ordax-mcp")
        self.assertEqual(config["main"], "src/product_mcp_entry.ts")
        self.assertFalse(config.get("d1_databases", []))
        self.assertFalse(config.get("r2_buckets", []))
        self.assertEqual(config["durable_objects"]["bindings"], [{
            "name": "DEVICE_WAKE", "class_name": "ProductDeviceWake",
        }])
        self.assertFalse(any(
            "EnrollmentSession" in item.get("new_sqlite_classes", [])
            for item in config.get("migrations", [])
        ))

    def test_legacy_d1_source_and_config_are_physically_absent(self):
        from scripts.cloudflare.check_mcp_release import (
            SOURCES, d1_source_names, worker_source_texts,
        )
        self.assertFalse((SOURCES / "index.ts").exists())
        self.assertFalse((ROOT / "control-plane/cloudflare/d1-cutover-authority-map.json").exists())
        self.assertEqual(d1_source_names(worker_source_texts(SOURCES)), set())
        entry = (SOURCES / "product_mcp_entry.ts").read_text(encoding="utf-8")
        self.assertIn("handleProductDeviceSetup", entry)
        self.assertIn("PRODUCT_DEVICE_SETUP_PATH", entry)

    def test_worker_adapter_exposes_hash_only_device_methods(self) -> None:
        for method in (
            "enrollProductDevice",
            "identifyProductDevice",
            "authenticateProductDevice",
        ):
            self.assertIn(f"function {method}", self.adapter)
        for rpc in (
            "ordax_enroll_product_device_v1",
            "ordax_identify_product_device_v1",
            "ordax_authenticate_product_device_v1",
        ):
            self.assertIn(rpc, self.adapter)
        self.assertNotIn("importLegacyProductDevice", self.adapter)
        self.assertNotIn("ordax_import_legacy_product_device_v1", self.adapter)
        lowered = self.adapter.lower()
        self.assertIn("tokensha256", lowered)
        self.assertIn("machinebindingsha256", lowered)
        self.assertNotIn("rawtoken", lowered)


if __name__ == "__main__":
    unittest.main()
