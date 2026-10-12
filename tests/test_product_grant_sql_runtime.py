"""P0: the installed Product PostgreSQL RPC is the only grant resolver.

The historic D1 SELECT has been deleted; exercising a synthetic SQLite
copy would test a removed authority, so this suite instead guards the real
PostgreSQL RPC source and its already deployed read-only postflight.
A live postflight must be run against Supabase to prove the installed body.
"""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
MIGRATION=(ROOT/"control-plane/supabase/migrations/20261007203000_product_client_grant_isolation_v1.sql").read_text("utf-8").lower()
POSTFLIGHT=(ROOT/"control-plane/supabase/tests/product_client_grant_isolation_postflight.sql").read_text("utf-8").lower()
LEGACY=(ROOT/"control-plane/cloudflare/src/index.ts").read_text("utf-8")
STORE=(ROOT/"control-plane/cloudflare/src/product_postgres_store.ts").read_text("utf-8")

class ProductCanonicalGrantContract(unittest.TestCase):
    def test_legacy_d1_grant_resolver_removed(self):
        for name in (
            "async function resolveProductGrantForContext(",
            "async function resolveProductGrantAdmin(",
            "async function createProductGrant(",
            "async function revokeProductGrant(",
        ):
            self.assertNotIn(name,LEGACY)
        self.assertIn('error: "legacy_product_grants_retired"',LEGACY)

    def test_exact_space_and_client_in_postgres_resolver(self):
        for predicate in (
            "and g.client_id = p_client_id",
            "and g.space_id is not distinct from p_space_id",
            "and g.device_id = p_device_id",
            "and g.owner_user_id = p_owner_user_id",
            "and g.client_kind = p_client_kind",
            "and g.access_mode = p_access_mode",
        ):
            self.assertIn(predicate,MIGRATION)
        self.assertNotIn("g.space_id is null or g.space_id = p_space_id",MIGRATION)

    def test_null_space_only_for_device_grant_and_project_is_exact(self):
        self.assertIn("g.scope_kind = 'device'",MIGRATION)
        self.assertIn("and p_project_id is null",MIGRATION)
        self.assertIn("g.scope_kind = 'project'",MIGRATION)
        self.assertIn("and p_space_id is not null",MIGRATION)
        self.assertIn("and g.project_id = p_project_id",MIGRATION)
        self.assertIn("and sd.state = 'active'",MIGRATION)
        self.assertIn("and b.state = 'active'",MIGRATION)

    def test_revoked_expired_foreign_device_grants_cannot_authorize(self):
        self.assertIn("and g.state = 'active'",MIGRATION)
        self.assertIn("and d.state = 'active'",MIGRATION)
        self.assertIn("g.valid_until > pg_catalog.clock_timestamp()",MIGRATION)
        self.assertIn("and g.device_id = p_device_id",MIGRATION)

    def test_enqueue_rpc_rechecks_exact_client_and_request_id(self):
        self.assertIn("v_existing.client_id = p_client_id",MIGRATION)
        self.assertIn("v_existing.space_id is not distinct from p_space_id",MIGRATION)
        self.assertIn("drop function public.ordax_enqueue_product_action_v1(",MIGRATION)
        self.assertIn("if (!client || client.p_client_id === null)",STORE)

    def test_postflight_checks_installed_definitions_not_copied_sql(self):
        for required in (
            "pg_catalog.pg_get_functiondef(v_new_resolver::oid)",
            "pg_catalog.pg_get_functiondef(v_new_rpc::oid)",
            "g.space_id is not distinct from p_space_id",
            "v_existing.space_id is not distinct from p_space_id",
            "and g.client_id = p_client_id",
            "v_existing.client_id = p_client_id",
            "g.valid_until > pg_catalog.clock_timestamp()",
            "product_space_contract_wildcard_or_revocation_regression",
            "g.state = ''active''",
            "d.state = ''active''",
        ):
            self.assertIn(required,POSTFLIGHT)

if __name__=="__main__":
    unittest.main()
