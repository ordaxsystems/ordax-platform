"""Canonical SQL contract: concurrent retries never race past idempotency lookup.

This is a source-level regression. Live concurrent transaction and Hyperdrive
behavior must still be proved separately before production rollout.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "control-plane/supabase/migrations/20261007212500_product_owner_auth_eligibility_v1.sql"
MIGRATION = ROOT / "control-plane/supabase/migrations/20261101111000_product_action_enqueue_concurrent_idempotency_v1.sql"
INITIAL = ROOT / "control-plane/supabase/migrations/20261007150000_product_remote_authority_v1.sql"
FUNCTION = "create or replace function public.ordax_enqueue_product_action_v1"
END = "$function$\n;"
LOCK_START = "  -- The Auth eligibility helper takes FOR SHARE locks:"
LOOKUP = "  select *\n    into v_existing\n    from private.ordax_product_action_requests"


def function_definition(sql: str) -> str:
    lower = sql.lower()
    start = lower.find(FUNCTION)
    if start < 0:
        raise AssertionError("canonical enqueue function missing")
    end = lower.find(END, start)
    if end < 0:
        raise AssertionError("canonical enqueue function not terminated")
    return sql[start:end + len(END)]


class ProductActionConcurrentIdempotencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = function_definition(BASE.read_text(encoding="utf-8"))
        cls.migration = MIGRATION.read_text(encoding="utf-8")
        cls.updated = function_definition(cls.migration)

    def test_only_advisory_serialization_added_to_canonical_rpc(self):
        original = self.original.lower()
        updated = self.updated.lower()
        start = updated.index(LOCK_START.lower())
        lookup = updated.index(LOOKUP.lower())
        self.assertLess(start, lookup)
        # No ad-hoc new execution backend, ACL mutation or altered grant logic:
        # byte-for-byte the original SQL body remains after removing the lock.
        self.assertEqual(updated[:start] + updated[lookup:], original)

    def test_owner_and_key_lock_before_read_and_unique_insert(self):
        sql = self.updated.lower()
        lock = sql.index("perform pg_catalog.pg_advisory_xact_lock(")
        owner_key = sql.index("pg_catalog.hashtextextended(p_owner_user_id::text || ':' || p_idempotency_key, 0)")
        lookup = sql.index("idempotency_key = p_idempotency_key")
        grant = sql.index("private.ordax_resolve_product_remote_grant_v1(")
        insert = sql.index("insert into private.ordax_product_action_requests(")
        self.assertLess(lock, owner_key)
        self.assertLess(owner_key, lookup)
        self.assertLess(lookup, grant)
        self.assertLess(grant, insert)
        self.assertEqual(sql.count("pg_catalog.pg_advisory_xact_lock("), 1)
        self.assertEqual(sql.count("insert into private.ordax_product_action_requests("), 1)
        base = INITIAL.read_text(encoding="utf-8").lower()
        self.assertIn("unique (owner_user_id, idempotency_key)", base)

    def test_replay_still_requires_exact_owner_client_scope_and_payload(self):
        sql = self.updated.lower()
        for clause in (
            "private.ordax_trusted_actor_auth_eligible_v1(p_owner_user_id)",
            "v_existing.space_id is not distinct from p_space_id",
            "v_existing.project_id is not distinct from p_project_id",
            "v_existing.device_id = p_device_id",
            "v_existing.client_kind = p_client_kind",
            "v_existing.client_id = p_client_id",
            "v_existing.capability = p_capability",
            "v_existing.access_mode = p_access_mode",
            "v_existing.payload_sha256 = v_payload_sha256",
            "'replayed', true",
            "'idempotency_conflict'",
        ):
            self.assertIn(clause, sql)

    def test_migration_fails_closed_on_schema_and_acl_drift(self):
        sql = self.migration.lower()
        self.assertTrue(sql.startswith("-- serialize concurrent product"))
        self.assertIn("begin;", sql)
        self.assertTrue(sql.strip().endswith("commit;"))
        self.assertIn("do $preflight$", sql)
        self.assertIn("do $postflight$", sql)
        self.assertIn("pg_catalog.to_regprocedure(", sql)
        self.assertIn("pg_catalog.pg_get_functiondef(", sql)
        self.assertIn("has_function_privilege('ordax_edge_executor'", sql)
        for role in ("authenticated", "anon", "service_role"):
            self.assertIn(f"has_function_privilege('{role}'", sql)
        self.assertNotIn("create table ", sql)
        self.assertNotIn("create role ", sql)
        self.assertNotIn("grant execute ", sql)
        self.assertNotIn("drop function ", sql)
        self.assertNotIn("delete from ", sql)


if __name__ == "__main__":
    unittest.main()
