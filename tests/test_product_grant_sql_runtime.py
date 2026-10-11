"""P0: execute the ACTUAL legacy Product grant SELECT, not a copied predicate.

This does not assert a remote Worker has been deployed. The live, older MCP
deployment is still tracked by issue #118; use its own OAuth session for the
post-deployment negative proof. All identifiers below are synthetic.
"""
from __future__ import annotations

import json
import re
import sqlite3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "control-plane/cloudflare/src/index.ts"
MCP = ROOT / "control-plane/cloudflare/src/mcp_http.ts"
SUBJECT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
DEVICE = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
OTHER_DEVICE = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
SPACE_1 = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
SPACE_2 = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
NOW = "2026-10-11T21:00:00.000Z"


def worker_grant_select() -> str:
    text = WORKER.read_text(encoding="utf-8")
    start = text.index("async function resolveProductGrantForContext(")
    stop = text.index("async function resolveProductGrantAdmin(", start)
    body = text[start:stop]
    found = re.search(
        r"env\.DB\.prepare\(\s*`(SELECT id, subject_id, space_id, device_id, "
        r"actions_json, projects_json,[\s\S]*?LIMIT 100)`\s*,?\s*\)",
        body,
    )
    if not found:
        raise AssertionError("Could not extract canonical grant SELECT from actual Worker")
    return found.group(1)


class ProductLiveSpaceSqlContract(unittest.TestCase):
    def setUp(self) -> None:
        self.database = sqlite3.connect(":memory:")
        self.database.row_factory = sqlite3.Row
        self.database.execute(
            """CREATE TABLE ordax_product_grants(
                id TEXT PRIMARY KEY, subject_id TEXT NOT NULL,
                space_id TEXT NULL, device_id TEXT NOT NULL,
                actions_json TEXT NOT NULL, projects_json TEXT NOT NULL,
                expires_at TEXT NULL, created_at TEXT NOT NULL,
                revoked_at TEXT NULL
            )"""
        )
        self.source_query = worker_grant_select()

    def tearDown(self) -> None:
        self.database.close()

    def add(
        self, grant_id: str, space_id: str | None, *,
        device_id: str = DEVICE, subject_id: str = SUBJECT,
        revoked_at: str | None = None, expires_at: str | None = None,
        actions: list[str] | None = None,
    ) -> None:
        self.database.execute(
            "INSERT INTO ordax_product_grants("
            "id, subject_id, space_id, device_id, actions_json, projects_json,"
            "expires_at, created_at, revoked_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (grant_id, subject_id, space_id, device_id,
             json.dumps(actions or ["computer.screen_info"]), "[]",
             expires_at, "2026-10-10T10:00:00.000Z", revoked_at),
        )

    def resolve(
        self, space_id: str | None, *,
        subject_id: str = SUBJECT, device_id: str = DEVICE,
    ) -> list[dict]:
        return [
            dict(row)
            for row in self.database.execute(
                self.source_query, (subject_id, NOW, device_id, space_id)
            ).fetchall()
        ]

    def test_authorized_unscoped_request_can_use_exact_unscoped_grant(self) -> None:
        self.add("global", None)
        self.assertEqual([row["id"] for row in self.resolve(None)], ["global"])

    def test_real_bug_reproduction_unauthorized_explicit_space_denied_with_global_grant(self) -> None:
        self.add("global", None)
        # Matches the live MCP failure: real device and existing global grant,
        # but an explicit, syntactically valid UUID not present in any grant.
        self.assertEqual(self.resolve(SPACE_2), [])
        # A mere string argument is not grant authority, even if UUID-shaped.
        self.assertEqual(self.resolve("some-other-space"), [])

    def test_explicit_space_only_uses_same_space_grant_not_global_fallback(self) -> None:
        self.add("global", None)
        self.add("scoped-1", SPACE_1)
        self.assertEqual([x["id"] for x in self.resolve(SPACE_1)], ["scoped-1"])
        self.assertEqual(self.resolve(SPACE_2), [])
        self.assertEqual([x["id"] for x in self.resolve(None)], ["global"])

    def test_revoked_expired_and_unrelated_grants_cannot_resurrect_global_fallback(self) -> None:
        self.add("global", None)
        self.add("revoked", SPACE_1, revoked_at="2026-10-11T20:59:59.000Z")
        self.add("expired", SPACE_1, expires_at="2026-10-10T22:00:00.000Z")
        self.add("another-device", SPACE_1, device_id=OTHER_DEVICE)
        self.add("another-subject", SPACE_1, subject_id="ffffffff-ffff-4fff-8fff-ffffffffffff")
        self.assertEqual(self.resolve(SPACE_1), [])
        self.assertEqual([x["id"] for x in self.resolve(None)], ["global"])

    def test_live_postflight_checks_installed_resolver_not_just_migration_text(self) -> None:
        postflight = (
            ROOT / "control-plane/supabase/tests/"
            "product_client_grant_isolation_postflight.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("pg_catalog.pg_get_functiondef(v_new_resolver::oid)", postflight)
        self.assertIn("pg_catalog.pg_get_functiondef(v_new_rpc::oid)", postflight)
        self.assertIn("g.space_id is not distinct from p_space_id", postflight)
        self.assertIn("v_existing.space_id is not distinct from p_space_id", postflight)
        self.assertIn("and g.client_id = p_client_id", postflight)
        self.assertIn("v_existing.client_id = p_client_id", postflight)
        self.assertIn("g.valid_until > pg_catalog.clock_timestamp()", postflight)
        self.assertIn("product_space_contract_wildcard_or_revocation_regression", postflight)
        self.assertIn("g.state = ''active''", postflight)
        self.assertIn("d.state = ''active''", postflight)

    def test_source_grant_query_uses_same_scope_as_mcp_input_without_silent_fallback(self) -> None:
        # Keep the actual Worker SELECT and actual MCP command transport linked.
        # A test of copied SQL would miss a future regression in either one.
        body = MCP.read_text(encoding="utf-8")
        self.assertIn(
            'const spaceId = typeof args.space_id === "string" ? args.space_id : null;',
            body,
        )
        self.assertIn('space_id: spaceId,', body)
        self.assertIn('await handlers.createAction(createRequest)', body)
        self.assertIn('AND ((space_id IS NULL AND ?4 IS NULL) OR space_id = ?4)', self.source_query)
        self.assertNotIn('space_id IS NULL OR space_id = ?4', self.source_query)
        self.assertNotIn('COALESCE(space_id', self.source_query)


if __name__ == "__main__":
    unittest.main()
