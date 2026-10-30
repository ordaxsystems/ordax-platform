import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "control-plane" / "supabase" / "migration-registry.json"
ARCHIVE = ROOT / "control-plane" / "supabase" / "applied-ledger"


class AppliedSupabaseLedgerRegistryTests(unittest.TestCase):
    """Fail closed on missing or tampered historical applied migration evidence."""

    @classmethod
    def setUpClass(cls):
        cls.registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        cls.entries = cls.registry["migrations"]

    def test_complete_applied_ledger_baseline_and_exact_names(self):
        self.assertEqual(self.registry["canonical_database"]["project_ref"], "jhfphsjptrpmtnzkpwud")
        self.assertIs(self.registry["policy"]["reapply_applied_migration_allowed"], False)
        self.assertIs(self.registry["policy"]["applied_migrations_are_immutable"], True)
        self.assertGreaterEqual(len(self.entries), 82)
        names = [entry.get("ledger_name", entry["name"]) for entry in self.entries]
        versions = [entry["applied_version"] for entry in self.entries]
        self.assertEqual(len(names), len(set(names)), "duplicate live ledger name")
        self.assertEqual(len(versions), len(set(versions)), "duplicate applied ledger version")
        self.assertTrue(all(entry["state"] == "applied" for entry in self.entries))
        self.assertTrue(all(re.fullmatch(r"\d{14}", str(v)) for v in versions))

        aliases = [entry for entry in self.entries if "ledger_name" in entry]
        self.assertGreaterEqual(len(aliases), 16)
        for entry in aliases:
            self.assertEqual(re.sub(r"^\d{14}_", "", entry["name"]), entry["ledger_name"])
            self.assertNotEqual(entry["name"], entry["ledger_name"])

    def test_recovered_sql_is_immutable_and_byte_exact_to_canonical_ledger(self):
        recovered = [entry for entry in self.entries if "recovered_from" in entry]
        self.assertEqual(len(recovered), 17)
        for entry in recovered:
            with self.subTest(name=entry["name"]):
                source = entry["source"]
                self.assertEqual(source["repository"], "ordaxsystems/ordax-platform")
                path = (ROOT / source["path"]).resolve()
                self.assertTrue(path.is_relative_to(ROOT))
                self.assertTrue(path.is_file(), source["path"])
                raw = path.read_bytes()
                git_blob_sha = hashlib.sha1(
                    b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
                ).hexdigest()
                self.assertEqual(source["blob_sha"], git_blob_sha)
                self.assertEqual(
                    entry["recovered_from"]["statement_md5"],
                    hashlib.md5(raw).hexdigest(),
                )
                self.assertEqual(
                    entry["recovered_from"]["relation"],
                    "supabase_migrations.schema_migrations",
                )
                self.assertEqual(entry["ledger_source_relation"], "exact")
                if entry["name"] == "20261007201000_artifact_authority_v1":
                    self.assertEqual(entry["recovered_from"]["kind"], "closed_pr_68_verified_against_ledger")
                    self.assertEqual(path.parent.name, "migrations")
                else:
                    self.assertEqual(entry["recovered_from"]["kind"], "supabase_applied_ledger_statement")
                    self.assertEqual(path.parent, ARCHIVE)
                    self.assertTrue(path.name.startswith(entry["applied_version"] + "_"))

    def test_archive_is_not_a_second_migration_executor(self):
        self.assertTrue((ARCHIVE / "README.md").is_file())
        content = (ARCHIVE / "README.md").read_text(encoding="utf-8")
        self.assertIn("Never apply/replay", content)
        self.assertEqual(
            len(tuple(ARCHIVE.glob("*.sql"))),
            16,
            "applied history must not silently grow outside the canonical registry",
        )


if __name__ == "__main__":
    unittest.main()
