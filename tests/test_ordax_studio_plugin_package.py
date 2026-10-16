from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts.build_ordax_plugin import (
    LEGACY_MCP_ENDPOINT,
    PluginDistributionBlocked,
    build_archive,
    canonical_mcp_endpoint,
    distribution_readiness,
    validate_package,
)

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "plugins" / "ordax-chatgpt"
READY = {
    "schema": "ordax.chatgpt-plugin-distribution-readiness/1",
    "ready": True,
    "endpoint": "https://mcp.ordax.com.br/mcp",
    "supports_remote_actions": True,
    "blockers": [],
    "foundation_version": 23,
}


class OrdaxChatGptConnectorPackageTests(unittest.TestCase):
    def test_portable_plugin_manifest_is_valid(self):
        manifest = json.loads((PLUGIN_ROOT / "plugin.json").read_text(encoding="utf-8-sig"))
        self.assertEqual(manifest["name"], "ordax-chatgpt")
        self.assertEqual(manifest["repository"], "https://github.com/ordaxsystems/ordax-platform")
        self.assertEqual(
            manifest["extensions"]["com.openai"]["interface"]["displayName"],
            "ORDAX Studio",
        )
        interface = manifest["extensions"]["com.openai"]["interface"]
        self.assertIn("Computer Control", interface["capabilities"])
        self.assertIn("Owner-approved Full Computer Control", interface["capabilities"])
        self.assertIn("Persistent project context", interface["capabilities"])
        self.assertIn("Blender & Unity adapters", interface["capabilities"])
        self.assertNotIn("Development commands", interface["capabilities"])
        self.assertIn(
            "Continue working on my ORDAX project from where we left off.",
            interface["defaultPrompt"],
        )
        self.assertIn("durable project continuity", interface["longDescription"])
        self.assertIn("does not own ORDAX Studio", interface["longDescription"])
        self.assertIn("Full Access", interface["longDescription"])
        self.assertIn("cannot mint its own grants", interface["longDescription"])

    def test_package_version_matches_canonical_manifest(self):
        manifest = json.loads((PLUGIN_ROOT / "plugin.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory, patch(
            "scripts.build_ordax_plugin.distribution_readiness", return_value=READY
        ):
            archive, _ = build_archive(Path(directory))
            self.assertEqual(archive.name, f"ordax-chatgpt-plugin-{manifest['version']}.zip")

    def test_connector_has_single_authoritative_source_tree(self):
        self.assertTrue(PLUGIN_ROOT.is_dir())
        self.assertFalse((ROOT / "plugins" / "ordax-studio").exists())

    def test_plugin_uses_canonical_product_mcp_endpoint(self):
        config = json.loads((PLUGIN_ROOT / "mcp.json").read_text(encoding="utf-8-sig"))
        server = config["mcpServers"]["ordax"]
        self.assertEqual(server["type"], "streamable-http")
        self.assertEqual(server["url"], canonical_mcp_endpoint())
        self.assertEqual(server["url"], "https://mcp.ordax.com.br/mcp")
        self.assertNotEqual(server["url"], LEGACY_MCP_ENDPOINT)

    def test_distribution_remains_blocked_while_interactive_candidate_is_enabled(self):
        readiness = distribution_readiness()
        self.assertFalse(readiness["ready"])
        self.assertTrue(readiness["supports_remote_actions"])
        self.assertIn("canonical_remote_actions_release_not_verified", readiness["blockers"])
        self.assertIn("attested_interactive_end_to_end_not_verified", readiness["blockers"])
        self.assertIn("interactive_computer_grant_not_authorized", readiness["blockers"])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(PluginDistributionBlocked):
                build_archive(Path(directory))
            self.assertEqual(list(Path(directory).glob("*.zip")), [])

    def test_builder_rejects_retired_legacy_mcp_endpoint(self):
        legacy = {
            "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
            "mcpServers": {
                "ordax": {"type": "streamable-http", "url": LEGACY_MCP_ENDPOINT}
            },
        }
        with patch("scripts.build_ordax_plugin.load_mcp_config", return_value=legacy):
            with self.assertRaisesRegex(ValueError, "retired legacy MCP endpoint"):
                validate_package()

    def test_manifests_are_utf8_without_bom(self):
        for name in ("plugin.json", "mcp.json"):
            self.assertFalse((PLUGIN_ROOT / name).read_bytes().startswith(b"\xef\xbb\xbf"))

    def test_builder_rejects_invalid_version_subtitle_and_prompt_count(self):
        original = json.loads((PLUGIN_ROOT / "plugin.json").read_text(encoding="utf-8"))
        for field, value in (("version", "../escape"), ("shortDescription", "x" * 31), ("defaultPrompt", ["one"] * 4)):
            manifest = json.loads(json.dumps(original))
            target = manifest if field == "version" else manifest["extensions"]["com.openai"]["interface"]
            target[field] = value
            with self.subTest(field=field), patch("scripts.build_ordax_plugin.load_manifest", return_value=manifest):
                with self.assertRaises(ValueError):
                    validate_package()

    def test_builder_produces_deterministic_portable_zip_when_release_is_ready(self):
        with tempfile.TemporaryDirectory() as directory, patch(
            "scripts.build_ordax_plugin.distribution_readiness", return_value=READY
        ):
            first, first_sha = build_archive(Path(directory) / "a")
            second, second_sha = build_archive(Path(directory) / "b")
            self.assertEqual(first_sha, second_sha)
            self.assertTrue(first.name.startswith("ordax-chatgpt-plugin-"))
            with zipfile.ZipFile(first) as bundle:
                self.assertEqual(
                    sorted(bundle.namelist()),
                    ["ordax-chatgpt/assets/ordax.svg", "ordax-chatgpt/mcp.json", "ordax-chatgpt/plugin.json"],
                )

    def test_builder_removes_legacy_package_names_when_release_is_ready(self):
        with tempfile.TemporaryDirectory() as directory, patch(
            "scripts.build_ordax_plugin.distribution_readiness", return_value=READY
        ):
            output = Path(directory)
            for stem in ("ordax-dev-plugin-0.4.1", "ordax-studio-plugin-0.4.1"):
                (output / f"{stem}.zip").write_bytes(b"legacy")
                (output / f"{stem}.zip.sha256").write_text("legacy\n", encoding="ascii")
            build_archive(output)
            self.assertFalse(any(output.glob("ordax-dev-plugin-*")))
            self.assertFalse(any(output.glob("ordax-studio-plugin-*")))

    def test_public_submission_metadata_is_complete(self):
        manifest = json.loads((PLUGIN_ROOT / "plugin.json").read_text(encoding="utf-8"))
        interface = manifest["extensions"]["com.openai"]["interface"]
        self.assertLessEqual(len(interface["displayName"]), 30)
        self.assertLessEqual(len(interface["shortDescription"]), 30)
        self.assertLessEqual(len(interface["defaultPrompt"]), 3)
        for field in ("websiteURL", "supportURL", "privacyPolicyURL", "termsOfServiceURL"):
            self.assertTrue(interface[field].startswith("https://"))
        self.assertEqual(interface["composerIcon"], "./assets/ordax.svg")
        self.assertEqual(interface["logo"], "./assets/ordax.svg")
        review = manifest["extensions"]["com.openai"]["review"]["test_cases"]
        self.assertEqual(len(review["positive"]), 7)
        self.assertEqual(len(review["negative"]), 6)
        self.assertTrue(
            any("computer_screenshot" in case.get("tools_triggered", "") for case in review["positive"])
        )
        self.assertTrue(
            any("computer_launch_app" in case.get("tools_triggered", "") for case in review["positive"])
        )
        self.assertTrue(any("powershell.exe" in case.get("prompt", "") for case in review["negative"]))

    def test_review_write_targets_only_approved_document_directory(self):
        manifest = json.loads((PLUGIN_ROOT / "plugin.json").read_text(encoding="utf-8"))
        scenarios = manifest["extensions"]["com.openai"]["review"]["test_cases"]["positive"]
        write_cases = [case for case in scenarios if "project_text_write" in case.get("tools_triggered", "")]
        self.assertEqual(len(write_cases), 1)
        self.assertIn("docs/review-output.txt", write_cases[0]["prompt"])
        self.assertNotIn("Create review-output.txt in ", write_cases[0]["prompt"])
        review_docs = (ROOT / "docs" / "OPENAI_PLUGIN_REVIEW.md").read_text(encoding="utf-8")
        self.assertIn("available: true", review_docs)
        self.assertIn("docs/review-output.txt", review_docs)
        self.assertIn("expected_sha256", review_docs)

    def test_submission_assets_are_present(self):
        self.assertTrue((PLUGIN_ROOT / "assets" / "ordax.svg").is_file())


if __name__ == "__main__":
    unittest.main()
