import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/cloudflare/package_product_plugin.py"
MODULE_SPEC = importlib.util.spec_from_file_location("ordax_plugin_build", SCRIPT)
assert MODULE_SPEC and MODULE_SPEC.loader
plugin_build = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(plugin_build)


class PrivateProductInteractiveValidationPluginTest(unittest.TestCase):
    def test_ssot_build_uses_canonical_custom_domain_and_interactive_candidate(self):
        url, files = plugin_build.build_files()
        self.assertEqual(url, "https://mcp.ordax.com.br/mcp")
        self.assertEqual(
            set(files),
            {"plugin.json", "mcp.json", ".mcp.json", ".codex-plugin/plugin.json"},
        )
        definition = json.loads(files["plugin.json"])
        self.assertEqual(definition["name"], "ordax-product-canary")
        self.assertEqual(definition["version"], "0.3.0")
        self.assertEqual(
            definition["extensions"]["com.openai"]["interface"]["capabilities"],
            ["Read", "Computer Control"],
        )
        for file_path in ("mcp.json", ".mcp.json"):
            mcp = json.loads(files[file_path])
            packaged_url = mcp["mcpServers"]["ordax-product-canary"]["url"]
            self.assertEqual(packaged_url, url)
            self.assertNotIn("workers.dev", packaged_url)
            self.assertNotIn("ordax-control-plane-v3", packaged_url)
            self.assertNotIn("ordax-ac1ca1b50d09", packaged_url)
        all_text = b"\n".join(files.values()).decode("utf-8")
        self.assertNotIn("service_role", all_text)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", all_text)
        self.assertNotIn("localhost", all_text)
        self.assertIn("Computer Control", all_text)
        self.assertIn("grants explícitos", all_text)
        self.assertNotIn("filesystem", definition["extensions"]["com.openai"]["interface"]["capabilities"])

    def test_manifest_matches_complete_18_tool_validation_surface(self):
        manifest = json.loads(plugin_build.MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(manifest["worker_role"], "attested-interactive-validation")
        self.assertEqual(manifest["allowed_tools"], list(plugin_build.VALIDATION_TOOLS))
        self.assertEqual(len(manifest["allowed_tools"]), 18)
        for tool in (
            "computer_windows",
            "computer_screenshot",
            "computer_click",
            "computer_type",
            "computer_hotkey",
        ):
            self.assertIn(tool, manifest["allowed_tools"])
        for tool in ("terminal_exec", "browser_start", "project_text_write"):
            self.assertNotIn(tool, manifest["allowed_tools"])

    def test_zip_is_reproducible_and_contains_one_private_validation_plugin(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            one, two = output / "one.zip", output / "two.zip"
            for target in (one, two):
                process = subprocess.run(
                    [sys.executable, str(SCRIPT), "--out", str(target)],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=True,
                )
                self.assertIn(
                    "ORDAX_PRIVATE_INTERACTIVE_VALIDATION_PLUGIN=PACKAGED",
                    process.stdout,
                )
                self.assertIn("ENDPOINT=https://mcp.ordax.com.br/mcp", process.stdout)
            self.assertEqual(one.read_bytes(), two.read_bytes())
            with zipfile.ZipFile(one) as archive:
                self.assertEqual(
                    set(archive.namelist()),
                    {"plugin.json", "mcp.json", ".mcp.json", ".codex-plugin/plugin.json"},
                )
                self.assertEqual(
                    json.loads(archive.read("plugin.json"))["version"],
                    "0.3.0",
                )

    def test_package_fails_closed_if_candidate_or_e2e_state_is_wrong(self):
        foundation = json.loads(plugin_build.FOUNDATION.read_text(encoding="utf-8"))
        for mutate, expected in (
            (lambda release: release.__setitem__("supports_remote_actions", False), "requires remote actions"),
            (lambda release: release.__setitem__("validation_deployment_ready", False), "not deployable"),
            (lambda release: release.__setitem__("deployment_ready", True), "already-approved production"),
            (lambda release: release.__setitem__("readiness_blockers", []), "real E2E blocker"),
        ):
            candidate = json.loads(json.dumps(foundation))
            mutate(candidate["mcp_release"])
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, expected):
                plugin_build._canonical_endpoint(candidate)


if __name__ == "__main__":
    unittest.main()
