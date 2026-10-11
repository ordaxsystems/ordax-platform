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


class CanonicalProductPluginTest(unittest.TestCase):
    def test_ssot_build_requires_postgres_and_read_only_tools(self):
        url, files = plugin_build.build_files()
        self.assertEqual(
            url,
            "https://ordax-control-plane-v3-canary.ordaxsystems.workers.dev/mcp",
        )
        self.assertEqual(set(files), {
            "plugin.json", "mcp.json", ".mcp.json", ".codex-plugin/plugin.json",
        })
        definition = json.loads(files["plugin.json"])
        self.assertEqual(definition["name"], "ordax-product-canary")
        self.assertEqual(definition["version"], "0.1.0")
        self.assertEqual(definition["extensions"]["com.openai"]["interface"]["capabilities"], ["Read"])
        for file_path in ("mcp.json", ".mcp.json"):
            mcp = json.loads(files[file_path])
            self.assertEqual(mcp["mcpServers"]["ordax-product-canary"]["url"], url)
        all_text = b"\n".join(files.values()).decode("utf-8")
        self.assertNotIn("ordax-ac1ca1b50d09", all_text)
        self.assertNotIn("service_role", all_text)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", all_text)
        self.assertNotIn("localhost", all_text)
        self.assertNotIn("computer-control", all_text)

    def test_zip_is_reproducible_and_contains_one_plugin(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)
            one, two = output / "one.zip", output / "two.zip"
            for target in (one, two):
                process = subprocess.run(
                    [sys.executable, str(SCRIPT), "--out", str(target)],
                    capture_output=True, text=True, timeout=20, check=True,
                )
                self.assertIn("ORDAX_CANONICAL_CHATGPT_PLUGIN=PACKAGED", process.stdout)
            self.assertEqual(one.read_bytes(), two.read_bytes())
            with zipfile.ZipFile(one) as archive:
                self.assertEqual(set(archive.namelist()), {
                    "plugin.json", "mcp.json", ".mcp.json", ".codex-plugin/plugin.json",
                })
                self.assertEqual(
                    json.loads(archive.read("plugin.json"))["version"], "0.1.0",
                )


if __name__ == "__main__":
    unittest.main()
