from __future__ import annotations

import re
import unittest
from pathlib import Path


class OpenAiPluginAnnotationEvidenceTests(unittest.TestCase):
    def test_every_public_tool_is_explicitly_classified_and_documented(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source = (root / 'control-plane' / 'cloudflare' / 'src' / 'mcp_http.ts').read_text(encoding='utf-8')
        evidence = (root / 'docs' / 'OPENAI_PLUGIN_ANNOTATION_EVIDENCE.md').read_text(encoding='utf-8')

        tools_start = source.index('const TOOLS: ToolSpec[] = [')
        tools_block = source[tools_start:source.index('];', tools_start)]
        tool_names = re.findall(r'name:\s*"([^"]+)"', tools_block)
        self.assertGreater(len(tool_names), 0)
        self.assertEqual(len(tool_names), len(set(tool_names)))

        tick = chr(96)
        for name in tool_names:
            with self.subTest(tool=name):
                self.assertIn('| ' + tick + name + tick + ' |', evidence)

        rows = re.findall(
            r'^\| `([^`]+)` \| (true|false) \| (true|false) \| (true|false) \|',
            evidence,
            re.MULTILINE,
        )
        self.assertEqual(set(tool_names), {row[0] for row in rows})
        self.assertIn('effectClassCount !== 1', source)
        self.assertIn('NON_DESTRUCTIVE_WRITE_TOOLS', source)

    def test_review_positive_prompts_use_the_single_canonical_mcp_tool_catalog(self) -> None:
        import json
        root = Path(__file__).resolve().parents[1]
        source = (root / "control-plane/cloudflare/src/mcp_http.ts").read_text(encoding="utf-8")
        tools_start = source.index("const TOOLS: ToolSpec[] = [")
        tools_block = source[tools_start:source.index("];", tools_start)]
        published = set(re.findall(r'name:\s*"([^"]+)"', tools_block))
        manifest = json.loads((root / "plugins/ordax-chatgpt/plugin.json").read_text(encoding="utf-8"))
        positive = manifest["extensions"]["com.openai"]["review"]["test_cases"]["positive"]
        self.assertGreater(len(positive), 0)
        for case in positive:
            invoked = [name.strip() for name in str(case.get("tools_triggered") or "").split(",") if name.strip()]
            self.assertTrue(invoked, case.get("description"))
            for name in invoked:
                with self.subTest(tool=name):
                    self.assertIn(name, published)


if __name__ == '__main__':
    unittest.main()
