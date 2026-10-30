"""Ensure a blocked production deployment names every canonical blocker.

This test never changes infrastructure and remains valid once readiness is true.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FOUNDATION = ROOT / "control-plane/cloudflare/production-foundation.json"
SCRIPT = ROOT / "scripts/cloudflare/check_deploy_readiness.py"


class ProductionReadinessOutputTests(unittest.TestCase):
    def test_blockers_are_explicit_without_authorizing_deploy(self):
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--allow-blocked"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        blockers = foundation["readiness_blockers"]
        if foundation["deployment_ready"]:
            self.assertIn("deployment READY", result.stdout)
            self.assertEqual(blockers, [])
        else:
            self.assertIn(f"BLOCKED ({len(blockers)} blockers)", result.stdout)
            self.assertEqual(
                [line.strip().removeprefix("BLOCKER: ") for line in result.stdout.splitlines()
                 if line.strip().startswith("BLOCKER: ")],
                blockers,
            )

    def test_direct_deploy_stays_blocked(self):
        foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0 if foundation["deployment_ready"] else 3)
        if not foundation["deployment_ready"]:
            self.assertIn("BLOCKER:", result.stdout)


if __name__ == "__main__":
    unittest.main()
