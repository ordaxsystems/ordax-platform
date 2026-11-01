#!/usr/bin/env bash
# The single contract-suite owner for all three MCP candidate/release gates.
# Node's test glob discovers new regressions automatically: no per-workflow
# copied allowlist can silently omit a new status, grant or wake test.
# This only validates the candidate; it never publishes a Worker.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

python -m unittest tests.test_mcp_candidate_suite_ssot tests.test_central_mcp_candidate_ci_contract

node --test control-plane/tests/*.test.mts control-plane/labs/relay/scoped-mcp.test.mts
