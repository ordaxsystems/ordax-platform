#!/usr/bin/env python3
"""One fail-closed compiled-bundle check for the single canonical OrdaX MCP Worker.

Used by source CI, the candidate gate and production validation. Never
deploys, mutates Cloudflare, or creates an alternative auth/queue authority.
"""
from pathlib import Path
import sys

FORBIDDEN = (
    "D1Database",
    "env.DB.prepare",
    "operatorAuthorized(",
    "ordax-control-plane-v3",
    "legacy_mcp_retired",
)
REQUIRED = (
    "trusted_operation_required",
    "attested-device-control",
    "computer-observe",
    "interactive-computer-control",
    "ordax_action_status",
    "computer.click",
    "computer.type",
    "ordax-mcp.ordaxsystems.workers.dev",
    "/v3/product/session",
    "/v3/device/setup",
    "/v3/product/device/central-session",
    "/v3/device/transport",
    "/v3/owner/remote-authority",
    "/v3/owner/remote-grant-groups",
)


def check_bundle(directory: Path) -> None:
    scripts = sorted(directory.glob("*.js"))
    if len(scripts) != 1:
        raise ValueError(f"Expected exactly one canonical MCP bundle: {scripts}")
    code = scripts[0].read_text(encoding="utf-8")
    for forbidden in FORBIDDEN:
        if forbidden in code:
            raise ValueError(f"Retired/unsafe Worker authority bundled: {forbidden}")
    for required in REQUIRED:
        if required not in code:
            raise ValueError(f"Canonical MCP contract missing in bundle: {required}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: assert_canonical_mcp_bundle.py <dry-run-output-directory>")
    try:
        check_bundle(Path(sys.argv[1]))
    except (ValueError, OSError) as exc:
        raise SystemExit(str(exc)) from exc
    print("ORDAX_CANONICAL_MCP_ATTESTED_INTERACTIVE=PASS")
    print("ORDAX_MCP_TRUSTED_CLIENT_INGRESS_GUARD=PASS")
