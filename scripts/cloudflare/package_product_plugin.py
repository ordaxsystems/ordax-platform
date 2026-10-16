#!/usr/bin/env python3
"""Build the private ChatGPT interactive-validation package from Product SSOT.

This package is intentionally not the production-distribution connector. It uses
exactly the canonical Product MCP custom domain so OAuth, attested device
binding, owner grants and the first interactive-computer tranche can be proven
end to end before production distribution is enabled. It never deploys a
Worker, creates grants, or introduces a workers.dev/legacy fallback.
"""
from __future__ import annotations

import argparse
import json
import re
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "integrations/chatgpt/product-canary/manifest.json"
FOUNDATION = ROOT / "control-plane/cloudflare/production-foundation.json"
VALIDATION_TOOLS = (
    "ordax_session",
    "ordax_profile",
    "ordax_targets",
    "ordax_action_status",
    "computer_windows",
    "computer_active_window",
    "computer_screenshot",
    "computer_screen_info",
    "computer_focus_window",
    "computer_click",
    "computer_mouse_move",
    "computer_drag",
    "computer_launch_app",
    "computer_scroll",
    "computer_type",
    "computer_hotkey",
    "computer_access_status",
    "computer_processes",
)


def _canonical_endpoint(foundation: dict) -> str:
    release = foundation.get("mcp_release")
    if not isinstance(release, dict):
        raise ValueError("Canonical MCP release is missing")
    hostname = release.get("hostname")
    path = release.get("path")
    if not isinstance(hostname, str) or not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
        hostname,
    ):
        raise ValueError("Canonical MCP hostname is invalid")
    if not isinstance(path, str) or not path.startswith("/") or "?" in path or "#" in path:
        raise ValueError("Canonical MCP path is invalid")
    if release.get("transport") != "streamable-http" or release.get("authority") != "postgresql":
        raise ValueError("Canonical MCP transport/authority is invalid")
    if release.get("custom_domain_required") is not True or release.get("workers_dev") is not False:
        raise ValueError("Private validation must use the canonical custom domain")
    if release.get("validation_mode") != "attested-interactive-candidate":
        raise ValueError("Private validation package requires the attested interactive candidate")
    if release.get("validation_deployment_ready") is not True:
        raise ValueError("Private interactive validation candidate is not deployable")
    if release.get("supports_remote_actions") is not True:
        raise ValueError("Private interactive validation package requires remote actions")
    if release.get("deployment_ready") is not False:
        raise ValueError("Private validation package cannot represent an already-approved production release")
    blockers = release.get("readiness_blockers")
    if not isinstance(blockers, list) or "attested_interactive_end_to_end_not_verified" not in blockers:
        raise ValueError("Private validation package requires the real E2E blocker")
    endpoint = f"https://{hostname}{path}"
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" or parsed.hostname != hostname or parsed.path != path:
        raise ValueError("Canonical MCP endpoint is invalid")
    if "workers.dev" in endpoint:
        raise ValueError("workers.dev cannot be packaged as the Product MCP endpoint")
    return endpoint


def build_files() -> tuple[str, dict[str, bytes]]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
    if manifest.get("schema") != "ordax.product-chatgpt-plugin/1":
        raise ValueError("Manifesto do plugin inválido")
    if manifest.get("status") != "private-canary" or manifest.get("worker_role") != "attested-interactive-validation":
        raise ValueError("Plugin não tem o escopo privado de validação interativa")
    if manifest.get("allowed_tools") != list(VALIDATION_TOOLS):
        raise ValueError("Catálogo de ferramentas não corresponde ao candidato MCP interativo")
    if not re.fullmatch(r"[a-z][a-z0-9-]{3,63}", manifest.get("name", "")):
        raise ValueError("Nome interno inválido")
    if not re.fullmatch(r"\d+\.\d+\.\d+", manifest.get("version", "")):
        raise ValueError("Versão semântica inválida")

    endpoint = _canonical_endpoint(foundation)
    release = foundation["mcp_release"]
    expected_issuer = "https://" + foundation["postgres"]["project_ref"] + ".supabase.co/auth/v1"
    if release.get("oauth_issuer") != expected_issuer:
        raise ValueError("OAuth issuer difere do Supabase canônico")

    display = {
        "displayName": manifest["display_name"],
        "shortDescription": manifest["short_description"],
        "longDescription": manifest["long_description"],
        "developerName": "OrdaX",
        "category": "Developer Tools",
        "capabilities": ["Read", "Computer Control"],
    }
    plugin = {
        "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        "name": manifest["name"],
        "version": manifest["version"],
        "description": manifest["description"],
        "author": {"name": "OrdaX"},
        "repository": "https://github.com/ordaxsystems/ordax-platform",
        "license": "Proprietary",
        "keywords": manifest["keywords"],
        "extensions": {"com.openai": {"interface": display}},
    }
    codex = {
        "interface": display,
        "name": manifest["name"],
        "version": manifest["version"],
        "description": manifest["description"],
        "author": {"name": "OrdaX"},
        "keywords": manifest["keywords"],
        "repository": plugin["repository"],
        "license": "Proprietary",
        "mcpServers": "./.mcp.json",
    }
    mcp = {
        "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers": {manifest["name"]: {"type": "streamable-http", "url": endpoint}},
    }
    mcp_codex = {
        "mcpServers": {
            manifest["name"]: {
                "type": "streamable-http",
                "url": endpoint,
                "headers": {},
            }
        },
    }
    documents = {
        "plugin.json": plugin,
        ".codex-plugin/plugin.json": codex,
        "mcp.json": mcp,
        ".mcp.json": mcp_codex,
    }
    return endpoint, {
        path: (json.dumps(body, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        for path, body in documents.items()
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    endpoint, contents = build_files()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(contents):
            info = zipfile.ZipInfo(path, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, contents[path])
    print("ORDAX_PRIVATE_INTERACTIVE_VALIDATION_PLUGIN=PACKAGED")
    print("ENDPOINT=" + endpoint)
    print("ARCHIVE=" + str(args.out))


if __name__ == "__main__":
    main()
