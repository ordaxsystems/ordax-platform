#!/usr/bin/env python3
"""Gera o plugin ChatGPT privado a partir do SSOT Product/Cloudflare.

Não instala o plugin nem modifica o deployment ativo. O release publicado
deve ser atualizado apenas com o current_release_id retornado pelo ChatGPT.
"""
from __future__ import annotations

import argparse
import json
import re
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "integrations/chatgpt/product-canary/manifest.json"
FOUNDATION = ROOT / "control-plane/cloudflare/production-foundation.json"
WRANGLER = ROOT / "control-plane/cloudflare/wrangler.product-mcp-canary.toml"
READ_TOOLS = ("ordax_session", "ordax_profile", "ordax_targets", "ordax_action_status")


def build_files() -> tuple[str, dict[str, bytes]]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    foundation = json.loads(FOUNDATION.read_text(encoding="utf-8"))
    with WRANGLER.open("rb") as stream:
        wrangler = tomllib.load(stream)
    if manifest.get("schema") != "ordax.product-chatgpt-plugin/1":
        raise ValueError("Manifesto do plugin inválido")
    if manifest.get("status") != "private-canary" or manifest.get("worker_role") != "read-only-canary":
        raise ValueError("Plugin não tem o escopo privado de validação")
    if manifest.get("allowed_tools") != list(READ_TOOLS):
        raise ValueError("Catálogo de ferramentas não corresponde à entrada MCP de leitura")
    if not re.fullmatch(r"[a-z][a-z0-9-]{3,63}", manifest.get("name", "")):
        raise ValueError("Nome interno inválido")
    if not re.fullmatch(r"\d+\.\d+\.\d+", manifest.get("version", "")):
        raise ValueError("Versão semântica inválida")
    worker = foundation.get("worker_name", "") + "-canary"
    subdomain = foundation.get("workers_dev_subdomain", "")
    if wrangler.get("name") != worker or wrangler.get("main") != "src/product_mcp_entry.ts":
        raise ValueError("Worker do plugin diverge do código canônico")
    if wrangler.get("d1_databases") or wrangler.get("durable_objects"):
        raise ValueError("Worker read-only não pode incluir D1 nem o Runtime legado")
    if wrangler.get("workers_dev") is not True or wrangler.get("preview_urls") is not False:
        raise ValueError("A exposição do Worker de validação diverge do manifesto")
    if not re.fullmatch(r"[a-z][a-z0-9-]{3,63}", subdomain):
        raise ValueError("Subdomínio oficial inválido")
    expected_hyperdrive = foundation["live_evidence"]["hyperdrive"]["id"]
    if wrangler.get("hyperdrive") != [{"binding": "POSTGRES", "id": expected_hyperdrive}]:
        raise ValueError("O plugin não está vinculado ao Hyperdrive oficial")
    issuer = "https://" + foundation["postgres"]["project_ref"] + ".supabase.co/auth/v1"
    variables = wrangler.get("vars") or {}
    if (variables.get("PRODUCT_AUTH_ISSUER") != issuer
        or variables.get("PRODUCT_AUTH_JWKS_URL") != issuer + "/.well-known/jwks.json"
        or variables.get("PRODUCT_AUTH_AUDIENCE") != "authenticated"):
        raise ValueError("Issuer e JWKS diferem do Supabase canônico")
    url = f"https://{worker}.{subdomain}.workers.dev/mcp"
    if "ordax-ac1ca1b50d09" in url:
        raise ValueError("A URL de origem antiga não pode entrar no release")

    display = {
        "displayName": manifest["display_name"],
        "shortDescription": manifest["short_description"],
        "longDescription": manifest["long_description"],
        "developerName": "OrdaX",
        "category": "Developer Tools",
        "capabilities": ["Read"],
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
        "interface": display, "name": manifest["name"],
        "version": manifest["version"], "description": manifest["description"],
        "author": {"name": "OrdaX"}, "keywords": manifest["keywords"],
        "repository": plugin["repository"], "license": "Proprietary",
        "mcpServers": "./.mcp.json",
    }
    mcp = {
        "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers": {manifest["name"]: {"type": "streamable-http", "url": url}},
    }
    mcp_codex = {
        "mcpServers": {manifest["name"]: {
            "type": "streamable-http", "url": url, "headers": {},
        }},
    }
    documents = {
        "plugin.json": plugin,
        ".codex-plugin/plugin.json": codex,
        "mcp.json": mcp,
        ".mcp.json": mcp_codex,
    }
    return url, {
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
    print("ORDAX_CANONICAL_CHATGPT_PLUGIN=PACKAGED")
    print("ENDPOINT=" + endpoint)
    print("ARCHIVE=" + str(args.out))


if __name__ == "__main__":
    main()
