from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_ROOT = ROOT / "plugins" / "ordax-chatgpt"
FOUNDATION_PATH = ROOT / "control-plane" / "cloudflare" / "production-foundation.json"
MCP_CONFIG_PATH = PLUGIN_ROOT / "mcp.json"
JSON_FILES = ("plugin.json", "mcp.json")
PACKAGE_FILES = ("plugin.json", "mcp.json", "assets/ordax.svg")
FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)
LEGACY_MCP_ENDPOINT = "https://ordax-control-plane-v3.ordax-ac1ca1b50d09.workers.dev/mcp"


class PluginDistributionBlocked(RuntimeError):
    def __init__(self, blockers: list[str]):
        self.blockers = tuple(blockers)
        super().__init__("plugin_distribution_blocked:" + ",".join(blockers))


def load_manifest() -> dict:
    raw = (PLUGIN_ROOT / "plugin.json").read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("plugin.json must be UTF-8 without BOM")
    manifest = json.loads(raw.decode("utf-8"))
    if manifest.get("name") != "ordax-chatgpt":
        raise ValueError("unexpected ChatGPT connector name")
    return manifest


def load_mcp_config() -> dict:
    raw = MCP_CONFIG_PATH.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("mcp.json must be UTF-8 without BOM")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("mcp.json must be an object")
    return value


def load_foundation() -> dict:
    value = json.loads(FOUNDATION_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("production foundation must be an object")
    return value


def canonical_mcp_endpoint(foundation: dict | None = None) -> str:
    foundation = foundation if foundation is not None else load_foundation()
    release = foundation.get("mcp_release")
    if not isinstance(release, dict):
        raise ValueError("canonical mcp_release is missing")
    hostname = release.get("hostname")
    path = release.get("path")
    if not isinstance(hostname, str) or not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
        hostname,
    ):
        raise ValueError("canonical MCP hostname is invalid")
    if not isinstance(path, str) or not path.startswith("/") or "?" in path or "#" in path:
        raise ValueError("canonical MCP path is invalid")
    if release.get("transport") != "streamable-http" or release.get("authority") != "postgresql":
        raise ValueError("canonical MCP transport/authority is invalid")
    if release.get("custom_domain_required") is not True or release.get("workers_dev") is not False:
        raise ValueError("canonical MCP must use the production custom domain")
    safety = release.get("safety")
    if not isinstance(safety, dict) or any(
        safety.get(key) is not False
        for key in ("allow_d1", "allow_legacy_fallback", "allow_untrusted_model_dispatch", "allow_production_release_without_e2e")
    ):
        raise ValueError("canonical MCP safety contract is invalid")
    endpoint = f"https://{hostname}{path}"
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" or parsed.hostname != hostname or parsed.path != path:
        raise ValueError("canonical MCP endpoint is invalid")
    return endpoint


def distribution_readiness(foundation: dict | None = None) -> dict:
    foundation = foundation if foundation is not None else load_foundation()
    release = foundation.get("mcp_release")
    if not isinstance(release, dict):
        raise ValueError("canonical mcp_release is missing")
    endpoint = canonical_mcp_endpoint(foundation)
    raw_blockers = release.get("readiness_blockers")
    if not isinstance(raw_blockers, list) or not all(
        isinstance(item, str) and re.fullmatch(r"[a-z0-9_]+", item) for item in raw_blockers
    ):
        raise ValueError("canonical MCP readiness blockers are invalid")
    blockers = sorted(set(raw_blockers))
    if release.get("deployment_ready") is not True and "deployment_not_ready" not in blockers:
        blockers.append("deployment_not_ready")
    if release.get("supports_remote_actions") is not True and "canonical_remote_actions_not_ready" not in blockers:
        blockers.append("canonical_remote_actions_not_ready")
    blockers = sorted(set(blockers))
    return {
        "schema": "ordax.chatgpt-plugin-distribution-readiness/1",
        "ready": len(blockers) == 0,
        "endpoint": endpoint,
        "supports_remote_actions": release.get("supports_remote_actions") is True,
        "blockers": blockers,
        "foundation_version": foundation.get("version"),
    }


def validate_package() -> dict:
    manifest = load_manifest()
    version = manifest.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", version):
        raise ValueError("plugin version must be a strict semantic version")
    if manifest.get("repository") != "https://github.com/ordaxsystems/ordax-platform":
        raise ValueError("connector source must reference canonical OrdaX platform repository")
    interface = manifest["extensions"]["com.openai"]["interface"]
    subtitle = interface.get("shortDescription")
    if not isinstance(subtitle, str) or not 1 <= len(subtitle) <= 30:
        raise ValueError("shortDescription must contain 1 to 30 characters")
    prompts = interface.get("defaultPrompt")
    if isinstance(prompts, str):
        prompts = [prompts]
    if not isinstance(prompts, list) or not 1 <= len(prompts) <= 3 or not all(
        isinstance(prompt, str) and prompt.strip() for prompt in prompts
    ):
        raise ValueError("defaultPrompt must be a string or 1 to 3 nonempty strings")
    for name in PACKAGE_FILES:
        path = PLUGIN_ROOT / name
        if path.is_symlink() or not path.resolve().is_relative_to(PLUGIN_ROOT.resolve()):
            raise ValueError(f"plugin file must be contained and not a symlink: {name}")
        if not path.is_file():
            raise FileNotFoundError(path)
    for name in JSON_FILES:
        raw = (PLUGIN_ROOT / name).read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            raise ValueError(f"{name} must be UTF-8 without BOM")
        json.loads(raw.decode("utf-8"))

    mcp = load_mcp_config()
    servers = mcp.get("mcpServers")
    ordax = servers.get("ordax") if isinstance(servers, dict) else None
    if not isinstance(ordax, dict) or ordax.get("type") != "streamable-http":
        raise ValueError("canonical ORDAX MCP server is invalid")
    endpoint = ordax.get("url")
    if endpoint == LEGACY_MCP_ENDPOINT:
        raise ValueError("retired legacy MCP endpoint must never be packaged")
    if endpoint != canonical_mcp_endpoint():
        raise ValueError("plugin MCP endpoint differs from production foundation SSOT")
    return manifest


def build_archive(output_dir: Path) -> tuple[Path, str]:
    manifest = validate_package()
    readiness = distribution_readiness()
    if not readiness["ready"]:
        raise PluginDistributionBlocked(list(readiness["blockers"]))
    version = str(manifest.get("version") or "0.0.0")
    output_dir.mkdir(parents=True, exist_ok=True)
    for legacy_stem in ("ordax-studio-plugin", "ordax-dev-plugin"):
        for pattern in (
            f"{legacy_stem}-*.zip",
            f"{legacy_stem}-*.zip.sha256",
        ):
            for legacy in output_dir.glob(pattern):
                legacy.unlink(missing_ok=True)
    archive = output_dir / f"ordax-chatgpt-plugin-{version}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for name in sorted(PACKAGE_FILES):
            data = (PLUGIN_ROOT / name).read_bytes()
            info = zipfile.ZipInfo(f"{manifest['name']}/{name}", date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            bundle.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(archive.suffix + ".sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="ascii"
    )
    return archive, digest


def write_readiness(path: Path) -> dict:
    validate_package()
    value = distribution_readiness()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the portable ORDAX Studio ChatGPT connector package"
    )
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist" / "plugins")
    parser.add_argument("--readiness-json", type=Path)
    args = parser.parse_args()
    if args.readiness_json is not None:
        readiness = write_readiness(args.readiness_json)
        print("ORDAX_CHATGPT_PLUGIN_READY=" + ("true" if readiness["ready"] else "false"))
        print("ORDAX_CHATGPT_PLUGIN_ENDPOINT=" + readiness["endpoint"])
        if readiness["blockers"]:
            print("ORDAX_CHATGPT_PLUGIN_BLOCKERS=" + ",".join(readiness["blockers"]))
        return 0
    try:
        archive, digest = build_archive(args.output_dir)
    except PluginDistributionBlocked as exc:
        print("ORDAX_CHATGPT_PLUGIN_DISTRIBUTION=BLOCKED")
        print("ORDAX_CHATGPT_PLUGIN_BLOCKERS=" + ",".join(exc.blockers))
        return 3
    print(f"ORDAX_CHATGPT_PLUGIN_ARCHIVE={archive}")
    print(f"ORDAX_CHATGPT_PLUGIN_SHA256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
