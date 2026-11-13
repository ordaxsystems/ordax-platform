#!/usr/bin/env python3
"""Secret-free LIVE smoke for the canonical OrdaX MCP public surface.

This probe verifies only public HTTPS metadata/health behavior. It never uses
OAuth credentials, device tokens, grants or remote actions, and therefore is
not an MCP provider E2E or production-release proof by itself.
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from scripts.cloudflare.verify_product_oauth_server import validate_metadata

ROOT = Path(__file__).resolve().parents[2]
MAX_BYTES = 65536


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: urllib.request.Request, fp: Any,
                         code: int, msg: str, headers: Any, url: str) -> None:
        return None


def load_identity() -> tuple[str, str]:
    foundation = json.loads(
        (ROOT / "control-plane/cloudflare/production-foundation.json").read_text("utf-8")
    )
    release = foundation["mcp_release"]
    ref = foundation["postgres"]["project_ref"]
    issuer = f"https://{ref}.supabase.co/auth/v1"
    assert release["oauth_issuer"] == issuer
    assert release["worker_name"] == "ordax-mcp"
    assert release["hostname"] == "mcp.ordax.com.br"
    assert release["path"] == "/mcp"
    assert release["workers_dev"] is False
    return issuer, f"https://{release['hostname']}"


def get_json(url: str) -> tuple[int | None, dict[str, Any] | None]:
    req = urllib.request.Request(
        url, headers={"accept": "application/json", "user-agent": "OrdaX-Public-Readiness/2"},
        method="GET"
    )
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect()
    )
    try:
        response = opener.open(req, timeout=12)
    except urllib.error.HTTPError as exc:
        response = exc
    except (urllib.error.URLError, TimeoutError, OSError):
        return None, None
    try:
        status = response.status
        raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return status, None
        obj = json.loads(raw.decode("utf-8"))
        return status, obj if isinstance(obj, dict) else None
    except (UnicodeError, ValueError, OSError):
        return status, None
    finally:
        response.close()


def analyze(issuer: str, worker: str,
            responses: dict[str, tuple[int | None, dict[str, Any] | None]]) -> dict[str, str | int | None]:
    health_status, health = responses["health"]
    ready_status, ready = responses["ready"]
    metadata_status, metadata = responses["resource"]
    auth_status, auth = responses["oauth"]
    unsupported_status, _ = responses["legacy_get"]
    report: dict[str, str | int | None] = {
        "worker": worker,
        "issuer": issuer,
        "health_http": health_status,
        "ready_http": ready_status,
        "resource_http": metadata_status,
        "oauth_discovery_http": auth_status,
        "legacy_get_http": unsupported_status,
        "public_surface": "INCONCLUSIVE",
        "oauth_state": "INCONCLUSIVE",
        "central_remote_actions": "NOT_TESTED_BY_READ_ONLY_PROBE",
    }
    if (health_status != 200 or not isinstance(health, dict)
        or health.get("service") != "ordax-platform-mcp"
        or health.get("mode") != "attested-device-control"
        or health.get("supports_remote_actions") is not True
        or health.get("postgres_configured") is not True
        or metadata_status != 200 or not isinstance(metadata, dict)
        or metadata.get("resource") != worker + "/mcp"
        or metadata.get("authorization_servers") != [issuer]
        or unsupported_status != 404):
        return report
    report["public_surface"] = "PASS_CANONICAL"

    if auth_status == 200 and isinstance(auth, dict):
        report["oauth_state"] = "INVALID_DISCOVERY" if validate_metadata(auth, issuer) else "DISCOVERY_READY"
    elif auth_status in (404, 403):
        report["oauth_state"] = "BLOCKED_BY_AUTH_SERVER"
    elif auth_status is None:
        report["oauth_state"] = "NETWORK_UNAVAILABLE"
    else:
        report["oauth_state"] = "NOT_READY"

    if report["oauth_state"] == "DISCOVERY_READY":
        if ready_status != 200 or not ready or ready.get("oauth_discovery_ready") is not True:
            report["public_surface"] = "INCONSISTENT_READINESS"
    elif ready_status == 200 or (isinstance(ready, dict) and ready.get("oauth_discovery_ready") is True):
        report["public_surface"] = "UNSAFE_FALSE_READY"
    elif ready_status != 503:
        report["public_surface"] = "INCONCLUSIVE"
    return report


def main() -> int:
    issuer, worker = load_identity()
    urls = {
        "health": worker + "/health",
        "ready": worker + "/ready",
        "resource": worker + "/.well-known/oauth-protected-resource",
        "oauth": issuer.removesuffix("/auth/v1") + "/.well-known/oauth-authorization-server/auth/v1",
        "legacy_get": worker + "/v3/product/actions",
    }
    outcome = analyze(issuer, worker, {k: get_json(url) for k, url in urls.items()})
    print(json.dumps(outcome, sort_keys=True))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("### LIVE canonical OrdaX MCP public surface\n\n")
            handle.write("| Check | Observed |\n|---|---|\n")
            for k in ("public_surface", "health_http", "resource_http", "legacy_get_http",
                      "oauth_state", "oauth_discovery_http", "ready_http", "central_remote_actions"):
                handle.write(f"| {k} | {outcome[k]} |\n")
            handle.write("\n**This secret-free probe is not OAuth consent, device attestation, "
                         "remote-action execution or multi-device E2E proof.**\n")
    if outcome["public_surface"] != "PASS_CANONICAL":
        print("LIVE_CANONICAL_MCP_SURFACE=FAIL_OR_INCONCLUSIVE", file=sys.stderr)
        return 2
    print("LIVE_CANONICAL_MCP_SURFACE=PASS")
    print("LIVE_OAUTH_DISCOVERY=" + str(outcome["oauth_state"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
