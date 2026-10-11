#!/usr/bin/env python3
"""Public, read-only LIVE smoke test for the canonical OrdaX Product MCP.

Runs outside Cloudflare/Supabase (GitHub-hosted runner). It does NOT mock
OAuth, grant devices, invoke tool actions, or claim that the Central works.
The canary is required to stay read-only even after OAuth becomes ready.
"""
from __future__ import annotations

import json
import os
import ssl
import sys
import tomllib
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
    with (ROOT / "control-plane/cloudflare/wrangler.product-mcp-canary.toml").open("rb") as handle:
        canary = tomllib.load(handle)
    ref = foundation["postgres"]["project_ref"]
    issuer = f"https://{ref}.supabase.co/auth/v1"
    assert canary["vars"]["PRODUCT_AUTH_ISSUER"] == issuer
    assert canary["name"] == foundation["worker_name"] + "-canary"
    assert canary["hyperdrive"][0]["binding"] == "POSTGRES"
    assert canary["hyperdrive"][0]["id"] == foundation["live_evidence"]["hyperdrive"]["id"]
    assert canary["workers_dev"] is True
    worker = f"https://{canary['name']}.{foundation['workers_dev_subdomain']}.workers.dev"
    return issuer, worker


def get_json(url: str) -> tuple[int | None, dict[str, Any] | None]:
    # No user input, cookies, redirects, secrets, or requests that can enqueue work.
    req = urllib.request.Request(
        url, headers={"accept": "application/json", "user-agent": "OrdaX-Public-Readiness/1"},
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


def analyze(issuer: str, worker: str, responses: dict[str, tuple[int | None, dict[str, Any] | None]]) -> dict[str, str | int | None]:
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
        "canary_security": "INCONCLUSIVE",
        "oauth_state": "INCONCLUSIVE",
        "central_remote_actions": "NOT_TESTED_NOT_ENABLED",
    }
    if (health_status != 200 or not isinstance(health, dict)
        or health.get("service") != "ordax-platform-mcp"
        or health.get("mode") != "read-only-canary"
        or health.get("supports_remote_actions") is not False
        or health.get("postgres_configured") is not True
        or metadata_status != 200 or not isinstance(metadata, dict)
        or metadata.get("resource") != worker + "/mcp"
        or metadata.get("authorization_servers") != [issuer]
        or unsupported_status != 404):
        return report
    report["canary_security"] = "PASS_READ_ONLY"
    if auth_status == 200 and isinstance(auth, dict):
        if validate_metadata(auth, issuer):
            report["oauth_state"] = "INVALID_DISCOVERY"
        else:
            report["oauth_state"] = "DISCOVERY_READY"
    elif auth_status in (404, 403):
        report["oauth_state"] = "BLOCKED_BY_AUTH_SERVER"
    elif auth_status is None:
        report["oauth_state"] = "NETWORK_UNAVAILABLE"
    else:
        report["oauth_state"] = "NOT_READY"

    # The Worker must report the OAuth server's real readiness, not merely
    # configured env vars. A live 404 from Supabase may be a legitimate
    # fail-closed state; NEVER call that operationally ready.
    if report["oauth_state"] == "DISCOVERY_READY":
        if ready_status != 200 or not ready or ready.get("oauth_discovery_ready") is not True:
            report["canary_security"] = "INCONSISTENT_READINESS"
    elif ready_status == 200 or (isinstance(ready, dict) and ready.get("oauth_discovery_ready") is True):
        report["canary_security"] = "UNSAFE_FALSE_READY"
    elif ready_status != 503:
        report["canary_security"] = "INCONCLUSIVE"
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
    # No private responses, tokens, cookies, user identifiers, or env values.
    print(json.dumps(outcome, sort_keys=True))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("### LIVE Product MCP readiness (public endpoints only)\n\n")
            handle.write("| Check | Observed |\n|---|---|\n")
            for k in ("canary_security", "health_http", "resource_http", "legacy_get_http",
                      "oauth_state", "oauth_discovery_http", "ready_http", "central_remote_actions"):
                handle.write(f"| {k} | {outcome[k]} |\n")
            handle.write("\n**OAuth discovery success is not consent, enrollment, "
                         "ChatGPT plugin invocation, or multi-PC execution proof.**\n")
    if outcome["canary_security"] != "PASS_READ_ONLY":
        print("LIVE_CANARY_SECURITY=FAIL_OR_INCONCLUSIVE", file=sys.stderr)
        return 2
    # A disabled OAuth server is explicitly recorded as a blocker, not PASS.
    print("LIVE_CANARY_SECURITY=PASS_READ_ONLY")
    print("LIVE_OAUTH_DISCOVERY=" + str(outcome["oauth_state"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
