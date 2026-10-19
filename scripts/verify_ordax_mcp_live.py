"""Fail-closed, unauthenticated readiness probe for the canonical OrdaX MCP.

Never treats HTTP 200 /health, tool catalog publication, or an OAuth session as
proof that PostgreSQL-backed targets and device actions work.
"""
from __future__ import annotations

import argparse
import os
from urllib.parse import urlsplit

import httpx


class MCPNotReady(RuntimeError):
    pass


def check(base_url: str, *, client: httpx.Client | None = None) -> dict:
    origin = urlsplit(base_url)
    if (origin.scheme != "https" or not origin.netloc or origin.username
            or origin.password or origin.path not in ("", "/") or origin.query
            or origin.fragment):
        raise MCPNotReady("invalid_mcp_origin")
    owns_client = client is None
    if client is None:
        client = httpx.Client(timeout=httpx.Timeout(12.0), follow_redirects=False)
    try:
        response = client.get(base_url.rstrip("/") + "/ready")
        if response.is_redirect:
            raise MCPNotReady("mcp_readiness_redirect_forbidden")
        try:
            payload = response.json()
        except ValueError as exc:
            raise MCPNotReady("mcp_readiness_invalid_json") from exc
        if not isinstance(payload, dict) or payload.get("service") != "ordax-platform-mcp":
            raise MCPNotReady("mcp_readiness_wrong_service")
        required = ("ok", "oauth_discovery_ready", "postgres_ready",
                    "supports_attested_remote_reads", "supports_remote_actions")
        if response.status_code != 200 or any(payload.get(key) is not True for key in required):
            # Only allow-listed diagnostics, never database URLs, SQL, raw HTTP
            # responses, token material, exception messages or connection strings.
            allowed = {
                "product_postgres_unavailable", "product_postgres_unconfigured",
                "platform_mcp_unconfigured", "product_oauth_discovery_unavailable",
            }
            reason = payload.get("error")
            reason = reason if reason in allowed else "mcp_dependencies_not_ready"
            stage = payload.get("postgres_failure_stage")
            suffix = ":" + stage if stage in ("connect", "query", "decode") else ""
            raise MCPNotReady(reason + suffix)
        return {"ok": True, "postgres_ready": True, "oauth_discovery_ready": True}
    except httpx.HTTPError as exc:
        raise MCPNotReady("mcp_readiness_transport_unavailable") from exc
    finally:
        if owns_client:
            client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.environ.get("ORDAX_MCP_BASE_URL",
                        "https://mcp.ordax.com.br"))
    args = parser.parse_args()
    try:
        check(args.base_url)
    except MCPNotReady as exc:
        print("ORDAX_MCP_NOT_READY: " + str(exc))
        return 3
    print("ORDAX_MCP_READY: OAuth and PostgreSQL connection verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
