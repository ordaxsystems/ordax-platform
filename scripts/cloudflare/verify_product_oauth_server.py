from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit


MAX_DISCOVERY_BYTES = 64 * 1024
ISSUER_RE = re.compile(r"https://[a-z0-9-]+\.supabase\.co/auth/v1")


def _canonical_issuer(issuer: str) -> bool:
    return bool(ISSUER_RE.fullmatch(issuer))


def _same_origin_auth_endpoint(value: Any, expected_issuer: str) -> bool:
    """OAuth service endpoints must stay on the canonical Supabase Auth origin."""
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
        canonical = urlsplit(expected_issuer)
        return (
            parsed.scheme == "https"
            and parsed.netloc == canonical.netloc
            and parsed.username is None
            and parsed.password is None
            and parsed.query == ""
            and parsed.fragment == ""
            and parsed.path.startswith("/auth/v1/")
            and not parsed.path.startswith("/auth/v1//")
        )
    except ValueError:
        return False


def validate_metadata(metadata: Any, expected_issuer: str) -> list[str]:
    errors: list[str] = []
    if not _canonical_issuer(expected_issuer):
        return ["ORDAX Product Auth issuer must be the canonical Supabase Auth URL"]
    if not isinstance(metadata, dict):
        return ["OAuth discovery response must be a JSON object"]

    if metadata.get("issuer") != expected_issuer:
        errors.append("issuer does not match the ORDAX Product Auth issuer")

    for field in ("authorization_endpoint", "token_endpoint", "registration_endpoint"):
        if not _same_origin_auth_endpoint(metadata.get(field), expected_issuer):
            errors.append(f"{field} must be an HTTPS endpoint on the canonical Supabase Auth origin")

    methods = metadata.get("code_challenge_methods_supported")
    if not isinstance(methods, list) or "S256" not in methods:
        errors.append("code_challenge_methods_supported must include S256")

    grants = metadata.get("grant_types_supported")
    if not isinstance(grants, list) or "authorization_code" not in grants:
        errors.append("grant_types_supported must include authorization_code")

    responses = metadata.get("response_types_supported")
    if not isinstance(responses, list) or "code" not in responses:
        errors.append("response_types_supported must include code")

    auth_methods = metadata.get("token_endpoint_auth_methods_supported")
    if not isinstance(auth_methods, list) or "none" not in auth_methods:
        errors.append("token_endpoint_auth_methods_supported must include none for public PKCE clients")

    return errors


def _canonical_project_issuer() -> str:
    """Resolve the immutable project identity from the production foundation."""
    root = Path(__file__).resolve().parents[2]
    try:
        foundation = json.loads(
            (root / "control-plane/cloudflare/production-foundation.json").read_text(encoding="utf-8")
        )
        with (root / "control-plane/cloudflare/wrangler.mcp.toml").open("rb") as stream:
            wrangler = tomllib.load(stream)
    except (OSError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SystemExit("Cannot read the canonical PostgreSQL/Worker identity") from exc

    ref = foundation.get("postgres", {}).get("project_ref")
    if not isinstance(ref, str) or not re.fullmatch(r"[a-z0-9]{20}", ref):
        raise SystemExit("Canonical Supabase project ref is invalid")
    expected = f"https://{ref}.supabase.co/auth/v1"
    if wrangler.get("vars", {}).get("PRODUCT_AUTH_ISSUER") != expected:
        raise SystemExit("Wrangler Auth issuer differs from the canonical PostgreSQL project")
    return expected


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request: urllib.request.Request, fp: Any, code: int,
                         msg: str, headers: Any, newurl: str) -> None:
        return None


def _read_metadata(discovery_url: str) -> Any:
    request = urllib.request.Request(
        discovery_url,
        headers={"Accept": "application/json", "User-Agent": "OrdaX-OAuth-Readiness"},
    )
    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(request, timeout=15) as response:
            if response.status != 200:
                raise SystemExit(f"OAuth discovery endpoint returned HTTP {response.status}")
            raw = response.read(MAX_DISCOVERY_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise SystemExit(
            f"OAuth discovery endpoint returned HTTP {exc.code}; "
            "verify Authentication > OAuth Server and the canonical issuer"
        ) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise SystemExit(f"OAuth discovery request failed: {exc}") from exc

    if len(raw) > MAX_DISCOVERY_BYTES:
        raise SystemExit("OAuth discovery response exceeds the maximum allowed size")
    try:
        return json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit("OAuth discovery response is not valid JSON") from exc


def main() -> int:
    if len(sys.argv) not in {2, 3}:
        raise SystemExit("usage: verify-product-oauth-server.py <issuer> [discovery-url]")

    issuer = sys.argv[1].rstrip("/")
    if issuer != _canonical_project_issuer():
        raise SystemExit("issuer differs from the canonical PostgreSQL project identity")

    discovery_url = (
        sys.argv[2]
        if len(sys.argv) == 3
        else issuer.removesuffix("/auth/v1") + "/.well-known/oauth-authorization-server/auth/v1"
    )
    expected_discovery = issuer.removesuffix("/auth/v1") + "/.well-known/oauth-authorization-server/auth/v1"
    if discovery_url != expected_discovery:
        raise SystemExit("OAuth discovery URL must match the canonical issuer")

    errors = validate_metadata(_read_metadata(discovery_url), issuer)
    if errors:
        raise SystemExit("OAuth server is not MCP-ready: " + "; ".join(errors))

    # Metadata only advertises registration: no client is created by this probe.
    print("Product OAuth metadata OK: canonical endpoints, DCR advertised and public PKCE S256")
    print("Read-only check: dynamic registration and end-to-end consent were not exercised")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
