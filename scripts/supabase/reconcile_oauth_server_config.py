"""Reconcile the production Supabase OAuth Server configuration for OrdaX.

Uses the official Supabase Management API. The management token is read only
from SUPABASE_ACCESS_TOKEN and is never printed.
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

PROJECT = "jhfphsjptrpmtnzkpwud"
URL = f"https://api.supabase.com/v1/projects/{PROJECT}/config/auth"
EXPECTED = {
    "site_url": "https://ordax.com.br",
    "oauth_server_enabled": True,
    "oauth_server_allow_dynamic_registration": True,
    "oauth_server_authorization_path": "/oauth/consent",
}


class OAuthConfigFailure(Exception):
    pass


def _request(token: str, method: str, body: dict | None = None) -> dict:
    if not token:
        raise OAuthConfigFailure("supabase_token_missing")
    data = None if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(URL, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read(256 * 1024)
    except urllib.error.HTTPError as error:
        raise OAuthConfigFailure(f"supabase_auth_config_http_{error.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise OAuthConfigFailure("supabase_auth_config_unavailable") from None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        raise OAuthConfigFailure("supabase_auth_config_invalid_json") from None
    if not isinstance(parsed, dict):
        raise OAuthConfigFailure("supabase_auth_config_invalid_shape")
    return parsed


def _subset(config: dict) -> dict:
    return {key: config.get(key) for key in EXPECTED}


def reconcile(token: str, *, apply: bool) -> dict:
    before = _request(token, "GET")
    current = _subset(before)
    drift = {key: {"expected": expected, "actual": current.get(key)}
             for key, expected in EXPECTED.items() if current.get(key) != expected}
    if not drift:
        return {"ok": True, "state": "in_sync", "config": current}

    if not apply:
        return {
            "ok": False,
            "state": "drift",
            "drift_keys": sorted(drift),
            "config": current,
        }

    _request(token, "PATCH", EXPECTED)
    after = _subset(_request(token, "GET"))
    remaining = sorted(key for key, expected in EXPECTED.items()
                       if after.get(key) != expected)
    if remaining:
        raise OAuthConfigFailure("supabase_auth_config_reconcile_failed:" + ",".join(remaining))
    return {
        "ok": True,
        "state": "applied",
        "changed_keys": sorted(drift),
        "config": after,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        result = reconcile(os.environ.get("SUPABASE_ACCESS_TOKEN", ""), apply=args.apply)
    except OAuthConfigFailure as error:
        print("ORDAX_SUPABASE_OAUTH_CONFIG_FAILURE=" + str(error), flush=True)
        return 1
    print("ORDAX_SUPABASE_OAUTH_CONFIG=" + json.dumps(
        result, sort_keys=True, separators=(",", ":")), flush=True)
    if result.get("state") == "drift":
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
