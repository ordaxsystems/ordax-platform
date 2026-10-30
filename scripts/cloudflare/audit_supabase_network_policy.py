"""Protected read-only audit of database network restrictions.

Uses the canonical Supabase Management API without changing any restrictions.
Never prints bearer tokens, CIDRs, backend errors or raw response bodies.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

PROJECT = "jhfphsjptrpmtnzkpwud"
URL = f"https://api.supabase.com/v1/projects/{PROJECT}/network-restrictions"


class AuditFailure(Exception):
    pass


def inspect(token: str) -> dict:
    if not token:
        raise AuditFailure("supabase_token_missing")
    req = urllib.request.Request(URL, headers={
        "Authorization": "Bearer " + token, "Accept": "application/json",
    }, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            body = json.loads(response.read(32768))
    except urllib.error.HTTPError as error:
        raise AuditFailure(f"supabase_http_{error.code}") from None
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        raise AuditFailure("supabase_policy_unavailable") from None
    if not isinstance(body, dict):
        raise AuditFailure("supabase_network_policy_shape")
    # Current v1 Management API: entitlement + status + nested config.
    # Never log network CIDR values, just counts and non-sensitive statuses.
    settings = body.get("config")
    if not isinstance(settings, dict):
        settings = {}
    ipv4 = settings.get("dbAllowedCidrs")
    ipv6 = settings.get("dbAllowedCidrsV6")
    status = body.get("status")
    entitlement = body.get("entitlement")
    return {
        "status": status if status in ("applied", "stored", "pending") else "unknown",
        "entitlement": entitlement if entitlement in ("allowed", "disallowed") else "unknown",
        "ipv4_count": len(ipv4) if isinstance(ipv4, list) else None,
        "ipv6_count": len(ipv6) if isinstance(ipv6, list) else None,
        "applied": status == "applied" if status in ("applied", "stored") else "unknown",
    }


if __name__ == "__main__":
    try:
        print("ORDAX_SUPABASE_NETWORK_POLICY=" + json.dumps(
            inspect(os.environ.get("SUPABASE_ACCESS_TOKEN", "")),
            sort_keys=True, separators=(",", ":")), flush=True)
    except AuditFailure as error:
        print("ORDAX_SUPABASE_NETWORK_POLICY_FAILURE=" + str(error), flush=True)
        raise SystemExit(1)
