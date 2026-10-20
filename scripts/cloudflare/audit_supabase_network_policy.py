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
    # Management API has evolved across project versions; do not classify an
    # unknown shape as unrestricted. List field names only, not CIDR values.
    return {
        "applied": body.get("restrictions_applied", body.get("applied", "unknown")),
        "network_policy_fields": sorted(k for k in body if k in (
            "db_allowed_cidrs", "db_allowed_ipv6_cidrs", "restrictions_applied",
            "applied", "ipv4", "ipv6", "db_allowed_cidrs_v6"
        )),
        "ipv4_count": len(body.get("db_allowed_cidrs", []))
                      if isinstance(body.get("db_allowed_cidrs"), list) else None,
        "ipv6_count": len(body.get("db_allowed_ipv6_cidrs", []))
                      if isinstance(body.get("db_allowed_ipv6_cidrs"), list) else None,
    }


if __name__ == "__main__":
    try:
        print("ORDAX_SUPABASE_NETWORK_POLICY=" + json.dumps(
            inspect(os.environ.get("SUPABASE_ACCESS_TOKEN", "")),
            sort_keys=True, separators=(",", ":")), flush=True)
    except AuditFailure as error:
        print("ORDAX_SUPABASE_NETWORK_POLICY_FAILURE=" + str(error), flush=True)
        raise SystemExit(1)
