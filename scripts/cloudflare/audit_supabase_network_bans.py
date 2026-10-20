"""Read-only audit of Supabase network bans for the OrdaX P0.

No banned IPs, CIDRs or administration credentials are printed.
"""
import json
import os
import urllib.error
import urllib.request

URL = ("https://api.supabase.com/v1/projects/"
       "jhfphsjptrpmtnzkpwud/network-bans/retrieve/enriched")


class BanAuditFailure(Exception):
    pass


def inspect(token: str) -> dict:
    if not token:
        raise BanAuditFailure("supabase_token_missing")
    req = urllib.request.Request(URL, method="POST", data=b"{}",
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/json",
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            value = json.loads(response.read(32768))
    except urllib.error.HTTPError as exc:
        raise BanAuditFailure(f"provider_http_{exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise BanAuditFailure("network_bans_unavailable") from None
    if not isinstance(value, dict):
        raise BanAuditFailure("network_bans_response_invalid")
    entries = value.get("banned_ipv4_addresses")
    if not isinstance(entries, list):
        raise BanAuditFailure("network_bans_response_invalid")
    if not all(isinstance(x, dict) and isinstance(x.get("banned_address"), str)
               for x in entries):
        raise BanAuditFailure("network_bans_response_invalid")
    # Only report counts. The actual banned IP is private to the protected runner.
    return {"banned_ipv4_count": len(entries),
            "has_active_bans": len(entries) != 0}


if __name__ == "__main__":
    try:
        print("ORDAX_SUPABASE_BANS=" + json.dumps(
            inspect(os.environ.get("SUPABASE_ACCESS_TOKEN", "")),
            sort_keys=True, separators=(",", ":")), flush=True)
    except BanAuditFailure as exc:
        print("ORDAX_SUPABASE_BANS_FAILURE=" + str(exc), flush=True)
        raise SystemExit(1)
