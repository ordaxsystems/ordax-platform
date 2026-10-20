"""Read-only audit of Supabase network bans for the OrdaX P0.

No banned IPs, CIDRs or administration credentials are printed.
"""
import ipaddress
import json
import os
import urllib.error
import urllib.request

URL = ("https://api.supabase.com/v1/projects/"
       "jhfphsjptrpmtnzkpwud/network-bans/retrieve/enriched")


class BanAuditFailure(Exception):
    pass


def inspect(token: str, *, include_cloudflare_overlap: bool = False) -> dict:
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
    # All IP addresses remain private to the protected runner.
    report = {"banned_ipv4_count": len(entries),
              "has_active_bans": len(entries) != 0}
    if include_cloudflare_overlap:
        try:
            with urllib.request.urlopen("https://api.cloudflare.com/client/v4/ips", timeout=15) as response:
                published = json.loads(response.read(16384))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise BanAuditFailure("cloudflare_ip_list_unavailable") from None
        ranges = published.get("result", {}).get("ipv4_cidrs") if isinstance(published, dict) else None
        if published.get("success") is not True or not isinstance(ranges, list) or len(ranges) != 15:
            raise BanAuditFailure("cloudflare_ip_list_invalid")
        try:
            networks = [ipaddress.ip_network(x, strict=True) for x in ranges]
            addresses = [ipaddress.IPv4Address(entry["banned_address"]) for entry in entries]
            if any(net.version != 4 or net.prefixlen == 0 for net in networks):
                raise ValueError("unsafe network")
        except ValueError:
            raise BanAuditFailure("network_ban_address_invalid") from None
        count = sum(any(addr in network for network in networks) for addr in addresses)
        report["cloudflare_banned_ipv4_count"] = count
        report["other_banned_ipv4_count"] = len(addresses) - count
    return report


if __name__ == "__main__":
    try:
        print("ORDAX_SUPABASE_BANS=" + json.dumps(
            inspect(os.environ.get("SUPABASE_ACCESS_TOKEN", ""), include_cloudflare_overlap=True),
            sort_keys=True, separators=(",", ":")), flush=True)
    except BanAuditFailure as exc:
        print("ORDAX_SUPABASE_BANS_FAILURE=" + str(exc), flush=True)
        raise SystemExit(1)
