"""One-source-of-truth Cloudflare Hyperdrive egress ACL reconciliation.

This is a deliberate NETWORK CONFIGURATION REPAIR, not a database bypass:
- Preserve every existing Supabase IPv4/IPv6 restriction;
- Add ONLY the documented Cloudflare Hyperdrive egress networks;
- Never grant new database roles or broaden PostgreSQL function permissions;
- Verify /ready via the existing MCP Worker; rollback on failed verification;
- Refuse unsafe concurrent policy updates rather than overwrite other changes.

Run exclusively via protected, manual GitHub Actions with privileged secrets
kept inside the runner. No CIDRs, credentials, response bodies, or stack traces
are logged.
"""
from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.error
import urllib.request

PROJECT = "jhfphsjptrpmtnzkpwud"
API = f"https://api.supabase.com/v1/projects/{PROJECT}/network-restrictions"
READY = "https://ordax-mcp.ordaxsystems.workers.dev/ready"
CF_V4 = frozenset("""
173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22
141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20
197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13
104.24.0.0/14 172.64.0.0/13 131.0.72.0/22
""".split())
CF_V6 = frozenset("""
2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32
2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32
""".split())


class RepairFailure(Exception):
    pass


def request(method: str, url: str, token: str | None = None,
            body: dict | None = None) -> dict:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read(32768)
            obj = json.loads(raw) if raw else {}
            if not isinstance(obj, dict):
                raise RepairFailure("provider_response_invalid")
            return obj
    except urllib.error.HTTPError as exc:
        # Do not read or print provider bodies; the request may contain ACLs.
        raise RepairFailure(f"provider_http_{exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise RepairFailure("provider_unreachable") from None
    except (ValueError, UnicodeError):
        raise RepairFailure("provider_response_invalid") from None


def policy(token: str) -> tuple[dict, str]:
    response = request("GET", API, token)
    if response.get("entitlement") != "allowed" or response.get("status") not in ("applied", "stored"):
        raise RepairFailure("policy_entitlement_or_state_invalid")
    cfg = response.get("config")
    if not isinstance(cfg, dict):
        raise RepairFailure("policy_config_invalid")
    v4 = cfg.get("dbAllowedCidrs")
    v6 = cfg.get("dbAllowedCidrsV6")
    if not isinstance(v4, list) or not isinstance(v6, list):
        raise RepairFailure("policy_cidr_shape_invalid")
    for family, values in ((4, v4), (6, v6)):
        for cidr in values:
            if not isinstance(cidr, str) or len(cidr) > 64:
                raise RepairFailure("policy_cidr_invalid")
            try:
                address = ipaddress.ip_network(cidr, strict=True)
                if address.version != family:
                    raise ValueError("family")
            except ValueError:
                raise RepairFailure("policy_cidr_invalid") from None
    return {"dbAllowedCidrs": v4, "dbAllowedCidrsV6": v6}, response["status"]


def official_cloudflare_networks() -> None:
    """Fail closed if the published Cloudflare IP list diverges from the reviewed snapshot."""
    for url, expected in (("https://www.cloudflare.com/ips-v4", CF_V4),
                          ("https://www.cloudflare.com/ips-v6", CF_V6)):
        try:
            with urllib.request.urlopen(url, timeout=15) as response:
                content = response.read(8192).decode("ascii")
        except (urllib.error.URLError, TimeoutError, OSError, UnicodeError):
            raise RepairFailure("official_cloudflare_ip_list_unavailable") from None
        observed = frozenset(content.split())
        if observed != expected:
            raise RepairFailure("official_cloudflare_ip_list_mismatch")


def merge(current: dict) -> dict:
    if len(CF_V4) != 15 or len(CF_V6) != 7:
        raise RepairFailure("cloudflare_network_snapshot_invalid")
    for nets, family in ((CF_V4, 4), (CF_V6, 6)):
        for cidr in nets:
            net = ipaddress.ip_network(cidr, strict=True)
            if net.version != family or net.prefixlen == 0:
                raise RepairFailure("unsafe_cloudflare_network")
    return {
        "dbAllowedCidrs": sorted(set(current["dbAllowedCidrs"]) | CF_V4),
        "dbAllowedCidrsV6": sorted(set(current["dbAllowedCidrsV6"]) | CF_V6),
    }


def equal_acl(a: dict, b: dict) -> bool:
    return (set(a["dbAllowedCidrs"]) == set(b["dbAllowedCidrs"])
            and set(a["dbAllowedCidrsV6"]) == set(b["dbAllowedCidrsV6"]))


def update_policy(token: str, config: dict) -> None:
    receipt = request("POST", API + "/apply", token, config)
    if receipt.get("status") not in ("stored", "applied"):
        raise RepairFailure("policy_apply_unconfirmed")


def wait_for_applied(token: str, expected: dict, retries: int = 18) -> bool:
    for attempt in range(retries):
        current, status = policy(token)
        if status == "applied" and equal_acl(current, expected):
            return True
        if not equal_acl(current, expected):
            raise RepairFailure("policy_changed_concurrently")
        if attempt + 1 < retries:
            time.sleep(5)
    return False


def ready() -> bool:
    try:
        v = request("GET", READY)
    except RepairFailure:
        return False
    return all(v.get(key) is True for key in (
        "postgres_ready", "oauth_discovery_ready",
        "supports_attested_remote_reads", "supports_remote_actions",
    ))


def rollback_if_ours(token: str, previous: dict, expected: dict) -> None:
    current, _ = policy(token)
    if equal_acl(current, previous):
        print("ORDAX_EGRESS_ROLLBACK=NOT_NEEDED", flush=True)
        return
    if not equal_acl(current, expected):
        raise RepairFailure("rollback_blocked_concurrent_change")
    update_policy(token, previous)
    if not wait_for_applied(token, previous):
        raise RepairFailure("rollback_not_confirmed")
    print("ORDAX_EGRESS_ROLLBACK=CONFIRMED", flush=True)


def run() -> None:
    token = os.environ.get("SUPABASE_ACCESS_TOKEN", "")
    if not token:
        raise RepairFailure("supabase_token_missing")
    previous, status = policy(token)
    if status != "applied":
        raise RepairFailure("policy_not_applied_do_not_change")
    official_cloudflare_networks()
    expected = merge(previous)
    additions = {
        "ipv4": len(set(expected["dbAllowedCidrs"]) - set(previous["dbAllowedCidrs"])),
        "ipv6": len(set(expected["dbAllowedCidrsV6"]) - set(previous["dbAllowedCidrsV6"])),
    }
    print("ORDAX_EGRESS_ADD_COUNTS=" + json.dumps(additions, sort_keys=True), flush=True)
    if additions["ipv4"] + additions["ipv6"] == 0:
        print("ORDAX_EGRESS_POLICY=ALREADY_COVERED", flush=True)
        if not ready():
            raise RepairFailure("covered_network_but_postgres_unavailable")
        print("ORDAX_EGRESS_READY=PASS", flush=True)
        return

    # The user has requested the root fix; apply exactly the reviewed Cloudflare
    # network list, keep the original rules and explicitly rollback if the MCP
    # does not recover after the ACL propagation window.
    try:
        update_policy(token, expected)
        print("ORDAX_EGRESS_ACL=APPLIED_REQUEST", flush=True)
        if not wait_for_applied(token, expected):
            raise RepairFailure("policy_application_not_confirmed")
        for attempt in range(18):
            if ready():
                print("ORDAX_EGRESS_READY=PASS", flush=True)
                return
            if attempt < 17:
                time.sleep(10)
        raise RepairFailure("mcp_remains_unavailable_after_network_repair")
    except RepairFailure:
        try:
            rollback_if_ours(token, previous, expected)
        except RepairFailure as failure:
            print("ORDAX_EGRESS_ROLLBACK=FAILED_" + str(failure), flush=True)
        raise


if __name__ == "__main__":
    try:
        run()
    except RepairFailure as error:
        print("ORDAX_EGRESS_FINAL=" + str(error), flush=True)
        raise SystemExit(1)
    except Exception:
        print("ORDAX_EGRESS_FINAL=unexpected_failure", flush=True)
        raise SystemExit(1)
