#!/usr/bin/env python3
"""Release guard for OrdaX's ONE public MCP endpoint, independent of old D1.

The legacy Control Plane config is NEVER a fallback or deployment target.
Blocked state is an expected green result only in CI inspection mode.
"""
from __future__ import annotations
import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
FOUNDATION=ROOT/"control-plane/cloudflare/production-foundation.json"
CONFIG=ROOT/"control-plane/cloudflare/wrangler.mcp.toml"

class McpReleaseError(ValueError):
    pass

# These six proofs must be provided by independent service/CI evidence before
# production cutover. Source flags alone do not constitute readiness.
REQUIRED_PROOFS=frozenset({
    "custom_domain_tls_run_url",
    "oauth_chatgpt_consent_run_url",
    "paired_device_and_grants_run_url",
    "trusted_host_attestation_run_url",
    "multi_device_end_to_end_run_url",
    "legacy_worker_retirement_run_url",
})

def validate(foundation:dict,config:dict)->bool:
    release=foundation.get("mcp_release")
    if not isinstance(release,dict):
        raise McpReleaseError("canonical_mcp_release_missing")
    if release.get("worker_name")!="ordax-mcp" or config.get("name")!="ordax-mcp":
        raise McpReleaseError("mcp_name_not_canonical")
    if release.get("hostname")!="mcp.ordax.com.br" or release.get("path")!="/mcp":
        raise McpReleaseError("mcp_public_hostname_not_canonical")
    if release.get("wrangler")!="control-plane/cloudflare/wrangler.mcp.toml":
        raise McpReleaseError("mcp_release_config_not_canonical")
    if (release.get("entrypoint")!="src/product_mcp_entry.ts" or
        config.get("main")!="src/product_mcp_entry.ts"):
        raise McpReleaseError("mcp_entrypoint_not_canonical")
    if release.get("transport")!="streamable-http" or release.get("authority")!="postgresql":
        raise McpReleaseError("mcp_transport_or_authority_not_canonical")
    if (release.get("custom_domain_required") is not True
        or release.get("workers_dev") is not False
        or config.get("workers_dev") is not False
        or config.get("preview_urls") is not False):
        raise McpReleaseError("mcp_workers_dev_must_be_disabled")
    if any(key in config for key in (
        "d1_databases","kv_namespaces","durable_objects","r2_buckets",
        "services","routes","unsafe")):
        raise McpReleaseError("mcp_must_not_bind_other_authorities_or_routes")
    policy=release.get("safety") or {}
    if any(policy.get(k) is not False for k in (
        "allow_d1","allow_legacy_fallback","allow_untrusted_model_dispatch",
        "allow_production_release_without_e2e")):
        raise McpReleaseError("mcp_security_policy_incomplete")
    if foundation.get("account_id")!="42586bf13b61436219d21def299833e4":
        raise McpReleaseError("mcp_wrong_cloudflare_account")
    postgres=foundation.get("postgres") or {}
    issuer=f"https://{postgres.get('project_ref')}.supabase.co/auth/v1"
    if issuer!="https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1" or release.get("oauth_issuer")!=issuer:
        raise McpReleaseError("mcp_wrong_oauth_issuer")
    vars=config.get("vars") or {}
    if vars != {
        "PRODUCT_AUTH_ISSUER":issuer,
        "PRODUCT_AUTH_AUDIENCE":"authenticated",
        "PRODUCT_AUTH_JWKS_URL":issuer+"/.well-known/jwks.json",
    }:
        raise McpReleaseError("mcp_auth_vars_not_canonical")
    hyperdrive=foundation.get("live_evidence",{}).get("hyperdrive",{})
    if config.get("hyperdrive")!=[{
        "binding":"POSTGRES","id":hyperdrive.get("id")
    }] or hyperdrive.get("id")!="4b601ec5815f43259bd8040053825d2a":
        raise McpReleaseError("mcp_hyperdrive_not_canonical")

    blocked=release.get("readiness_blockers")
    ready=release.get("deployment_ready")
    if not isinstance(ready,bool) or not isinstance(blocked,list) or any(
        not isinstance(x,str) or not re.fullmatch("[a-z0-9_]{8,120}",x) for x in blocked
    ) or len(set(blocked))!=len(blocked):
        raise McpReleaseError("mcp_release_status_invalid")
    if ready==bool(blocked):
        raise McpReleaseError("mcp_release_status_inconsistent")
    if not ready:
        return False

    proofs=release.get("release_evidence")
    if not isinstance(proofs,dict) or set(proofs)!=REQUIRED_PROOFS:
        raise McpReleaseError("mcp_release_missing_independent_proofs")
    for key,value in proofs.items():
        if not isinstance(value,str) or not re.fullmatch(
            r"https://github\.com/ordaxsystems/(ordax-platform|ordax-apps|ordax-os)/actions/runs/[0-9]+",value
        ):
            raise McpReleaseError(f"mcp_release_invalid_proof_{key}")
    # A real production dispatcher also requires verified host attestation;
    # the read-only canary source must not be silently promoted as executor.
    if not release.get("device_dispatch_via_trusted_host_verified",False):
        raise McpReleaseError("mcp_device_dispatch_not_verified")
    return True

def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--inspect",action="store_true",
        help="Allow the blocked candidate for CI/audit; NEVER authorizes deploy.")
    opt=parser.parse_args()
    try:
        data=json.loads(FOUNDATION.read_text("utf-8"))
        with CONFIG.open("rb") as stream:
            config=tomllib.load(stream)
        ready=validate(data,config)
    except (ValueError,KeyError,TypeError,OSError) as error:
        print(f"ORDAX_MCP_RELEASE_GUARD=INVALID {error}",file=sys.stderr)
        return 2
    if not ready:
        print(f"ORDAX_MCP_RELEASE=BLOCKED ({len(data['mcp_release']['readiness_blockers'])} verified blockers)")
        return 0 if opt.inspect else 3
    print("ORDAX_MCP_RELEASE=ELIGIBLE_REQUIRES_REAL_PUBLIC_SMOKE")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
