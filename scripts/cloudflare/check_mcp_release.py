#!/usr/bin/env python3
"""Release guards for OrdaX's ONE public MCP endpoint, independent of old D1.

Production remains fail-closed until the full E2E proof set exists. A separate
attested interactive candidate gate may deploy the canonical PostgreSQL/OAuth
Worker for real-device validation while production readiness remains false.
"""
from __future__ import annotations
import argparse
import json
import re
import sys
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
FOUNDATION=ROOT/"control-plane/cloudflare/production-foundation.json"
CONFIG=ROOT/"control-plane/cloudflare/wrangler.mcp.toml"
ENTRY=ROOT/"control-plane/cloudflare/src/product_mcp_entry.ts"

class McpReleaseError(ValueError):
    pass

REQUIRED_PROOFS=frozenset({
    "custom_domain_tls_run_url",
    "oauth_chatgpt_consent_run_url",
    "paired_device_and_grants_run_url",
    "trusted_host_attestation_run_url",
    "remote_actions_contract_run_url",
    "multi_device_end_to_end_run_url",
    "legacy_worker_retirement_run_url",
})
VALIDATION_BASELINE_EVIDENCE=frozenset({
    "candidate_run_url",
    "control_plane_ci_run_url",
    "canary_run_url",
    "chatgpt_oauth_client_id",
    "chatgpt_oauth_consent_granted_at",
})
CHATGPT_OAUTH_CLIENT_ID="95d41a8f-0fb8-4c4b-9757-83ba6345062d"
RUN_URL_RE=re.compile(r"https://github\.com/ordaxsystems/ordax-platform/actions/runs/[0-9]+")
TRUSTED_CLIENT_INGRESS={
    "hostname":"ordax-mcp.ordaxsystems.workers.dev",
    "workers_dev_enabled":True,
    "public_mcp_exposed":False,
    "authority":"same_worker_postgresql_oauth",
    "allowed_exact_paths":[
        "/v3/product/session",
        "/v3/product/device/setup",
        "/v3/product/device/central-session",
        "/v3/owner/remote-authority",
        "/v3/owner/remote-grant-groups",
    ],
    "allowed_path_prefixes":[
        "/v3/device/transport/",
        "/v3/owner/remote-grant-groups/",
    ],
}


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
    if release.get("entrypoint")!="src/product_mcp_entry.ts" or config.get("main")!="src/product_mcp_entry.ts":
        raise McpReleaseError("mcp_entrypoint_not_canonical")
    if release.get("transport")!="streamable-http" or release.get("authority")!="postgresql":
        raise McpReleaseError("mcp_transport_or_authority_not_canonical")
    if (release.get("custom_domain_required") is not True
        or release.get("workers_dev") is not False
        or config.get("preview_urls") is not False):
        raise McpReleaseError("mcp_public_surface_must_remain_custom_domain_only")
    trusted_ingress=release.get("trusted_client_ingress")
    if trusted_ingress!=TRUSTED_CLIENT_INGRESS or config.get("workers_dev") is not True:
        raise McpReleaseError("mcp_trusted_client_ingress_contract_invalid")
    if "device_machine_ingress" in release:
        raise McpReleaseError("mcp_obsolete_device_machine_ingress_present")
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

    code=ENTRY.read_text("utf-8")
    for required in (
        'PRODUCT_TRUSTED_CLIENT_HOSTNAME = "ordax-mcp.ordaxsystems.workers.dev"',
        "isProductTrustedClientPath",
        "PRODUCT_OWNER_SESSION_PATH",
        "PRODUCT_DEVICE_SETUP_PATH",
        "PRODUCT_DEVICE_CENTRAL_SESSION_PATH",
        "PRODUCT_DEVICE_TRANSPORT_PREFIX",
        "PRODUCT_OWNER_REMOTE_AUTHORITY_PATH",
        "PRODUCT_OWNER_REMOTE_GRANT_GROUPS_PATH",
    ):
        if required not in code:
            raise McpReleaseError("mcp_trusted_client_ingress_source_guard_missing")
    for obsolete in ("PRODUCT_DEVICE_MACHINE_HOSTNAME", "isProductDeviceMachinePath"):
        if obsolete in code:
            raise McpReleaseError("mcp_obsolete_device_machine_ingress_source_present")

    blocked=release.get("readiness_blockers")
    ready=release.get("deployment_ready")
    remote_actions=release.get("supports_remote_actions")
    if not isinstance(ready,bool) or not isinstance(remote_actions,bool) or not isinstance(blocked,list) or any(
        not isinstance(x,str) or not re.fullmatch("[a-z0-9_]{8,120}",x) for x in blocked
    ) or len(set(blocked))!=len(blocked):
        raise McpReleaseError("mcp_release_status_invalid")
    if ready==bool(blocked):
        raise McpReleaseError("mcp_release_status_inconsistent")
    if not ready:
        if remote_actions:
            if "attested_interactive_end_to_end_not_verified" not in blocked:
                raise McpReleaseError("mcp_interactive_e2e_blocker_missing")
        elif "canonical_remote_actions_not_ready" not in blocked:
            raise McpReleaseError("mcp_remote_actions_blocker_missing")
        return False
    if remote_actions is not True:
        raise McpReleaseError("mcp_remote_actions_not_ready")

    proofs=release.get("release_evidence")
    if not isinstance(proofs,dict) or set(proofs)!=REQUIRED_PROOFS:
        raise McpReleaseError("mcp_release_missing_independent_proofs")
    for key,value in proofs.items():
        if not isinstance(value,str) or not re.fullmatch(
            r"https://github\.com/ordaxsystems/(ordax-platform|ordax-apps|ordax-os)/actions/runs/[0-9]+",value
        ):
            raise McpReleaseError(f"mcp_release_invalid_proof_{key}")
    if not release.get("device_dispatch_via_trusted_host_verified",False):
        raise McpReleaseError("mcp_device_dispatch_not_verified")
    return True


def validate_interactive_candidate(foundation:dict,config:dict)->bool:
    """Allow real-device candidate deployment without claiming production readiness."""
    production_ready=validate(foundation,config)
    if production_ready:
        raise McpReleaseError("candidate_gate_cannot_authorize_production_release")
    release=foundation["mcp_release"]
    if release.get("validation_mode")!="attested-interactive-candidate":
        raise McpReleaseError("mcp_interactive_candidate_mode_invalid")
    if release.get("validation_deployment_ready") is not True:
        raise McpReleaseError("mcp_interactive_candidate_not_ready")
    if release.get("supports_remote_actions") is not True:
        raise McpReleaseError("mcp_interactive_candidate_remote_actions_required")
    if release.get("conversation_topology")!="user_chatgpt_direct" or release.get("model_relay") is not False:
        raise McpReleaseError("mcp_interactive_candidate_topology_invalid")
    blockers=set(release.get("readiness_blockers") or [])
    if "attested_interactive_end_to_end_not_verified" not in blockers:
        raise McpReleaseError("mcp_interactive_candidate_e2e_blocker_missing")

    evidence=release.get("oauth_baseline_evidence")
    if not isinstance(evidence,dict) or set(evidence)!=VALIDATION_BASELINE_EVIDENCE:
        raise McpReleaseError("mcp_interactive_baseline_evidence_incomplete")
    for key in ("candidate_run_url","control_plane_ci_run_url","canary_run_url"):
        value=evidence.get(key)
        if not isinstance(value,str) or RUN_URL_RE.fullmatch(value) is None:
            raise McpReleaseError(f"mcp_interactive_baseline_invalid_{key}")
    client_id=evidence.get("chatgpt_oauth_client_id")
    try:
        canonical=str(uuid.UUID(str(client_id)))
    except (ValueError,AttributeError,TypeError):
        raise McpReleaseError("mcp_interactive_chatgpt_client_invalid") from None
    if canonical!=CHATGPT_OAUTH_CLIENT_ID or client_id!=canonical:
        raise McpReleaseError("mcp_interactive_chatgpt_client_invalid")
    consent=evidence.get("chatgpt_oauth_consent_granted_at")
    if not isinstance(consent,str) or not consent.endswith("Z"):
        raise McpReleaseError("mcp_interactive_consent_timestamp_invalid")
    try:
        when=datetime.fromisoformat(consent[:-1]+"+00:00")
    except ValueError:
        raise McpReleaseError("mcp_interactive_consent_timestamp_invalid") from None
    if when.tzinfo is None or when.astimezone(timezone.utc).isoformat().endswith("+00:00") is False:
        raise McpReleaseError("mcp_interactive_consent_timestamp_invalid")

    code=ENTRY.read_text("utf-8")
    required=(
        "PRODUCT_MCP_CORE_READ_TOOLS",
        "PRODUCT_MCP_DIRECT_TOOLS",
        "ATTESTED_DEVICE_ACTION_TOOLS",
        "createAttestedDeviceActionHandler",
        "supports_attested_remote_reads: true",
        "supports_remote_actions: true",
        "supports_project_continuity: true",
        "trusted_operation_required",
        "createCanonicalProductMcpReadHandlers",
        "PRODUCT_TRUSTED_CLIENT_HOSTNAME",
        "isProductTrustedClientPath",
    )
    if any(item not in code for item in required):
        raise McpReleaseError("mcp_interactive_entry_contract_missing")
    forbidden=("D1Database","env.DB.prepare","ordax-control-plane-v3","operatorAuthorized(")
    if any(item in code for item in forbidden):
        raise McpReleaseError("mcp_interactive_legacy_authority_detected")
    return True


def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument("--inspect",action="store_true",
        help="Allow a blocked production candidate for CI/audit; NEVER authorizes production deploy.")
    parser.add_argument("--validation-candidate",action="store_true",
        help="Authorize the canonical attested interactive candidate for real-device E2E.")
    opt=parser.parse_args()
    try:
        data=json.loads(FOUNDATION.read_text("utf-8"))
        with CONFIG.open("rb") as stream:
            config=tomllib.load(stream)
        if opt.validation_candidate:
            if not validate_interactive_candidate(data,config):
                raise McpReleaseError("mcp_interactive_candidate_not_ready")
            print("ORDAX_MCP_ATTESTED_INTERACTIVE_CANDIDATE=ELIGIBLE")
            return 0
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
