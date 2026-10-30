#!/usr/bin/env python3
"""Single deploy-readiness gate for the OrdaX Cloudflare production Worker.

The GitHub workflow may validate a blocked foundation; direct deploy scripts
must reject it before any Cloudflare API requests or Wrangler invocation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FOUNDATION = ROOT / "control-plane/cloudflare/production-foundation.json"
WRANGLER = ROOT / "control-plane/cloudflare/wrangler.toml"
WORKER_SOURCES = ROOT / "control-plane/cloudflare/src"


BOOTSTRAP_BLOCKERS = frozenset({
    "worker_not_provisioned",
    "cloudflare_ci_worker_editor_token_not_provisioned",
})


class DeployGateError(ValueError):
    pass


D1_ACCESS_RE = re.compile(
    r"""(?<![A-Za-z0-9_])(?:this\s*\??\.\s*)?env\s*(?:\??\.\s*DB\b|(?:\?\.\s*)?\[\s*['"`]DB['"`]\s*\])"""
)
D1_TABLE_RE = re.compile(
    r"\b(?:from|join|into|update|table)\s+(ordax_[a-z0-9_]+)",
    re.IGNORECASE,
)


def d1_access_count(source: str) -> int:
    """Count direct, computed and optional-chained legacy D1 environment access."""
    return len(D1_ACCESS_RE.findall(source))


def d1_source_names(sources: dict[str, str]) -> set[str]:
    """Shared Worker inventory rule for CI tests and the deployment boundary."""
    return {
        name for name, source in sources.items()
        if "D1Database" in source or d1_access_count(source) > 0
    }


WORKER_CODE_SUFFIXES = frozenset({".ts", ".tsx", ".mts", ".js", ".jsx", ".mjs"})


def worker_source_texts(root: Path) -> dict[str, str]:
    """Use one recursive source inventory in CI audits and production deploy."""
    return {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.suffix in WORKER_CODE_SUFFIXES
    }


def validate(data: dict, config: dict, source: str, account_id: str | None = None, *, bootstrap: bool = False) -> bool:
    canonical_account = data.get("account_id")
    if not isinstance(canonical_account, str) or not re.fullmatch(r"[0-9a-f]{32}", canonical_account):
        raise DeployGateError("invalid canonical account ID")
    if account_id is not None and account_id != canonical_account:
        raise DeployGateError("deploy account differs from canonical Cloudflare account")

    worker_name = data.get("worker_name")
    if not isinstance(worker_name, str) or config.get("name") != worker_name:
        raise DeployGateError("Worker name differs from canonical foundation")

    authorities = data.get("authorities") or {}
    if (authorities.get("persistent"), authorities.get("artifacts"),
            authorities.get("realtime_session_coordination")) != (
            "postgresql", "r2", "durable_objects"):
        raise DeployGateError("non-canonical persistent/artifact/realtime authorities")

    policy = data.get("policy") or {}
    if policy.get("allow_d1") is not False or policy.get("allow_dual_write") is not False:
        raise DeployGateError("D1 or dual-write permitted by foundation")
    forbidden = set(policy.get("forbidden_runtime_secrets") or [])
    if not {"SUPABASE_SERVER_KEY", "SUPABASE_SERVICE_ROLE_KEY", "ORDAX_OPERATOR_TOKEN"}.issubset(forbidden):
        raise DeployGateError("forbidden runtime secrets policy incomplete")
    if (data.get("security") or {}).get("require_two_factor") is not True:
        raise DeployGateError("2FA security requirement missing")
    account_security = (data.get("live_evidence") or {}).get("security") or {}
    if (account_security.get("member_two_factor_enabled") is not True
            or account_security.get("account_enforce_twofactor") is not True):
        raise DeployGateError("account 2FA enforcement evidence missing")

    postgres = data.get("postgres") or {}
    if postgres.get("runtime_transport") != "hyperdrive" or postgres.get("hyperdrive_binding") != "POSTGRES":
        raise DeployGateError("PostgreSQL transport/binding must use Hyperdrive POSTGRES")
    if postgres.get("query_cache") != "disabled":
        raise DeployGateError("Hyperdrive query cache must be disabled")
    # Fail closed even while the deployment is blocked. A future release must
    # never accidentally combine the canonical database with a legacy identity
    # provider or a second Supabase OAuth consent project.
    ref = postgres.get("project_ref")
    if not isinstance(ref, str) or not re.fullmatch(r"[a-z0-9]{20}", ref):
        raise DeployGateError("canonical Supabase project ref is invalid")
    issuer = f"https://{ref}.supabase.co/auth/v1"
    public_auth = config.get("vars") or {}
    if public_auth.get("PRODUCT_AUTH_ISSUER") != issuer:
        raise DeployGateError("Product OAuth issuer differs from canonical PostgreSQL project")
    if public_auth.get("PRODUCT_AUTH_JWKS_URL") != issuer + "/.well-known/jwks.json":
        raise DeployGateError("Product OAuth JWKS differs from canonical Supabase issuer")
    if public_auth.get("PRODUCT_AUTH_AUDIENCE") != "authenticated":
        raise DeployGateError("Product OAuth audience differs from canonical Supabase Auth")
    publishable = public_auth.get("SUPABASE_PUBLISHABLE_KEY")
    if not isinstance(publishable, str) or not re.fullmatch(
        r"sb_publishable_[A-Za-z0-9_-]{16,}", publishable
    ):
        raise DeployGateError("canonical Supabase public browser key is missing or invalid")

    evidence = (data.get("live_evidence") or {}).get("hyperdrive") or {}
    hyperdrive = config.get("hyperdrive") or []
    if (not isinstance(hyperdrive, list) or len(hyperdrive) != 1
            or hyperdrive[0].get("binding") != "POSTGRES"
            or hyperdrive[0].get("id") != evidence.get("id")
            or evidence.get("name") != data.get("hyperdrive_name")
            or evidence.get("runtime_role") != postgres.get("runtime_role")
            or evidence.get("query_cache_disabled") is not True
            or evidence.get("sslmode") != "require"):
        raise DeployGateError("Hyperdrive binding/evidence mismatch")

    # Retired runtime WebSocket and artifact handlers have been deleted.
    # No unused DO or R2 authority may be advertised until a canonical
    # implementation and fresh storage contracts have been reviewed.
    bindings = (config.get("durable_objects") or {}).get("bindings") or []
    if bindings:
        raise DeployGateError("retired Durable Objects bindings must be absent")
    buckets = config.get("r2_buckets") or []
    if buckets:
        raise DeployGateError("retired artifact R2 binding must be absent")

    ready = data.get("deployment_ready")
    blockers = data.get("readiness_blockers")
    if not isinstance(ready, bool) or not isinstance(blockers, list):
        raise DeployGateError("invalid deployment readiness structure")
    if any(not isinstance(blocker, str) or not blocker for blocker in blockers):
        raise DeployGateError("invalid readiness blocker")
    if len(blockers) != len(set(blockers)):
        raise DeployGateError("duplicate readiness blockers")
    if ready == bool(blockers):
        raise DeployGateError("deployment_ready contradicts readiness blockers")

    if bootstrap and (ready or set(blockers) != BOOTSTRAP_BLOCKERS):
        raise DeployGateError(
            "initial Worker bootstrap requires exactly the Worker and CI token blockers"
        )

    legacy_binding = bool(config.get("d1_databases"))
    legacy_source = d1_access_count(source) > 0 or "D1Database" in source
    if ready or bootstrap:
        if legacy_binding:
            raise DeployGateError("D1 binding remains in production Wrangler")
        if legacy_source:
            raise DeployGateError("legacy D1 access remains in Worker source")
        if "ORDAX_OPERATOR_TOKEN" in source or "operatorAuthorized(" in source:
            raise DeployGateError("legacy global operator bearer remains in Worker source")
        if "SUPABASE_SERVER_KEY" in source or "SUPABASE_SERVICE_ROLE_KEY" in source:
            raise DeployGateError("forbidden Supabase server secret remains in Worker source")
    if (legacy_binding or legacy_source) and "worker_d1_cutover_incomplete" not in blockers:
        raise DeployGateError("D1 cutover blocker missing while legacy authority remains")
    return ready


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--allow-blocked", action="store_true",
                      help="Inspect blocked foundation without authorizing deploy (CI only)")
    mode.add_argument("--bootstrap", action="store_true",
                      help="Permit initial Worker creation only after all runtime cutovers")
    parser.add_argument("--github-output", type=Path, default=None)
    args = parser.parse_args()
    if args.bootstrap and args.github_output is not None:
        parser.error("Bootstrap cannot write routine deployment readiness outputs")
    try:
        data = json.loads(FOUNDATION.read_text(encoding="utf-8"))
        with WRANGLER.open("rb") as stream:
            config = tomllib.load(stream)
        source_files = worker_source_texts(WORKER_SOURCES)
        if not source_files:
            raise DeployGateError("Cloudflare Worker sources not found")
        source = "\n".join(source_files.values())
        ready = validate(
            data, config, source, os.environ.get("CLOUDFLARE_ACCOUNT_ID"),
            bootstrap=args.bootstrap,
        )
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"Cloudflare deploy gate invalid: {error}", file=sys.stderr)
        return 2

    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"account_id={data['account_id']}\n")
            stream.write(f"deployment_ready={'true' if ready else 'false'}\n")

    if args.bootstrap:
        print("Cloudflare initial Worker bootstrap ELIGIBLE; routine production deployment remains blocked")
        return 0

    if not ready:
        print(f"Cloudflare production deployment BLOCKED ({len(data['readiness_blockers'])} blockers)")
        for blocker in data["readiness_blockers"]:
            print(f"  BLOCKER: {blocker}")
        if not args.allow_blocked:
            return 3
    else:
        print("Cloudflare production deployment READY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
