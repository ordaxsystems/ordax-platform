"""Reconcile the existing OrdaX Hyperdrive with the canonical PostgreSQL SSOT.

Run only from the authorized cloudflare-v3 GitHub Actions environment.
Never print or persist a plaintext password, database verifier or API token.
The existing restricted PostgreSQL role and Hyperdrive identity are preserved.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import time
import urllib.error
import urllib.request


class RecoveryFailure(RuntimeError):
    pass


ROOT = Path(__file__).resolve().parents[2]
FOUNDATION_PATH = ROOT / "control-plane/cloudflare/production-foundation.json"


def canonical_authority() -> dict:
    try:
        foundation = json.loads(FOUNDATION_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise RecoveryFailure("canonical_foundation_unavailable") from None
    hyper = (foundation.get("live_evidence") or {}).get("hyperdrive") or {}
    postgres = foundation.get("postgres") or {}
    authority = {
        "account": foundation.get("account_id"),
        "project": postgres.get("project_ref"),
        "hyperdrive_id": hyper.get("id"),
        "hyperdrive_name": hyper.get("name"),
        "host": hyper.get("origin_host"),
        "port": hyper.get("origin_port"),
        "database": hyper.get("database"),
        "role": hyper.get("runtime_role"),
        "postgres_role": postgres.get("runtime_role"),
        "connection_limit": hyper.get("origin_connection_limit"),
        "cache_disabled": hyper.get("query_cache_disabled"),
        "sslmode": hyper.get("sslmode"),
    }
    if not isinstance(authority["account"], str) or not re.fullmatch(r"[a-f0-9]{32}", authority["account"]):
        raise RecoveryFailure("canonical_foundation_invalid")
    if not isinstance(authority["project"], str) or not re.fullmatch(r"[a-z0-9]{10,40}", authority["project"]):
        raise RecoveryFailure("canonical_foundation_invalid")
    if not isinstance(authority["hyperdrive_id"], str) or not re.fullmatch(
            r"[a-f0-9]{32}", authority["hyperdrive_id"]):
        raise RecoveryFailure("canonical_foundation_invalid")
    if not isinstance(authority["hyperdrive_name"], str) or not authority["hyperdrive_name"]:
        raise RecoveryFailure("canonical_foundation_invalid")
    expected_host = f"db.{authority['project']}.supabase.co"
    if authority["host"] != expected_host:
        raise RecoveryFailure("canonical_hyperdrive_origin_not_direct")
    if not isinstance(authority["port"], int) or not 1 <= authority["port"] <= 65535:
        raise RecoveryFailure("canonical_foundation_invalid")
    if authority["database"] != "postgres":
        raise RecoveryFailure("canonical_foundation_invalid")
    if (not isinstance(authority["role"], str) or authority["role"] != authority["postgres_role"]
            or not re.fullmatch(r"[a-z0-9_]{3,63}", authority["role"])):
        raise RecoveryFailure("canonical_foundation_invalid")
    if not isinstance(authority["connection_limit"], int) or authority["connection_limit"] < 5:
        raise RecoveryFailure("canonical_foundation_invalid")
    if authority["cache_disabled"] is not True or authority["sslmode"] != "require":
        raise RecoveryFailure("canonical_foundation_invalid")
    return authority


AUTHORITY = canonical_authority()
ACCOUNT = AUTHORITY["account"]
PROJECT = AUTHORITY["project"]
HYPERDRIVE = AUTHORITY["hyperdrive_id"]
HYPERDRIVE_NAME = AUTHORITY["hyperdrive_name"]
ROLE = AUTHORITY["role"]
HOST = AUTHORITY["host"]
PORT = AUTHORITY["port"]
DATABASE = AUTHORITY["database"]
CONNECTION_LIMIT = AUTHORITY["connection_limit"]
SSLMODE = AUTHORITY["sslmode"]
CF_ROOT = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}"
DB_QUERY = f"https://api.supabase.com/v1/projects/{PROJECT}/database/query"
READY_URL = "https://mcp.ordax.com.br/ready"


def literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def response_rows(body: object) -> list:
    if isinstance(body, list):
        return body
    if isinstance(body, dict) and isinstance(body.get("result"), list):
        return body["result"]
    if isinstance(body, dict) and isinstance(body.get("data"), list):
        return body["data"]
    raise RecoveryFailure("unexpected_database_response_shape")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RecoveryFailure("provider_redirect_forbidden")


OPENER = urllib.request.build_opener(NoRedirect)


def request(method: str, url: str, token: str, payload: dict | None = None) -> object:
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        url, method=method, headers=headers,
        data=json.dumps(payload).encode() if payload is not None else None,
    )
    try:
        with OPENER.open(req, timeout=25) as res:
            raw = res.read(262144)
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        # Provider messages may echo credentials. Emit only HTTP status and one
        # bounded numeric Cloudflare code, never the response message/body.
        safe_code = None
        if url.startswith(CF_ROOT + "/") and exc.code == 400:
            try:
                body = json.loads(exc.read(8192))
                errors = body.get("errors", []) if isinstance(body, dict) else []
                for entry in errors if isinstance(errors, list) else []:
                    code = entry.get("code") if isinstance(entry, dict) else None
                    if type(code) is int and 0 <= code <= 999999:
                        safe_code = code
                        break
            except (ValueError, OSError):
                pass
        suffix = f"_cf_{safe_code}" if safe_code is not None else ""
        raise RecoveryFailure(f"provider_http_{exc.code}{suffix}") from None
    except (urllib.error.URLError, TimeoutError):
        raise RecoveryFailure("provider_connection_unavailable") from None
    except ValueError:
        raise RecoveryFailure("provider_invalid_json") from None


def database_sql(token: str, sql: str) -> list:
    return response_rows(request("POST", DB_QUERY, token, {"query": sql}))


def _hyperdrive_result(cf_token: str) -> dict:
    body = request("GET", f"{CF_ROOT}/hyperdrive/configs/{HYPERDRIVE}", cf_token)
    if not isinstance(body, dict) or body.get("success") is not True:
        raise RecoveryFailure("hyperdrive_fetch_failed")
    result = body.get("result")
    if not isinstance(result, dict):
        raise RecoveryFailure("hyperdrive_fetch_failed")
    if result.get("id") not in (None, HYPERDRIVE) or result.get("name") != HYPERDRIVE_NAME:
        raise RecoveryFailure("unexpected_hyperdrive_identity")
    return result


def assert_hyperdrive(cf_token: str, *, allow_migration_source: bool = False) -> str:
    result = _hyperdrive_result(cf_token)
    origin = result.get("origin") or {}
    if not isinstance(origin, dict):
        raise RecoveryFailure("unexpected_hyperdrive_origin")

    canonical = (
        origin.get("host") == HOST
        and origin.get("port") == PORT
        and origin.get("user") == ROLE
        and origin.get("database") == DATABASE
        and origin.get("scheme") in ("postgres", "postgresql")
    )
    # One-time migration guard: only a Supabase pooler for THIS project/role is
    # accepted as the source of reconciliation. Arbitrary drift remains blocked.
    migration_source = (
        allow_migration_source
        and isinstance(origin.get("host"), str)
        and origin["host"].endswith(".pooler.supabase.com")
        and origin.get("port") in (5432, 6543)
        and origin.get("user") == ROLE + "." + PROJECT
        and origin.get("database") == DATABASE
        and origin.get("scheme") in ("postgres", "postgresql")
    )
    if not canonical and not migration_source:
        raise RecoveryFailure("unexpected_hyperdrive_origin")

    if result.get("mtls", {}).get("sslmode") != SSLMODE:
        raise RecoveryFailure("tls_requirement_not_met")
    caching = result.get("caching")
    if not isinstance(caching, dict) or caching.get("disabled") is not True:
        raise RecoveryFailure("hyperdrive_cache_policy_drift")
    if result.get("origin_connection_limit") != CONNECTION_LIMIT:
        raise RecoveryFailure("hyperdrive_connection_limit_drift")
    return "canonical" if canonical else "migration_source"


def inspect_role(db_token: str) -> str:
    rows = database_sql(
        db_token,
        "SELECT rolpassword AS verifier, rolcanlogin AS login, "
        "(rolvaliduntil IS NULL OR rolvaliduntil > now()) AS valid "
        "FROM pg_authid WHERE rolname = " + literal(ROLE),
    )
    if len(rows) != 1 or not isinstance(rows[0], dict):
        raise RecoveryFailure("runtime_role_not_found")
    row = rows[0]
    if row.get("login") is not True or row.get("valid") is not True:
        raise RecoveryFailure("runtime_role_ineligible")
    verifier = row.get("verifier")
    if not isinstance(verifier, str) or not verifier.startswith("SCRAM-SHA-256$"):
        raise RecoveryFailure("runtime_role_verifier_unavailable")
    return verifier


def update_role(db_token: str, credential: str) -> None:
    request(
        "POST", DB_QUERY, db_token,
        {"query": "ALTER ROLE " + ROLE + " WITH PASSWORD " + literal(credential)},
    )


def patch_hyperdrive(cf_token: str, credential: str) -> None:
    result = request(
        "PATCH", f"{CF_ROOT}/hyperdrive/configs/{HYPERDRIVE}", cf_token,
        {
            "origin": {
                "host": HOST,
                "port": PORT,
                "database": DATABASE,
                "scheme": "postgres",
                "user": ROLE,
                "password": credential,
            },
            "mtls": {"sslmode": SSLMODE},
            "caching": {"disabled": True},
            "origin_connection_limit": CONNECTION_LIMIT,
        },
    )
    if not isinstance(result, dict) or result.get("success") is not True:
        raise RecoveryFailure("hyperdrive_update_uncertain")


def restart_hyperdrive(cf_token: str) -> None:
    response = request(
        "POST", f"{CF_ROOT}/hyperdrive/configs/{HYPERDRIVE}/restart", cf_token, {},
    )
    if not isinstance(response, dict) or response.get("success") is not True:
        raise RecoveryFailure("hyperdrive_restart_failed")


def ready() -> bool:
    req = urllib.request.Request(READY_URL, headers={"Accept": "application/json"})
    try:
        with OPENER.open(req, timeout=12) as res:
            value = json.load(res)
            return bool(
                res.status == 200
                and value.get("ok") is True
                and value.get("postgres_ready") is True
                and value.get("oauth_discovery_ready") is True
                and value.get("supports_remote_actions") is True
            )
    except (urllib.error.URLError, ValueError, TimeoutError, RecoveryFailure):
        return False


def main() -> int:
    cf = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    db = os.environ.get("SUPABASE_ACCESS_TOKEN", "")
    if not cf or not db:
        print("ORDAX_RECOVERY=BLOCKED_MISSING_AUTHORIZED_CREDENTIALS")
        return 3

    try:
        state = assert_hyperdrive(cf, allow_migration_source=True)
        if state == "canonical" and ready():
            print("ORDAX_RECOVERY=ALREADY_HEALTHY_NO_ROTATION")
            return 0

        previous_verifier = inspect_role(db)
        print("ORDAX_RECOVERY_FOUNDATION=VERIFIED")
        credential = secrets.token_urlsafe(48)
        update_role(db, credential)

        try:
            # Hyperdrive validates the supplied direct-origin credential during
            # PATCH. A definitive provider rejection means the write did not
            # commit and the database verifier can be safely restored.
            patch_hyperdrive(cf, credential)
        except RecoveryFailure as exc:
            provider_status = str(exc).split("_cf_", 1)[0]
            if provider_status in (
                "provider_http_400", "provider_http_401", "provider_http_403",
                "provider_http_404", "provider_http_422",
            ):
                update_role(db, previous_verifier)
                print("ORDAX_RECOVERY=ROLLED_BACK_AFTER_CLOUDFLARE_REJECTION")
            else:
                print("ORDAX_RECOVERY=AMBIGUOUS_WRITE_REQUIRES_OPERATOR_REVIEW")
            raise

        # From this point the old Cloudflare password is unrecoverable by API:
        # never restore only the DB side. Prove exact SSOT before restart.
        if assert_hyperdrive(cf) != "canonical":
            raise RecoveryFailure("hyperdrive_canonical_reconciliation_failed")
        restart_hyperdrive(cf)
        print("ORDAX_HYPERDRIVE_ORIGIN_RECONCILED=PASS")
        print("ORDAX_RECOVERY_CREDENTIALS_SYNCHRONIZED=PASS")

        for attempt in range(8):
            if ready():
                print("ORDAX_MCP_POSTGRES_READY=PASS")
                return 0
            if attempt != 7:
                time.sleep(10)
        print("ORDAX_MCP_POSTGRES_READY=FAIL_AFTER_SYNCHRONIZATION")
        return 4
    except (RecoveryFailure, OSError, ValueError) as exc:
        print(
            "ORDAX_RECOVERY_FAILED="
            + (str(exc) if isinstance(exc, RecoveryFailure)
               else "transport_or_connectivity")
        )
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
