"""Synchronized recovery of the *existing* OrdaX PostgreSQL Hyperdrive credential.

Run only from the authorized cloudflare-v3 GitHub Actions environment.
Never print or persist a plaintext password, database verifier or API token.
The current canonical Postgres role and Hyperdrive are preserved.
"""
from __future__ import annotations
import json
import os
import secrets
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

ACCOUNT = "42586bf13b61436219d21def299833e4"
PROJECT = "jhfphsjptrpmtnzkpwud"
HYPERDRIVE = "4b601ec5815f43259bd8040053825d2a"
ROLE = "ordax_edge_runtime"
HOST = "aws-1-sa-east-1.pooler.supabase.com"
POOLER_USER = ROLE + "." + PROJECT
CF_ROOT = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}"
DB_QUERY = f"https://api.supabase.com/v1/projects/{PROJECT}/database/query"
READY_URL = "https://mcp.ordax.com.br/ready"


class RecoveryFailure(RuntimeError):
    pass


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
    # Hostname is selected only by the caller using the pinned endpoints above.
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, headers=headers,
                                 data=json.dumps(payload).encode() if payload is not None else None)
    try:
        with OPENER.open(req, timeout=25) as res:
            raw = res.read(262144)
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        # Providers may echo credentials in arbitrary messages. Emit only a
        # bounded, numeric Cloudflare error code, never any error body.
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
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RecoveryFailure("provider_connection_unavailable") from None
    except (ValueError, json.JSONDecodeError):
        raise RecoveryFailure("provider_invalid_json") from None


def database_sql(token: str, sql: str) -> list:
    return response_rows(request("POST", DB_QUERY, token, {"query": sql}))


def assert_hyperdrive(cf_token: str) -> None:
    body = request("GET", f"{CF_ROOT}/hyperdrive/configs/{HYPERDRIVE}", cf_token)
    if not isinstance(body, dict) or body.get("success") is not True:
        raise RecoveryFailure("hyperdrive_fetch_failed")
    origin = body.get("result", {}).get("origin", {})
    if (origin.get("host") != HOST or origin.get("port") != 5432
            or origin.get("user") != POOLER_USER or origin.get("database") != "postgres"):
        raise RecoveryFailure("unexpected_hyperdrive_origin")
    if body.get("result", {}).get("mtls", {}).get("sslmode") != "require":
        raise RecoveryFailure("tls_requirement_not_met")


def inspect_role(db_token: str) -> str:
    rows = database_sql(db_token,
        "SELECT rolpassword AS verifier, rolcanlogin AS login, "
        "(rolvaliduntil IS NULL OR rolvaliduntil > now()) AS valid "
        "FROM pg_authid WHERE rolname = " + literal(ROLE))
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
    # UPDATE may legitimately return an empty response: never misinterpret a
    # successful mutation as a parser error before updating Cloudflare.
    request("POST", DB_QUERY, db_token,
            {"query": "ALTER ROLE " + ROLE + " WITH PASSWORD " + literal(credential)})



def verify_pooler_credential(credential: str) -> None:
    """Prove the freshly rotated SCRAM credential through the real pooler.

    Cloudflare validates new Hyperdrive credentials during PATCH (error 2013
    when authentication fails). Supavisor can still have a cached old verifier.
    No Cloudflare write can precede an authenticated SELECT 1 using the exact
    same origin host, port, database and pooler user.
    """
    if shutil.which("psql") is None:
        raise RecoveryFailure("pooler_probe_cli_missing")
    # Do not pass Cloudflare/Supabase administration tokens into psql.
    env = {key: value for key, value in os.environ.items()
           if key in {"PATH", "HOME", "LANG", "LC_ALL", "SYSTEMROOT"}}
    env["PGPASSWORD"] = credential
    env["PGHOST"] = HOST
    env["PGPORT"] = "5432"
    env["PGDATABASE"] = "postgres"
    env["PGUSER"] = POOLER_USER
    env["PGSSLMODE"] = "require"
    env["PGCONNECT_TIMEOUT"] = "8"
    command = ["psql", "--no-psqlrc", "--no-password", "--tuples-only",
               "--no-align", "--command", "SELECT 1;"]
    # Never print stdout/stderr or a connection URI; only the fixed result.
    for attempt in range(18):
        try:
            outcome = subprocess.run(
                command, env=env, input=b"", stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False, timeout=14,
            )
            if outcome.returncode == 0 and outcome.stdout.strip() == b"1":
                return
        except (OSError, subprocess.TimeoutExpired):
            pass
        if attempt < 17:
            time.sleep(10)
    raise RecoveryFailure("pooler_new_credential_not_authenticated")


def patch_hyperdrive(cf_token: str, credential: str) -> None:
    result = request("PATCH", f"{CF_ROOT}/hyperdrive/configs/{HYPERDRIVE}",
                     cf_token, {"origin": {
                         # Host, port, user, database and TLS mode were checked
                         # by assert_hyperdrive and must remain unchanged.
                         "password": credential,
                     }})
    if not isinstance(result, dict) or result.get("success") is not True:
        raise RecoveryFailure("hyperdrive_update_uncertain")


def restart_hyperdrive(cf_token: str) -> None:
    response = request("POST", f"{CF_ROOT}/hyperdrive/configs/{HYPERDRIVE}/restart", cf_token, {})
    if not isinstance(response, dict) or response.get("success") is not True:
        raise RecoveryFailure("hyperdrive_restart_failed")


def ready() -> bool:
    req = urllib.request.Request(READY_URL, headers={"Accept": "application/json"})
    try:
        with OPENER.open(req, timeout=12) as res:
            value = json.load(res)
            return bool(res.status == 200 and value.get("ok") is True
                and value.get("postgres_ready") is True and value.get("oauth_discovery_ready") is True
                and value.get("supports_remote_actions") is True)
    except (urllib.error.URLError, ValueError, TimeoutError, RecoveryFailure):
        return False


def main() -> int:
    cf = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    db = os.environ.get("SUPABASE_ACCESS_TOKEN", "")
    if not cf or not db:
        print("ORDAX_RECOVERY=BLOCKED_MISSING_AUTHORIZED_CREDENTIALS")
        return 3
    try:
        assert_hyperdrive(cf)
        # Do not rotate a production credential when the canonical MCP is
        # already healthy. A recovery run must be idempotent, not disruptive.
        if ready():
            print("ORDAX_RECOVERY=ALREADY_HEALTHY_NO_ROTATION")
            return 0
        inspect = inspect_role(db)
        # Also prove the session-pooler IPv4 origin is routable from this
        # runner before changing any database credential.
        with socket.create_connection((HOST, 5432), timeout=8):
            pass
        # The runner must support an authenticated direct PostgreSQL probe
        # before a production credential is ever changed.
        if shutil.which("psql") is None:
            raise RecoveryFailure("pooler_probe_cli_missing")
        print("ORDAX_RECOVERY_PREFLIGHT=PASS")
        credential = secrets.token_urlsafe(48)
        update_role(db, credential)
        try:
            verify_pooler_credential(credential)
            print("ORDAX_POOLER_NEW_CREDENTIAL=AUTHENTICATED")
        except RecoveryFailure:
            update_role(db, inspect)
            print("ORDAX_RECOVERY=ROLLED_BACK_AFTER_POOLER_AUTH_FAILURE")
            raise
        try:
            patch_hyperdrive(cf, credential)
        except RecoveryFailure as exc:
            # Only a definitive 4xx write rejection guarantees no Cloudflare
            # update happened. Ambiguous transport errors must not revert
            # one side of the synchronized credential.
            provider_status = str(exc).split("_cf_", 1)[0]
            if provider_status in ("provider_http_400", "provider_http_401", "provider_http_403",
                                   "provider_http_404", "provider_http_422"):
                update_role(db, inspect)
                print("ORDAX_RECOVERY=ROLLED_BACK_AFTER_CLOUDFLARE_REJECTION")
            else:
                print("ORDAX_RECOVERY=AMBIGUOUS_WRITE_REQUIRES_OPERATOR_REVIEW")
            raise
        # The old CF password is write-only: after this point never restore
        # the prior database verifier without first restoring CF credentials.
        assert_hyperdrive(cf)
        restart_hyperdrive(cf)
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
        # Exception strings above are fixed allow-listed error labels only.
        print("ORDAX_RECOVERY_FAILED=" + (str(exc) if isinstance(exc, RecoveryFailure)
              else "transport_or_connectivity"))
        return 5


if __name__ == "__main__":
    raise SystemExit(main())
