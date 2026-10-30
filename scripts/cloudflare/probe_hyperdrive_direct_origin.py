"""One-shot origin-mode Hyperdrive probe; NEVER changes the canonical binding.

GitHub Actions is the only execution host. Secrets stay in runner memory; even
Cloudflare rejection bodies and subprocess logs are not printed. Ephemeral
database role has LOGIN only, with no table, function or schema grants.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ACCOUNT = "42586bf13b61436219d21def299833e4"
PROJECT = "jhfphsjptrpmtnzkpwud"
ORIGIN = f"db.{PROJECT}.supabase.co"
POOLER_ORIGIN = "aws-1-sa-east-1.pooler.supabase.com"
# Each mode gets its own short-lived role, config and Worker, never the Product
# MCP database role or live Hyperdrive. Compare paths before any production cutover.
ORIGIN_MODES = ("direct_ipv6", "pooler_session", "pooler_transaction")
CF_API = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}"
DB_API = f"https://api.supabase.com/v1/projects/{PROJECT}/database/query"
NAME_PREFIX = "ordax-direct-ipv6-diag-"
ROLE_PREFIX = "ordax_direct_diag_"
PROBE_DIR = Path(__file__).resolve().parents[2] / "control-plane" / "cloudflare"


class ProbeError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        raise ProbeError("unexpected_redirect")


OPENER = urllib.request.build_opener(NoRedirect)


def api(method: str, url: str, token: str | None = None, body: dict | None = None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers=headers, method=method)
    try:
        with OPENER.open(req, timeout=25) as response:
            raw = response.read(131072)
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        # The isolated Worker only returns a public-safe phase/classification.
        if exc.code == 503 and re.fullmatch(
            r"https://ordax-direct-ipv6-diag-[0-9]{5,16}[.]ordaxsystems[.]workers[.]dev/",
            url,
        ):
            try:
                report = json.loads(exc.read(8192))
                phase = report.get("phase") if isinstance(report, dict) else None
                label = report.get("classification") if isinstance(report, dict) else None
                if phase in ("connect", "query") and isinstance(label, str) and re.fullmatch(
                    r"[a-z_]{1,48}", label
                ):
                    return {"ok": False, "phase": phase, "classification": label}
            except (ValueError, OSError):
                pass
        # Provider error bodies can contain the submitted SQL/password.
        code = exc.code
        safe_cf = None
        if url.startswith(CF_API) and code in (400, 409, 422):
            try:
                value = json.loads(exc.read(8192))
                errs = value.get("errors", []) if isinstance(value, dict) else []
                for item in errs if isinstance(errs, list) else []:
                    val = item.get("code") if isinstance(item, dict) else None
                    if type(val) is int and 0 <= val <= 999999:
                        safe_cf = val
                        break
            except (ValueError, OSError):
                pass
        suffix = f"_cf_{safe_cf}" if safe_cf is not None else ""
        raise ProbeError(f"provider_http_{code}{suffix}") from None
    except (urllib.error.URLError, TimeoutError):
        raise ProbeError("provider_connection_unavailable") from None
    except (ValueError, UnicodeDecodeError):
        raise ProbeError("provider_invalid_json") from None


def sql(token: str, query: str):
    data = api("POST", DB_API, token, {"query": query})
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("result"), list):
        return data["result"]
    raise ProbeError("database_response_invalid")


def literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def identifiers(run_id: str) -> tuple[str, str]:
    if not re.fullmatch(r"[1-9][0-9]{4,15}", run_id):
        raise ProbeError("invalid_run_identity")
    return NAME_PREFIX + run_id, ROLE_PREFIX + run_id


def require_unique_role(token: str, role: str):
    rows = sql(token, f"select count(*)::int as n from pg_roles where rolname={literal(role)}")
    if len(rows) != 1 or rows[0].get("n") != 0:
        raise ProbeError("role_collision_or_database_unavailable")


def create_role(token: str, role: str, credential: str):
    # DDL may return an empty HTTP body on success; do not misparse it.
    api("POST", DB_API, token, {"query": f"create role {role} login password {literal(credential)}"})


def delete_role(token: str, role: str):
    api("POST", DB_API, token, {"query": f"drop role if exists {role}"})


def origin_for_mode(mode: str, role: str) -> dict:
    if mode not in ORIGIN_MODES:
        raise ProbeError("origin_mode_not_allowlisted")
    if mode == "direct_ipv6":
        return {"scheme": "postgres", "database": "postgres",
                "user": role, "host": ORIGIN, "port": 5432}
    return {"scheme": "postgres", "database": "postgres",
            "user": role + "." + PROJECT, "host": POOLER_ORIGIN,
            "port": 5432 if mode == "pooler_session" else 6543}


def verify_pooler_credential(mode: str, role: str, credential: str) -> None:
    """Prove the exact temporary tenant role before blaming Cloudflare.

    Supavisor may temporarily cache stale database role verifiers after CREATE
    ROLE or ALTER ROLE. A direct psql SELECT 1 rules out that misleading
    precondition; it never performs SQL writes or exposes the password.
    """
    if mode not in ("pooler_session", "pooler_transaction"):
        raise ProbeError("pooler_preflight_mode_invalid")
    if shutil.which("psql") is None:
        raise ProbeError("pooler_probe_cli_missing")
    origin = origin_for_mode(mode, role)
    env = {key: value for key, value in os.environ.items()
           if key in {"PATH", "HOME", "LANG", "LC_ALL", "SYSTEMROOT"}}
    env.update({"PGHOST": origin["host"], "PGPORT": str(origin["port"]),
                "PGDATABASE": "postgres", "PGUSER": origin["user"],
                "PGPASSWORD": credential, "PGSSLMODE": "require",
                "PGCONNECT_TIMEOUT": "6"})
    command = ["psql", "--no-psqlrc", "--no-password", "--tuples-only",
               "--no-align", "--command", "SELECT 1;"]
    for attempt in range(8):
        try:
            response = subprocess.run(command, input=b"", env=env,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      timeout=11, check=False)
            if response.returncode == 0 and response.stdout.strip() == b"1":
                return
        except (OSError, subprocess.TimeoutExpired):
            pass
        if attempt < 7:
            time.sleep(3)
    raise ProbeError("pooler_credential_not_authenticated")


def create_hyperdrive(token: str, name: str, role: str, credential: str,
                      mode: str = "direct_ipv6") -> str:
    origin = origin_for_mode(mode, role)
    origin["password"] = credential
    body = {"name": name,
            "origin": origin,
            "mtls": {"sslmode": "require"},
            "caching": {"disabled": True},
            "origin_connection_limit": 5}
    result = api("POST", CF_API + "/hyperdrive/configs", token, body)
    hid = result.get("result", {}).get("id") if isinstance(result, dict) else None
    if not result.get("success") or not isinstance(hid, str) or not re.fullmatch(r"[a-f0-9]{32}", hid):
        raise ProbeError("hyperdrive_create_invalid_receipt")
    return hid


def find_hyperdrive(token: str, name: str) -> str | None:
    result = api("GET", CF_API + "/hyperdrive/configs", token)
    rows = result.get("result") if isinstance(result, dict) else None
    if not isinstance(rows, list):
        raise ProbeError("hyperdrive_list_invalid")
    matching = [x.get("id") for x in rows if isinstance(x, dict) and x.get("name") == name]
    if len(matching) > 1:
        raise ProbeError("hyperdrive_cleanup_ambiguous")
    return matching[0] if matching else None


def worker_config(name: str, hyperdrive_id: str) -> str:
    if not re.fullmatch(r"ordax-direct-ipv6-diag-[0-9]{5,16}", name):
        raise ProbeError("worker_name_invalid")
    if not re.fullmatch(r"[a-f0-9]{32}", hyperdrive_id):
        raise ProbeError("hyperdrive_id_invalid")
    return (f'name = "{name}"\n'
            'main = "src/hyperdrive_direct_probe.ts"\n'
            'compatibility_date = "2026-10-17"\n'
            'compatibility_flags = ["nodejs_compat"]\n'
            'workers_dev = true\npreview_urls = false\n'
            '[[hyperdrive]]\nbinding = "POSTGRES"\n'
            f'id = "{hyperdrive_id}"\n')


def deploy_worker(name: str, hyperdrive_id: str):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", prefix="ordax-direct-probe-",
                                     dir=PROBE_DIR, encoding="utf-8", delete=False) as file:
        file.write(worker_config(name, hyperdrive_id))
        config_path = Path(file.name)
    try:
        # Captured output prevents Wrangler from leaking deployment metadata.
        process = subprocess.run(
            ["npx", "--yes", "wrangler@4.141.0", "deploy", "--config", str(config_path)],
            cwd=PROBE_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=120, env=os.environ.copy())
        if process.returncode:
            raise ProbeError("isolated_worker_deploy_failed")
    except (OSError, subprocess.TimeoutExpired):
        raise ProbeError("isolated_worker_deploy_unavailable") from None
    finally:
        config_path.unlink(missing_ok=True)


def check_worker(name: str) -> dict:
    """Probe with curl, as the original isolated Cloudflare probe did.

    A fresh workers.dev route may need time to propagate. No authorization
    headers, no secrets, no redirects, and only read-only SELECT 1.
    """
    url = f"https://{name}.ordaxsystems.workers.dev/"
    if shutil.which("curl") is None:
        raise ProbeError("curl_missing")
    status = "unknown"
    for attempt in range(6):
        try:
            result = subprocess.run(
                ["curl", "--silent", "--show-error", "--max-time", "15",
                 "--write-out", chr(10) + "%{http_code}", url],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=22,
            )
            if result.returncode:
                status = "transport"
            else:
                body, sep, code = result.stdout.rpartition(bytes([10]))
                status = code.decode("ascii", "replace").strip()[:3] if sep else "invalid"
                if status in ("200", "503"):
                    value = json.loads(body[:8192])
                    if not isinstance(value, dict):
                        raise ProbeError("probe_invalid_response")
                    if status == "200" and value.get("ok") is True and value.get("phase") == "complete":
                        return {"ok": True, "phase": "complete"}
                    phase = value.get("phase")
                    label = value.get("classification")
                    if phase in ("connect", "query") and isinstance(label, str) and re.fullmatch(
                        r"[a-z_]{1,48}", label
                    ):
                        return {"ok": False, "phase": phase, "classification": label}
                    raise ProbeError("probe_invalid_response")
        except (OSError, subprocess.TimeoutExpired, ValueError, UnicodeDecodeError):
            status = "transport"
        if attempt < 5:
            time.sleep(5)
    raise ProbeError("probe_http_" + (status if status.isdigit() else "unavailable"))


def run():
    cf = os.getenv("CLOUDFLARE_API_TOKEN")
    db = os.getenv("SUPABASE_ACCESS_TOKEN")
    run_id = os.getenv("GITHUB_RUN_ID", "")
    if not cf or not db:
        raise ProbeError("authorized_environment_missing")
    name, role = identifiers(run_id)
    mode = os.getenv("ORDAX_HYPERDRIVE_PROBE_MODE", "direct_ipv6")
    # Refuse unreviewed upstreams before even creating an ephemeral SQL role.
    origin_for_mode(mode, role)
    if not (PROBE_DIR / "src" / "hyperdrive_direct_probe.ts").is_file():
        raise ProbeError("isolated_source_missing")
    role_ownership = False
    deploy_attempted = False
    hd_id: str | None = None
    failures = []
    try:
        require_unique_role(db, role)
        credential = secrets.token_urlsafe(48)
        role_ownership = True  # Even an ambiguous CREATE needs safe cleanup.
        create_role(db, role, credential)
        print("ORDAX_DIRECT_ROLE=CREATED_LOGIN_ONLY", flush=True)
        if mode in ("pooler_session", "pooler_transaction"):
            verify_pooler_credential(mode, role, credential)
            print("ORDAX_DIRECT_POOLER_CREDENTIAL=VERIFIED", flush=True)
        hd_id = create_hyperdrive(cf, name, role, credential, mode)
        print("ORDAX_DIRECT_ORIGIN_MODE=" + mode, flush=True)
        print("ORDAX_DIRECT_HYPERDRIVE=CREATED", flush=True)
        deploy_attempted = True
        deploy_worker(name, hd_id)
        print("ORDAX_DIRECT_WORKER=DEPLOYED", flush=True)
        response = check_worker(name)
        print("ORDAX_DIRECT_PROBE=" + json.dumps(response, sort_keys=True, separators=(",", ":")), flush=True)
        if response.get("ok") is not True or response.get("phase") != "complete":
            raise ProbeError("direct_query_failed")
        print("ORDAX_DIRECT_POSTGRES_SELECT_1=PASS", flush=True)
    except ProbeError as exc:
        print("ORDAX_DIRECT_PROBE_FAILED=" + str(exc), flush=True)
        failures.append("probe")
    except Exception:
        print("ORDAX_DIRECT_PROBE_FAILED=internal_error", flush=True)
        failures.append("internal")
    finally:
        # Delete the Worker before the Hyperdrive, then the role; never touch
        # canonical ordax-mcp or its production Hyperdrive binding.
        if deploy_attempted:
            try:
                api("DELETE", CF_API + "/workers/scripts/" + name, cf)
                print("ORDAX_DIRECT_WORKER_CLEANUP=PASS", flush=True)
            except ProbeError as exc:
                if str(exc) == "provider_http_404":
                    print("ORDAX_DIRECT_WORKER_CLEANUP=ABSENT", flush=True)
                else:
                    failures.append("worker_cleanup")
                    print("ORDAX_DIRECT_WORKER_CLEANUP=FAILED", flush=True)
        try:
            config_id = hd_id or find_hyperdrive(cf, name)
            if config_id:
                api("DELETE", CF_API + "/hyperdrive/configs/" + config_id, cf)
            print("ORDAX_DIRECT_HYPERDRIVE_CLEANUP=PASS", flush=True)
        except ProbeError:
            failures.append("hyperdrive_cleanup")
            print("ORDAX_DIRECT_HYPERDRIVE_CLEANUP=FAILED_NAME_" + name, flush=True)
        if role_ownership:
            try:
                delete_role(db, role)
                print("ORDAX_DIRECT_ROLE_CLEANUP=PASS", flush=True)
            except ProbeError:
                failures.append("role_cleanup")
                print("ORDAX_DIRECT_ROLE_CLEANUP=FAILED_NAME_" + role, flush=True)
        # Failure must block accidental promotion even if SELECT 1 succeeded.
        if failures:
            raise ProbeError("gate_failed_" + "_".join(failures))


if __name__ == "__main__":
    try:
        run()
    except ProbeError as exc:
        print("ORDAX_DIRECT_FINAL=" + str(exc))
        raise SystemExit(1)
