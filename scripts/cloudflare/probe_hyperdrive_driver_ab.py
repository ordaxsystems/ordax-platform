"""One-shot A/B comparison of Cloudflare Hyperdrive drivers, no production writes.

Runs ONLY from protected GitHub Actions. Ephemeral workers.dev Worker is
removed in all outcomes, even an ambiguous deploy failure. One canonical
Hyperdrive, both drivers, the same SQL SELECT 1 and zero table privileges.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ACCOUNT = "42586bf13b61436219d21def299833e4"
HYPERDRIVE = "4b601ec5815f43259bd8040053825d2a"
API = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/workers/scripts/"
CLOUDFLARE_DIR = Path(__file__).resolve().parents[2] / "control-plane" / "cloudflare"


class ProbeFailure(Exception):
    pass


def worker_identity(run_id: str) -> str:
    if not re.fullmatch(r"[1-9][0-9]{4,15}", run_id):
        raise ProbeFailure("invalid_run_id")
    return "ordax-hyperdrive-ab-" + run_id


def config(worker: str) -> str:
    if not re.fullmatch(r"ordax-hyperdrive-ab-[1-9][0-9]{4,15}", worker):
        raise ProbeFailure("worker_identity_not_pinned")
    return (f'name = "{worker}"\n'
            'main = "labs/hyperdrive_driver_ab.ts"\n'
            'compatibility_date = "2026-10-20"\n'
            'compatibility_flags = ["nodejs_compat"]\n'
            'workers_dev = true\npreview_urls = false\n'
            '[observability]\nenabled = true\nredact_query_string = true\n'
            '[[hyperdrive]]\nbinding = "POSTGRES"\n'
            f'id = "{HYPERDRIVE}"\n')


def deploy(worker: str) -> None:
    with tempfile.NamedTemporaryFile(
        "w", suffix=".toml", prefix="ordax-driver-ab-", dir=CLOUDFLARE_DIR,
        encoding="utf-8", delete=False,
    ) as fh:
        fh.write(config(worker))
        path = Path(fh.name)
    try:
        result = subprocess.run(
            ["npx", "--yes", "wrangler@4.141.0", "deploy", "--config", str(path)],
            cwd=CLOUDFLARE_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=120, check=False,
        )
        if result.returncode:
            raise ProbeFailure("deploy_failed")
    except (OSError, subprocess.TimeoutExpired):
        raise ProbeFailure("deploy_unavailable") from None
    finally:
        path.unlink(missing_ok=True)


def probe(worker: str, driver_path: str) -> dict:
    if driver_path not in ("/pg", "/postgres-js"):
        raise ProbeFailure("unexpected_driver_path")
    driver = "node_postgres" if driver_path == "/pg" else "postgres_js"
    url = f"https://{worker}.ordaxsystems.workers.dev{driver_path}"
    for attempt in range(5):
        try:
            outcome = subprocess.run(
                ["curl", "--silent", "--show-error", "--max-time", "16",
                 "--write-out", chr(10) + "%{http_code}", url],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                timeout=22,
            )
            if outcome.returncode != 0:
                status = "unreachable"
            else:
                data, sep, code = outcome.stdout.rpartition(bytes([10]))
                status = code.decode("ascii", "replace").strip()[:3] if sep else "invalid"
                if status in ("200", "503"):
                    record = json.loads(data[:8192])
                    if not isinstance(record, dict) or record.get("driver") != driver:
                        raise ProbeFailure("response_driver_mismatch")
                    phase = record.get("phase")
                    classification = record.get("classification")
                    if phase not in ("complete", "connect", "query", "connect_or_query"):
                        raise ProbeFailure("response_phase_invalid")
                    if status == "200":
                        if record.get("ok") is not True or phase != "complete":
                            raise ProbeFailure("response_success_invalid")
                        return {"driver": driver, "ok": True, "phase": "complete"}
                    if record.get("ok") is not False or not isinstance(classification, str) or not re.fullmatch(
                        r"[a-z_]{1,45}", classification
                    ):
                        raise ProbeFailure("response_failure_invalid")
                    return {"driver": driver, "ok": False, "phase": phase,
                            "classification": classification}
        except (OSError, subprocess.TimeoutExpired, UnicodeError, ValueError):
            status = "unreachable"
        if attempt < 4 and status in ("403", "404", "unreachable"):
            time.sleep(5)
            continue
        break
    return {"driver": driver, "ok": False, "phase": "http",
            "classification": "http_" + status if status.isdigit() else "unreachable"}


def delete_worker(worker: str, token: str) -> bool:
    # Only the checked ephemeral name is ever accepted; never ordax-mcp.
    config(worker)
    req = urllib.request.Request(API + worker, method="DELETE",
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            data = json.loads(response.read(8192))
            return response.status == 200 and isinstance(data, dict) and data.get("success") is True
    except urllib.error.HTTPError as exc:
        return exc.code == 404
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return False


def run() -> None:
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    worker = worker_identity(os.environ.get("GITHUB_RUN_ID", ""))
    if not token:
        raise ProbeFailure("cloudflare_token_missing")
    deployed = False
    results = []
    cleaned = False
    try:
        # Even a failed deploy may have created the Worker; always clean.
        deployed = True
        deploy(worker)
        print("ORDAX_DRIVER_AB_DEPLOY=PASS", flush=True)
        for path in ("/pg", "/postgres-js"):
            item = probe(worker, path)
            results.append(item)
            print("ORDAX_DRIVER_AB_RESULT=" + json.dumps(item, separators=(",", ":"), sort_keys=True), flush=True)
    finally:
        if deployed:
            cleaned = delete_worker(worker, token)
            print("ORDAX_DRIVER_AB_CLEANUP=" + ("PASS" if cleaned else "FAILED"), flush=True)
    if not cleaned:
        raise ProbeFailure("worker_cleanup_not_confirmed")
    if len(results) != 2:
        raise ProbeFailure("incomplete_driver_comparison")
    if not any(r["ok"] for r in results):
        raise ProbeFailure("both_drivers_unavailable")
    if all(r["ok"] for r in results):
        print("ORDAX_DRIVER_AB_OUTCOME=BOTH_CONNECTED", flush=True)
    else:
        print("ORDAX_DRIVER_AB_OUTCOME=DRIVER_SPECIFIC_FAILURE", flush=True)


if __name__ == "__main__":
    try:
        run()
    except ProbeFailure as exc:
        print("ORDAX_DRIVER_AB_FINAL=" + str(exc), flush=True)
        raise SystemExit(1)
    except Exception:
        print("ORDAX_DRIVER_AB_FINAL=internal_error", flush=True)
        raise SystemExit(1)
