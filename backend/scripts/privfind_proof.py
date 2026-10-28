"""Real-pipeline proof for the pf_* private-findings pack.

Not a unit test: this boots the REAL backend (uvicorn, app.main) with a
throwaway SQLite DB, serves the canary samples over REAL HTTP on
localhost, starts a scan through the product's actual API
(POST /api/runs with the 100 pf_* plugin ids, mode=active), waits for
the run to finish, and reports which detectors fired - with the masked
evidence exactly as stored. It also verifies that no full planted
secret appears anywhere in the run-detail payload (masking proof at
the pipeline level).

Usage:  python3 scripts/privfind_proof.py
Exit code 0 only if all 100 detectors fire.
"""
from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "tests"))

import privfind_samples as samples  # noqa: E402
from app.plugins.privfind import PRIVFIND_IDS  # noqa: E402

CANARY_PORT = 8799
API_PORT = 8899
API = f"http://127.0.0.1:{API_PORT}"
CANARY = f"http://localhost:{CANARY_PORT}/"


class CanaryHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        route = samples.ROUTES.get(self.path)
        if route is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return
        ctype, body = route
        data = body.encode() if isinstance(body, str) else body
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # silence
        pass


def _req(method, url, payload=None, timeout=15):
    data = json.dumps(payload).encode() if payload is not None else None
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode() or "{}")


def main() -> int:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", CANARY_PORT),
                                             CanaryHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[canary] serving {len(samples.ROUTES)} routes on {CANARY}")

    db = "/tmp/privfind_proof.db"
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(db + suffix)
        except OSError:
            pass
    env = dict(os.environ)
    env["DATABASE_URL"] = f"sqlite:///{db}"
    env["RECON_ACCESS_CODE"] = ""
    env["ACCESS_CODE"] = ""
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(API_PORT)],
        cwd=backend_dir, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # wait for the API
        deadline = time.time() + 60
        plugins = None
        while time.time() < deadline:
            try:
                _, out = _req("GET", f"{API}/api/plugins", timeout=5)
                plugins = out.get("plugins")
                break
            except Exception:
                time.sleep(1)
        if plugins is None:
            print("[api] backend did not come up")
            return 2
        pf_listed = [p["id"] for p in plugins if p["id"].startswith("pf_")]
        print(f"[api] GET /api/plugins -> {len(plugins)} plugins, "
              f"{len(pf_listed)} pf_*")

        print(f"[api] POST /api/runs targets={CANARY} mode=active "
              f"plugins={len(PRIVFIND_IDS)} pf_* ids")
        _, out = _req("POST", f"{API}/api/runs",
                      {"targets": CANARY, "mode": "active",
                       "plugins": PRIVFIND_IDS})
        run_id = out["run_id"]
        print(f"[api] run_id={run_id}")

        detail = None
        deadline = time.time() + 900
        while time.time() < deadline:
            _, detail = _req("GET", f"{API}/api/runs/{run_id}", timeout=15)
            status = (detail.get("run") or {}).get("status")
            if status in ("done", "error", "failed"):
                break
            time.sleep(3)
        print(f"[api] run status={status}")

        findings = detail.get("findings") or []
        hits = {}
        for f in findings:
            if str(f.get("plugin", "")).startswith("pf_"):
                hits.setdefault(f["plugin"], []).append(f)
        print(f"[proof] pf findings stored: "
              f"{sum(len(v) for v in hits.values())} across "
              f"{len(hits)}/{len(PRIVFIND_IDS)} detectors")
        missed = [pid for pid in PRIVFIND_IDS if pid not in hits]
        for pid in PRIVFIND_IDS:
            if pid in hits:
                f0 = hits[pid][0]
                ev = f0.get("evidence") or {}
                mask = ev.get("match_redacted") or ev.get("path") or ""
                print(f"  HIT  {pid}: {f0.get('value', '')[:90]}")
            else:
                print(f"  MISS {pid}")
        # Masking proof at the pipeline level: no full planted value
        # anywhere in the run payload the API returned.
        blob = json.dumps(detail)
        leaked = [pid for pid, val in samples.VALUES.items()
                  if val in blob]
        print(f"[proof] full planted values in run payload: {leaked}")
        if missed:
            print(f"[proof] MISSED detectors: {missed}")
        return 0 if not missed and not leaked else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        server.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
