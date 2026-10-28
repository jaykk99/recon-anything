"""Real-pipeline proof for the gx_* completeness pack.

Not a unit test: this boots the REAL backend (uvicorn, app.main) with
a throwaway SQLite DB, serves the canary over REAL HTTP on localhost
(including a REAL git repo whose .git is served - the fake key exists
only in its history), starts a scan through the product's actual API
(POST /api/runs with the 23 gx_* plugin ids, mode=active), waits for
the run to finish, and reports which detectors fired, with the stored
(masked) evidence. It also verifies no full planted secret appears
anywhere in the run-detail payload.

Level note: detectors whose verification surface is a third-party
host (Trello/Atlassian/Google board checks, Azure/Firebase listing)
fire at REFERENCE level here - their fake ids do not resolve to real
public content on the live internet, by design. Their verified level
is proven in tests/test_gappack.py via MockTransport. Everything
target-relative (git history, GraphQL, all service probes, object
reads, content detectors) fires at full verified level here.

Usage:  python3 scripts/gappack_proof.py
Exit code 0 only if all 23 detectors fire.
"""
from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "tests"))

import gappack_samples as samples  # noqa: E402
from app.plugins.gappack import GAP_IDS  # noqa: E402

CANARY_PORT = 8799
API_PORT = 8899
API = f"http://127.0.0.1:{API_PORT}"
CANARY = f"http://localhost:{CANARY_PORT}/"
GIT_DIR: Path | None = None


def build_git_fixture() -> Path:
    root = Path(tempfile.mkdtemp(prefix="gx-proof-git-"))
    repo = root / "repo"
    repo.mkdir()
    env = {**os.environ,
           "GIT_AUTHOR_NAME": "GX Canary",
           "GIT_AUTHOR_EMAIL": "gx@canary.test",
           "GIT_COMMITTER_NAME": "GX Canary",
           "GIT_COMMITTER_EMAIL": "gx@canary.test"}

    def git(*args: str) -> None:
        subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, env=env, check=True)

    git("init", "-q", "-b", "main")
    (repo / "app_config.txt").write_text(
        f"# canary config\naws_access_key_id = {samples.GIT_KEY}\n")
    git("add", ".")
    git("commit", "-q", "-m", "add config")
    (repo / "app_config.txt").unlink()
    (repo / "README.md").write_text("# gx canary\n")
    git("add", "-A")
    git("commit", "-q", "-m", "remove config")
    return repo / ".git"


class CanaryHandler(http.server.BaseHTTPRequestHandler):
    def _send(self, code: int, ctype: str, body) -> None:
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _dispatch(self) -> None:
        path = self.path.split("?", 1)[0]
        if path.startswith("/.git/") and GIT_DIR is not None:
            rel = path[len("/.git/"):]
            target = (GIT_DIR / rel).resolve()
            if str(target).startswith(str(GIT_DIR.resolve())) \
                    and target.is_file():
                self._send(200, "application/octet-stream",
                           target.read_bytes())
                return
            self._send(404, "text/plain", "no object")
            return
        if self.command == "POST" and path in samples.POST_ROUTES:
            self._send(200, "application/json",
                       json.dumps(samples.POST_ROUTES[path]))
            return
        if path in ("/", "/index.html"):
            self._send(200, "text/html", samples.CANARY_HTML)
            return
        route = samples.ROUTES.get(path)
        if route is not None:
            self._send(200, route[0], route[1])
            return
        self._send(404, "text/plain", "not found")

    do_GET = _dispatch
    do_HEAD = _dispatch
    do_POST = _dispatch

    def log_message(self, *args):  # silence
        pass


def _req(method, url, payload=None, timeout=15):
    data = json.dumps(payload).encode() if payload is not None else None
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"Content-Type":
                                        "application/json"})
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode() or "{}")


def main() -> int:
    global GIT_DIR
    GIT_DIR = build_git_fixture()
    print(f"[canary] git fixture built at {GIT_DIR} "
          f"(secret only in history)")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", CANARY_PORT),
                                             CanaryHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[canary] serving {len(samples.ROUTES)} routes + .git on "
          f"{CANARY}")

    db = "/tmp/gappack_proof.db"
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
        gx_listed = [p["id"] for p in plugins if p["id"].startswith("gx_")]
        print(f"[api] GET /api/plugins -> {len(plugins)} plugins, "
              f"{len(gx_listed)} gx_*")

        print(f"[api] POST /api/runs targets={CANARY} mode=active "
              f"plugins={len(GAP_IDS)} gx_* ids")
        _, out = _req("POST", f"{API}/api/runs",
                      {"targets": CANARY, "mode": "active",
                       "plugins": GAP_IDS})
        run_id = out["run_id"]
        print(f"[api] run_id={run_id}")

        detail = None
        status = None
        deadline = time.time() + 900
        while time.time() < deadline:
            _, detail = _req("GET", f"{API}/api/runs/{run_id}",
                             timeout=15)
            status = (detail.get("run") or {}).get("status")
            if status in ("done", "error", "failed"):
                break
            time.sleep(3)
        print(f"[api] run status={status}")

        findings = detail.get("findings") or []
        hits: dict = {}
        for f in findings:
            if str(f.get("plugin", "")).startswith("gx_"):
                hits.setdefault(f["plugin"], []).append(f)
        print(f"[proof] gx findings stored: "
              f"{sum(len(v) for v in hits.values())} across "
              f"{len(hits)}/{len(GAP_IDS)} detectors")
        missed = [pid for pid in GAP_IDS if pid not in hits]
        for pid in GAP_IDS:
            if pid in hits:
                f0 = hits[pid][0]
                print(f"  HIT  {pid}: {f0.get('value', '')[:100]}")
            else:
                print(f"  MISS {pid}")
        blob = json.dumps(detail)
        leaked = [name for name, val in
                  (("git_key", samples.GIT_KEY),
                   ("pinecone_key", samples.PINECONE_KEY))
                  if val in blob]
        print(f"[proof] full planted secrets in run payload: {leaked}")
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
