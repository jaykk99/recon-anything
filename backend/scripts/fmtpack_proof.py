"""Real-pipeline proof for the fx_* format & graph pack.

Not a unit test: boots the REAL backend (uvicorn, app.main) with a
throwaway SQLite DB, serves the canary over REAL HTTP on localhost -
homepage linking the seven schema files, Set-Cookie headers carrying
real serialized markers, a JS bundle with a pickle + BinaryFormatter
blob - plus four mini servers on the graph services' conventional
ports (Neo4j discovery :7474, ArangoDB :8529, Gremlin :8182, SPARQL
:8890), starts a scan through the product's actual API (POST
/api/runs with the 12 fx_* plugin ids, mode=active), waits for the
run to finish, and reports which detectors fired, with the stored
(masked) evidence. Also verifies no full planted value appears
anywhere in the run-detail payload.

Detection only, end to end: the SPARQL surface answers a plain GET
of its service description; no query is issued, no payload is sent
to any deserialization surface (the markers travel in the CANARY's
own outbound traffic, which is the whole point of the detector).

Usage:  python3 scripts/fmtpack_proof.py
Exit code 0 only if all 12 detectors fire and nothing leaks.
"""
from __future__ import annotations

import http.server
import json
import os
import sys
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "tests"))

import fmtpack_samples as samples  # noqa: E402
from app.plugins.fmtpack import FX_IDS  # noqa: E402

CANARY_PORT = 8798
API_PORT = 8898
API = f"http://127.0.0.1:{API_PORT}"
CANARY = f"http://localhost:{CANARY_PORT}/"


def _make_handler(routes, default_body="not found"):
    class H(http.server.BaseHTTPRequestHandler):
        def _send(self, code, ctype, body, extra=()):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            for k, v in extra:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _dispatch(self):
            path = self.path.split("?", 1)[0]
            hit = routes.get((self.command, path)) or \
                routes.get(("GET", path))
            if hit is None:
                self._send(404, "text/plain", default_body)
                return
            self._send(*hit)

        do_GET = _dispatch
        do_HEAD = _dispatch

        def log_message(self, *args):
            pass

    return H


def start_servers():
    canary_routes = {
        ("GET", "/"): (200, "text/html", samples.CANARY_HTML, [
            ("Set-Cookie",
             f"FXJAVA={samples.JAVA_COOKIE_VALUE}; Path=/; HttpOnly"),
            ("Set-Cookie",
             f"prefs={samples.PHP_COOKIE_VALUE}; Path=/")]),
        ("GET", "/assets/app.js"): (
            200, "application/javascript", samples.CANARY_JS, []),
        ("GET", "/sparql"): (
            200, "text/turtle", samples.SPARQL_TURTLE, []),
        ("GET", "/query"): (
            200, "text/turtle", samples.SPARQL_TURTLE, []),
        ("GET", "/_api/version"): (
            200, "application/json", json.dumps(samples.ARANGO_JSON),
            []),
    }
    for path, body in samples.ROUTES.items():
        canary_routes[("GET", path)] = (200, "text/plain", body, [])

    neo4j = dict(samples.NEO4J_JSON)
    neo4j["bolt"] = "bolt://localhost:7687"
    servers = [
        (CANARY_PORT, canary_routes),
        (7474, {("GET", "/"): (200, "application/json",
                               json.dumps(neo4j), [])}),
        (8529, {("GET", "/_api/version"): (
            200, "application/json", json.dumps(samples.ARANGO_JSON),
            [])}),
        (8182, {("GET", "/"): (
            400, "application/json", json.dumps(samples.GREMLIN_JSON),
            [])}),
        (8890, {("GET", "/sparql"): (
            200, "text/turtle", samples.SPARQL_TURTLE, [])}),
    ]
    started = []
    for port, routes in servers:
        srv = http.server.ThreadingHTTPServer(
            ("127.0.0.1", port), _make_handler(routes))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        started.append(srv)
        print(f"[canary] listening on 127.0.0.1:{port} "
              f"({len(routes)} route(s))")
    return started


def _req(method, url, payload=None, timeout=15):
    data = json.dumps(payload).encode() if payload is not None \
        else None
    r = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode() or "{}")


def main() -> int:
    servers = start_servers()
    print(f"[canary] homepage + {len(samples.ROUTES)} schema files + "
          f"cookie markers on {CANARY}")

    db = "/tmp/fmtpack_proof.db"
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(db + suffix)
        except OSError:
            pass
    env = dict(os.environ)
    env["DATABASE_URL"] = f"sqlite:///{db}"
    env["RECON_ACCESS_CODE"] = ""
    env["ACCESS_CODE"] = ""
    backend_dir = os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))
    import subprocess
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
        fx_listed = [p["id"] for p in plugins
                     if p["id"].startswith("fx_")]
        print(f"[api] GET /api/plugins -> {len(plugins)} plugins, "
              f"{len(fx_listed)} fx_*")

        print(f"[api] POST /api/runs targets={CANARY} mode=active "
              f"plugins={len(FX_IDS)} fx_* ids")
        _, out = _req("POST", f"{API}/api/runs",
                      {"targets": CANARY, "mode": "active",
                       "plugins": FX_IDS})
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
            if str(f.get("plugin", "")).startswith("fx_"):
                hits.setdefault(f["plugin"], []).append(f)
        print(f"[proof] fx findings stored: "
              f"{sum(len(v) for v in hits.values())} across "
              f"{len(hits)}/{len(FX_IDS)} detectors")
        missed = [pid for pid in FX_IDS if pid not in hits]
        for pid in FX_IDS:
            if pid in hits:
                f0 = hits[pid][0]
                print(f"  HIT  {pid} x{len(hits[pid])}: "
                      f"{f0.get('value', '')[:110]}")
            else:
                print(f"  MISS {pid}")
        blob = json.dumps(detail)
        planted = {"java_cookie": samples.JAVA_COOKIE_VALUE,
                   "php_cookie": samples.PHP_COOKIE_VALUE,
                   "pickle_b64": samples.PICKLE_B64,
                   "viewstate": samples.VIEWSTATE_VALUE,
                   "binaryformatter": samples.BINARYFORMATTER_VALUE}
        leaked = [name for name, val in planted.items()
                  if val in blob]
        print(f"[proof] full planted values in run payload: "
              f"{leaked}")
        if missed:
            print(f"[proof] MISSED detectors: {missed}")
        return 0 if not missed and not leaked else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        for srv in servers:
            srv.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
