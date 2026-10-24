"""Real-pipeline proof for the xml_* reader pack.

Not a unit test: this boots the REAL backend (uvicorn, app.main) with
a throwaway SQLite DB, serves the canary over REAL HTTP on localhost,
starts a scan through the product's actual API (POST /api/runs with
the 5 xml_* plugin ids, mode=active), waits for the run to finish,
and reports which detectors fired, with the stored (masked) evidence.
It also verifies no full planted secret appears anywhere in the
run-detail payload.

The canary bodies are tests/xmlpack_samples.py verbatim, except the
canary host literal is rewritten to the real localhost origin so
robots.txt's sitemap-index children resolve to this server (the
samples address the canary as canary.test for MockTransport).

Usage:  python3 scripts/xmlpack_proof.py
Exit code 0 only if all 5 detectors fire, every required extraction
class is present, and no planted secret leaks.
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

import xmlpack_samples as samples  # noqa: E402
from app.plugins.xmlpack import XML_IDS  # noqa: E402

CANARY_PORT = 8799
API_PORT = 8899
API = f"http://127.0.0.1:{API_PORT}"
CANARY_ORIGIN = f"http://localhost:{CANARY_PORT}"
CANARY = CANARY_ORIGIN + "/"

REQUIRED_KEYS = {
    "xml_connection_string",        # config XML credential
    "xml_credential_attribute",     # password="..." attribute
    "xml_pii_ssn",                  # validated PII in XML
    "xml_sitemap_sensitive_url",    # sitemap mining (incl. index child)
    "xml_sitemap_internal_url",     # internal host in sitemap
    "xml_external_entity",          # XXE surface declaration
    "xml_crossdomain_wildcard",     # policy contents
    "xml_wsdl_service",             # WSDL surface
    "xml_wsdl_internal_endpoint",   # internal SOAP address
}


def _localize(body):
    if isinstance(body, str):
        return body.replace("https://canary.test", CANARY_ORIGIN) \
                   .replace("http://canary.test", CANARY_ORIGIN)
    return body


class CanaryHandler(http.server.BaseHTTPRequestHandler):
    def _send(self, code: int, ctype: str, body) -> None:
        data = _localize(body)
        data = data.encode() if isinstance(data, str) else data
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _dispatch(self) -> None:
        path = self.path.split("?", 1)[0]
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
    server = http.server.ThreadingHTTPServer(("127.0.0.1", CANARY_PORT),
                                             CanaryHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"[canary] serving {len(samples.ROUTES)} routes on {CANARY}")

    db = "/tmp/xmlpack_proof.db"
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
        xml_listed = [p["id"] for p in plugins
                      if p["id"].startswith("xml_")]
        print(f"[api] GET /api/plugins -> {len(plugins)} plugins, "
              f"{len(xml_listed)} xml_*")

        print(f"[api] POST /api/runs targets={CANARY} mode=active "
              f"plugins={XML_IDS}")
        _, out = _req("POST", f"{API}/api/runs",
                      {"targets": CANARY, "mode": "active",
                       "plugins": XML_IDS})
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
        keys = set()
        for f in findings:
            if str(f.get("plugin", "")).startswith("xml_"):
                hits.setdefault(f["plugin"], []).append(f)
                keys.add(f.get("key"))
        print(f"[proof] xml findings stored: "
              f"{sum(len(v) for v in hits.values())} across "
              f"{len(hits)}/{len(XML_IDS)} detectors")
        missed = [pid for pid in XML_IDS if pid not in hits]
        for pid in XML_IDS:
            if pid in hits:
                f0 = hits[pid][0]
                print(f"  HIT  {pid} ({len(hits[pid])}): "
                      f"{f0.get('value', '')[:110]}")
            else:
                print(f"  MISS {pid}")
        missing_keys = sorted(REQUIRED_KEYS - keys)
        print(f"[proof] extraction classes present: "
              f"{sorted(REQUIRED_KEYS & keys)}")
        if missing_keys:
            print(f"[proof] MISSING extraction classes: {missing_keys}")
        blob = json.dumps(detail)
        leaked = [s[:10] + "..." for s in
                  samples.PLANTED_SECRETS + ["123-45-6789",
                                             "GB29NWBK60161331926819"]
                  if s in blob]
        print(f"[proof] full planted secrets in run payload: {leaked}")
        if missed:
            print(f"[proof] MISSED detectors: {missed}")
        return 0 if not missed and not leaked and not missing_keys \
            else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        server.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
