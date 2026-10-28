"""Real-pipeline proof for the da_* deep-artifacts pack.

Boots the REAL backend (uvicorn, app.main) with a throwaway SQLite
DB and serves the canary over REAL HTTP on localhost. The canary
honors Range requests and RECORDS the body bytes it serves per path,
so the proof can assert the pack's read caps on the wire: the 300 KB
fake heap dump and the 200 KB firmware image must never be downloaded
- only a HEAD plus a <= 4 KB ranged window may cross.

Planted artifacts: fake HPROF heap dump (+ one linked from the
homepage), V8 heap snapshot, JVM thread dump, MDMP minidump, ELF core
dump, PDB, dSYM plist, hand-built WASM (import/export names + an
embedded internal URL), a real ZIP .jar whose application.properties
carries a fragment-assembled fake secret (plus a keystore entry), an
.apk containing google-services.json, a uImage firmware image, a
device config.bin with credential field names, an OTA manifest with
an internal download URL, and an Apache-style /bin/ listing with
.pdb/.class/.dll entries.

A second run against a clean site must produce zero da_* findings,
and the full planted secret must appear NOWHERE in the run payload
(only its masked form + SHA-256 fingerprint).

Usage:  python3 scripts/artifacts_proof.py
Exit code 0 only if all 10 detectors fire, caps hold, and no leak.
"""
from __future__ import annotations

import hashlib
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

import artifacts_samples as S  # noqa: E402
from app.plugins.artifacts_deep import DA_IDS  # noqa: E402

CANARY_PORT = 8799
CLEAN_PORT = 8801
API_PORT = 8899
API = f"http://127.0.0.1:{API_PORT}"

FILES = {
    "/": (S.fake_homepage(), "text/html"),
    "/static/app.js": (b"console.log(1)", "text/javascript"),
    "/heap.hprof": (S.fake_hprof(), "application/octet-stream"),
    "/files/app.hprof": (S.fake_hprof(), "application/octet-stream"),
    "/heap.heapsnapshot": (S.fake_heapsnapshot(),
                           "application/octet-stream"),
    "/actuator/threaddump": (S.fake_threaddump(), "application/json"),
    "/memory.dmp": (S.fake_mdmp(), "application/octet-stream"),
    "/core": (S.fake_core(), "application/octet-stream"),
    "/app.pdb": (S.fake_pdb(), "application/octet-stream"),
    "/app.dSYM/Contents/Info.plist": (S.fake_dsym_plist(), "text/xml"),
    "/program.wasm": (S.fake_wasm(), "application/wasm"),
    "/app.jar": (S.fake_jar(), "application/java-archive"),
    "/app.apk": (S.fake_apk(), "application/vnd.android.package"),
    "/firmware.bin": (S.fake_firmware(), "application/octet-stream"),
    "/config.bin": (S.fake_config_bin(), "application/octet-stream"),
    "/firmware.json": (S.fake_ota_manifest(), "application/json"),
    "/bin/": (S.fake_listing(), "text/html"),
}
CLEAN_FILES = {
    "/": (b"<html><head><title>ok</title></head><body>hello</body>"
          b"</html>", "text/html"),
    "/static/app.js": (b"console.log(1)", "text/javascript"),
}

SERVED: dict = {}
SERVED_LOCK = threading.Lock()


def _range_slice(body: bytes, header: str):
    """(start, part) for a Range header value, or None."""
    if not header.startswith("bytes="):
        return None
    spec = header[6:]
    total = len(body)
    try:
        if spec.startswith("-"):
            n = int(spec[1:])
            part = body[-n:] if n < total else body
            return total - len(part), part
        a, _, b = spec.partition("-")
        start = int(a)
        end = int(b) if b else total - 1
        return start, body[start:end + 1]
    except Exception:
        return None


def make_handler(files):
    class Handler(http.server.BaseHTTPRequestHandler):
        def _dispatch(self, send_body: bool):
            path = self.path.split("?")[0]
            route = files.get(path)
            if route is None:
                body = b"not found"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if send_body:
                    self.wfile.write(body)
                return
            body, ctype = route
            total = len(body)
            rng = self.headers.get("Range", "") if send_body else ""
            sliced = _range_slice(body, rng) if rng else None
            if sliced is not None:
                start, part = sliced
                self.send_response(206)
                self.send_header(
                    "Content-Range",
                    f"bytes {start}-{start + len(part) - 1}/{total}")
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(part)))
                self.end_headers()
                with SERVED_LOCK:
                    SERVED[path] = SERVED.get(path, 0) + len(part)
                self.wfile.write(part)
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(total))
            self.end_headers()
            if send_body:
                with SERVED_LOCK:
                    SERVED[path] = SERVED.get(path, 0) + total
                self.wfile.write(body)

        def do_GET(self):
            self._dispatch(True)

        def do_HEAD(self):
            self._dispatch(False)

        def log_message(self, *args):
            pass

    return Handler


def _req(method, url, payload=None, timeout=15):
    data = json.dumps(payload).encode() if payload is not None else None
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"Content-Type":
                                        "application/json"})
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode() or "{}")


def _run_scan(target_url: str):
    _, out = _req("POST", f"{API}/api/runs",
                  {"targets": target_url, "mode": "active",
                   "plugins": DA_IDS})
    run_id = out["run_id"]
    detail = None
    status = None
    deadline = time.time() + 900
    while time.time() < deadline:
        _, detail = _req("GET", f"{API}/api/runs/{run_id}", timeout=15)
        status = (detail.get("run") or {}).get("status")
        if status in ("done", "error", "failed"):
            break
        time.sleep(3)
    return run_id, status, detail


def main() -> int:
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", CANARY_PORT), make_handler(FILES))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    clean = http.server.ThreadingHTTPServer(
        ("127.0.0.1", CLEAN_PORT), make_handler(CLEAN_FILES))
    threading.Thread(target=clean.serve_forever, daemon=True).start()
    print(f"[canary] serving {len(FILES)} artifact routes on "
          f":{CANARY_PORT}, clean site on :{CLEAN_PORT}")

    db = "/tmp/artifacts_proof.db"
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
        da_listed = [p["id"] for p in plugins
                     if p["id"].startswith("da_")]
        print(f"[api] GET /api/plugins -> {len(plugins)} plugins, "
              f"{len(da_listed)} da_*")

        canary = f"http://localhost:{CANARY_PORT}/"
        print(f"[api] POST /api/runs targets={canary} mode=active "
              f"plugins={len(DA_IDS)} da_* ids")
        run_id, status, detail = _run_scan(canary)
        print(f"[api] run_id={run_id} status={status}")

        findings = (detail or {}).get("findings") or []
        hits: dict = {}
        for f in findings:
            if str(f.get("plugin", "")).startswith("da_"):
                hits.setdefault(f["plugin"], []).append(f)
        print(f"[proof] da findings stored: "
              f"{sum(len(v) for v in hits.values())} across "
              f"{len(hits)}/{len(DA_IDS)} detectors")
        missed = [pid for pid in DA_IDS if pid not in hits]
        for pid in DA_IDS:
            if pid in hits:
                f0 = hits[pid][0]
                print(f"  HIT  {pid}: {f0.get('value', '')[:100]}")
            else:
                print(f"  MISS {pid}")

        blob = json.dumps(detail)
        leaked = S.FAKE_SECRET in blob
        digest = hashlib.sha256(S.FAKE_SECRET.encode()).hexdigest()
        print(f"[proof] full planted secret in run payload: {leaked}")
        print(f"[proof] masked fingerprint present: {digest in blob}")
        print(f"[proof] bytes served by canary: "
              f"/heap.hprof={SERVED.get('/heap.hprof', 0)} "
              f"(file 300000), /firmware.bin="
              f"{SERVED.get('/firmware.bin', 0)} (file 200000), "
              f"/memory.dmp={SERVED.get('/memory.dmp', 0)} "
              f"(file 120000), /app.jar={SERVED.get('/app.jar', 0)}")
        caps_ok = (SERVED.get("/heap.hprof", 0) <= 4096
                   and SERVED.get("/firmware.bin", 0) <= 4096
                   and SERVED.get("/memory.dmp", 0) <= 4096
                   and SERVED.get("/app.jar", 0) <= 65557)

        print("[api] clean control run ...")
        run2, status2, detail2 = _run_scan(
            f"http://localhost:{CLEAN_PORT}/")
        clean_findings = [f for f in (detail2 or {}).get("findings", [])
                          if str(f.get("plugin", "")).startswith("da_")]
        print(f"[proof] clean run status={status2} "
              f"da findings={len(clean_findings)}")

        ok = (not missed and not leaked and digest in blob and caps_ok
              and status == "done" and len(clean_findings) == 0)
        if missed:
            print(f"[proof] MISSED detectors: {missed}")
        if not caps_ok:
            print("[proof] READ CAP VIOLATION - see bytes served above")
        print(f"[proof] RESULT: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        server.shutdown()
        clean.shutdown()


if __name__ == "__main__":
    sys.exit(main())
