"""Live canary for the sec_* pack: real local HTTP server + real scan path.

Serves the secretpack canary site (fake secrets only, each carrying a
"cnry" marker) on 127.0.0.1 and runs all five sec_* plugins through
the REAL Ctx with the REAL egress client (app.net.async_client),
the real rate limiter, and the real cache -- the same objects the
scan worker hands plugins. No mocks.

Output prints masked values and fingerprints only. The script exits
non-zero if any planted fake value appears anywhere in the output
(the evidence rule) or if any family fails to fire.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "backend"))
sys.path.insert(0, os.path.join(REPO_ROOT, "backend", "tests"))

import secretpack_samples as samples  # noqa: E402
from app.cache import Cache  # noqa: E402
from app.net import async_client  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.plugins.registry import discover  # noqa: E402
from app.plugins.secretpack import SEC_IDS  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        route = samples.CANARY_ROUTES.get(self.path)
        if route is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return
        ctype, body = route
        if isinstance(body, str):
            body = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        route = samples.CANARY_ROUTES.get(self.path)
        self.send_response(200 if route else 404)
        self.end_headers()


async def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    run_id = uuid.uuid4().hex[:12]
    print(f"canary run id: {run_id}")
    print(f"canary target: http://127.0.0.1:{port}/ (local server, "
          "real HTTP, real egress client)")
    client = async_client(follow_redirects=True)
    ctx = Ctx(run_id=run_id, mode="active", http=client,
              cache=Cache(), keys={}, limiter=RateLimiter(),
              evidence_dir="/tmp", source_type="website")
    target = Target(raw=f"http://127.0.0.1:{port}/", type="url",
                    normalized=f"http://127.0.0.1:{port}/")
    reg = discover()
    all_output: list = []
    ok = True
    try:
        for pid in SEC_IDS:
            cls = reg[pid]
            result = await cls().run(target, ctx)
            print(f"\n[{pid}] status={result.status.value} "
                  f"reason={result.reason!r} "
                  f"findings={len(result.findings)}")
            for f in result.findings:
                line = (f"  {f.key} | {f.value} | "
                        f"fp={f.evidence.get('fingerprint_sha256', '')[:16]} "
                        f"| {f.source_url}")
                print(line)
                all_output.append(line)
            if not result.findings:
                print(f"  !! {pid} did NOT fire on the canary")
                ok = False
    finally:
        await client.aclose()
        server.shutdown()
    blob = json.dumps(all_output)
    leaked = [s for s in samples.PLANTED if s in blob]
    leaked += [samples.PEM_BODY.strip()] if \
        samples.PEM_BODY.strip() in blob else []
    if leaked:
        print(f"\nLEAK CHECK: FAIL ({len(leaked)} planted values in output)")
        return 1
    print("\nLEAK CHECK: PASS (no planted value in any finding output)")
    print(f"RESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
