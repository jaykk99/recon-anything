#!/usr/bin/env python3
"""ReconAnything thin client: run scans from a phone (Termux) or any box
with only Python 3, no venv, no Node, no clone. Stdlib only.

The Linux box runs the real backend; this talks to its API over the LAN
(same WiFi, no internet on the phone needed).

First run (one command, printed by the Linux box when it starts):

    curl -s http://<linux-ip>:8000/recon-client.py | python3 - <6-digit-code> scan <target>

The code is exchanged once for the access code and saved to
~/.recon-client.json (0600). After that, save this file once:

    curl -s http://<linux-ip>:8000/recon-client.py -o recon.py

and use it directly:

    python3 recon.py scan <target>          # quick preset, waits, prints findings
    python3 recon.py scan <target> --preset standard
    python3 recon.py status <run_id>
    python3 recon.py runs
    python3 recon.py findings <run_id>
    python3 recon.py plugins

Detection only, same as the backend: scans never exploit, never move
funds, never touch private data. Only scan targets you are authorized
to test. Flags: --server URL, --code CODE (also env RECON_API_URL,
RECON_ACCESS_CODE).
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Replaced by the server when this file is served (GET /recon-client.py)
# with the address the phone used to reach it. Overridden by
# --server, env RECON_API_URL, or the saved config.
DEFAULT_SERVER = "__DEFAULT_SERVER__"

CONFIG = Path.home() / ".recon-client.json"
TERMINAL = {"done", "error", "failed", "cancelled"}


def _load_config() -> dict:
    try:
        return json.loads(CONFIG.read_text())
    except Exception:
        return {}


def _save_config(data: dict) -> None:
    CONFIG.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    CONFIG.write_text(json.dumps(data, indent=2) + "\n")
    CONFIG.chmod(0o600)


def _server(args) -> str:
    if args.server:
        return args.server.rstrip("/")
    env = os.environ.get("RECON_API_URL", "").rstrip("/")
    if env:
        return env
    saved = _load_config().get("server_url", "")
    if saved:
        return saved.rstrip("/")
    if DEFAULT_SERVER and not DEFAULT_SERVER.startswith("__"):
        return DEFAULT_SERVER.rstrip("/")
    return "http://127.0.0.1:8000"


def _code(args) -> str:
    if args.code:
        return args.code
    env = os.environ.get("RECON_ACCESS_CODE", "")
    if env:
        return env
    return _load_config().get("access_code", "")


def _api(server: str, code: str, method: str, path: str,
         body: dict | None = None) -> dict:
    url = server + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if code:
        req.add_header("X-Access-Code", code)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:300]
        raise SystemExit(f"ERROR: {method} {path} -> HTTP {exc.code}: {detail}")
    except urllib.error.URLError as exc:
        raise SystemExit(
            f"ERROR: cannot reach {server} ({exc.reason}). Is the Linux box "
            "running (bash local-run/run.sh) and is the phone on the same WiFi?")


def _pair(server: str, pair_code: str) -> str:
    out = _api(server, "", "GET", f"/api/pair?code={pair_code}")
    access = out.get("access_code", "")
    if not access:
        raise SystemExit("ERROR: pair exchange returned no access code.")
    cfg = _load_config()
    cfg.update({"server_url": server, "access_code": access})
    _save_config(cfg)
    print(f"Paired with {server} (access code saved to {CONFIG}, 0600).")
    return access


def _cmd_scan(args) -> int:
    server, code = _server(args), _code(args)
    if not code:
        raise SystemExit("ERROR: no access code. Run once with the 6-digit "
                         "pair code from the Linux box, or pass --code.")
    if not args.target:
        raise SystemExit("Usage: recon.py scan <target> [--preset quick|standard|deep]")
    body = {"targets": args.target, "preset": args.preset or "quick"}
    out = _api(server, code, "POST", "/api/runs", body)
    run_id = out.get("id") or out.get("run_id") or ""
    if not run_id:
        print(json.dumps(out, indent=2)[:1000])
        raise SystemExit("ERROR: server did not return a run id.")
    print(f"Run {run_id} started ({args.preset or 'quick'} preset). Waiting...")
    deadline = time.time() + args.timeout
    detail: dict = {}
    while time.time() < deadline:
        detail = _api(server, code, "GET", f"/api/runs/{run_id}")
        status = (detail.get("run") or {}).get("status", "")
        prog = detail.get("progress") or {}
        done, total = prog.get("done", "?"), prog.get("total", "?")
        print(f"  status={status} progress={done}/{total}", flush=True)
        if status in TERMINAL:
            break
        time.sleep(5)
    else:
        print("Timed out waiting; check status later with:")
        print(f"  python3 recon.py status {run_id}")
        return 0
    return _print_findings(detail, run_id)


def _print_findings(detail: dict, run_id: str) -> int:
    run = detail.get("run") or {}
    findings = detail.get("findings") or []
    summary = run.get("summary") or {}
    print(f"\nRun {run_id}: status={run.get('status')} "
          f"findings={len(findings)}")
    if summary.get("counts_by_severity"):
        print("By severity:", summary["counts_by_severity"])
    for f in findings[:50]:
        sev = f.get("severity", "?")
        print(f"  [{sev}] {f.get('plugin_id', '?')}: "
              f"{f.get('title', '')[:120]}")
    if len(findings) > 50:
        print(f"  ... and {len(findings) - 50} more "
              f"(python3 recon.py findings {run_id})")
    return 0


def _cmd_status(args) -> int:
    server, code = _server(args), _code(args)
    detail = _api(server, code, "GET", f"/api/runs/{args.run_id}")
    return _print_findings(detail, args.run_id)


def _cmd_runs(args) -> int:
    server, code = _server(args), _code(args)
    out = _api(server, code, "GET", "/api/runs?limit=20")
    for r in out.get("runs", []):
        print(f"{r['id']}  {r.get('status', '?'):8}  "
              f"findings={r.get('findings_count', '?'):>3}  "
              f"{r.get('source_type', '')}  {r.get('created_at', '')}")
    return 0


def _cmd_findings(args) -> int:
    server, code = _server(args), _code(args)
    detail = _api(server, code, "GET", f"/api/runs/{args.run_id}")
    return _print_findings(detail, args.run_id)


def _cmd_plugins(args) -> int:
    server, code = _server(args), _code(args)
    out = _api(server, code, "GET", "/api/plugins")
    health = out.get("health") or {}
    print(f"plugins: registered={health.get('registered', '?')} "
          f"healthy={health.get('healthy', '?')}")
    for p in out.get("plugins", [])[:40]:
        print(f"  {p.get('id', '?')}")
    return 0


def main(argv: list[str]) -> int:
    # Optional leading 6-digit pair code: exchange it, then run the rest.
    rest = argv[1:]
    if rest and rest[0].isdigit() and len(rest[0]) == 6:
        pair_code = rest.pop(0)
        # Server for pairing: --server flag, env, or the baked-in default.
        server = "http://127.0.0.1:8000"
        if "--server" in rest:
            i = rest.index("--server")
            server = rest[i + 1].rstrip("/")
        elif os.environ.get("RECON_API_URL"):
            server = os.environ["RECON_API_URL"].rstrip("/")
        elif DEFAULT_SERVER and not DEFAULT_SERVER.startswith("__"):
            server = DEFAULT_SERVER.rstrip("/")
        _pair(server, pair_code)

    import argparse
    ap = argparse.ArgumentParser(prog="recon.py")
    ap.add_argument("--server", default="")
    ap.add_argument("--code", default="")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scan")
    p.add_argument("target", nargs="?")
    p.add_argument("--preset", default="quick",
                   choices=["quick", "standard", "deep"])
    p.add_argument("--timeout", type=int, default=600)
    p.set_defaults(fn=_cmd_scan)
    p = sub.add_parser("status")
    p.add_argument("run_id")
    p.set_defaults(fn=_cmd_status)
    p = sub.add_parser("runs")
    p.set_defaults(fn=_cmd_runs)
    p = sub.add_parser("findings")
    p.add_argument("run_id")
    p.set_defaults(fn=_cmd_findings)
    p = sub.add_parser("plugins")
    p.set_defaults(fn=_cmd_plugins)
    args = ap.parse_args(rest)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
