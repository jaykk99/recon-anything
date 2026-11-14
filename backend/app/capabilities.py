"""Capability doctor: detect dependency drift before it silently eats a stage.

The pipeline leans on external analyzers (Slither, Aderyn, Semgrep, solc,
Echidna/Medusa, Mythril, nuclei, the crawlers) and on keyless public OSINT
APIs (crt.sh, RDAP, Wayback CDX). Either kind can break a whole stage
without a single error surfacing in the scan: a CLI renames a flag, a
version string changes shape, an endpoint starts returning HTML instead of
JSON, or a service quietly retires a route. Plugins then skip "cleanly" and
the run looks empty rather than broken.

This module answers "is the stack I think I have, the stack I actually
have?" for both kinds of dependency:

  * ``probe_tools()``    - binary present? ``--version`` still parseable?
                            flag still accepted, or renamed?
  * ``probe_upstreams()``- endpoint reachable? status sane? response SHAPE
                            still what the parser expects?
  * ``doctor()``         - both, plus a summary and the affected features.

Status vocabulary (deliberately small):
  ok        - dependency works and looks like itself
  missing   - binary not on PATH (feature degrades by design)
  drift     - present but CHANGED: flags/version shape/response schema
  degraded  - reachable but unhealthy right now (5xx, 429, timeout)
  error     - unexpected local failure running the probe

Surfaces: ``python -m app.capabilities`` (CLI), ``GET /api/capabilities``,
and the MCP tool ``recon_capabilities``. Local probes never touch the
network; upstream probes are opt-in (``--network`` / ``?network=true``).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence

PROBE_TIMEOUT = float(os.environ.get("RECON_CAPABILITY_TIMEOUT", "4"))
UPSTREAM_TIMEOUT = float(os.environ.get("RECON_CAPABILITY_NET_TIMEOUT", "8"))

# ---------------------------------------------------------------------------
# External CLI analyzers. version_re is the shape the plugin's parser expects;
# a binary whose output stops matching it is "drift", not "missing" - the
# distinction the doctor exists to make.
# ---------------------------------------------------------------------------
CLI_TOOLS: List[Dict[str, Any]] = [
    {"name": "slither", "args": ["--version"],
     "version_re": r"\d+\.\d+\.\d+", "used_by": ["audit_toolbox"]},
    {"name": "aderyn", "args": ["--version"],
     "version_re": r"\d+\.\d+\.\d+", "used_by": ["audit_toolbox"]},
    {"name": "semgrep", "args": ["--version"],
     "version_re": r"\d+\.\d+\.\d+", "used_by": ["audit_toolbox"]},
    {"name": "solc", "args": ["--version"],
     "version_re": r"\d+\.\d+\.\d+", "used_by": ["contract_fuzz",
                                                 "audit_toolbox"]},
    {"name": "echidna", "args": ["--version"],
     "version_re": r"\d+\.\d+\.\d+", "used_by": ["contract_fuzz"]},
    {"name": "medusa", "args": ["--version"],
     "version_re": r"\d+\.\d+\.\d+", "used_by": ["contract_fuzz"]},
    {"name": "myth", "args": ["--version"],
     "version_re": r"\d+\.\d+\.\d+", "used_by": ["contract_simulation"]},
    {"name": "nuclei", "args": ["-version"],
     "version_re": r"v?\d+\.\d+\.\d+", "used_by": ["nuclei_templates",
                                                   "nuclei_cve_pack"]},
    {"name": "gobuster", "args": ["version"],
     "version_re": r"\d+\.\d+\.\d+", "used_by": ["gobuster"]},
    {"name": "feroxbuster", "args": ["--version"],
     "version_re": r"\d+\.\d+\.\d+", "used_by": ["feroxbuster"]},
    {"name": "katana", "args": ["-version"],
     "version_re": r"v?\d+\.\d+\.\d+", "used_by": ["katana"]},
    {"name": "httrack", "args": ["--version"],
     "version_re": r"\d+\.\d+\.\d+", "used_by": ["httrack"]},
    {"name": "dig", "args": ["-v"],
     "version_re": r"\d+\.\d+", "used_by": ["cmd_dns", "cmd_dns_nscheck",
                                            "cmd_dns_recurse"]},
    {"name": "openssl", "args": ["version"],
     "version_re": r"\d+\.\d+\.\d+", "used_by": ["cmd_tls", "cmd_ocsp"]},
    {"name": "nc", "args": ["-h"], "version_re": None, "nonzero_ok": True,
     "used_by": ["cmd_ports"]},
    {"name": "nmap", "args": ["--version"],
     "version_re": r"\d+\.\d+", "used_by": ["port_audit"]},
]

# Flag/output changes that mean "installed, but no longer the interface we
# call". Matched case-insensitively against stdout+stderr.
_DRIFT_PATTERNS = re.compile(
    r"unknown (option|flag|argument)|unrecognized (option|argument)|"
    r"invalid option|no such option|usage:.*\b--help\b|"
    r"command not found|is not a valid command", re.I)

# ---------------------------------------------------------------------------
# Keyless upstream APIs. expect says how the parser validates the response;
# a 200 with the wrong shape is drift (the service changed under us).
# ---------------------------------------------------------------------------
UPSTREAMS: List[Dict[str, Any]] = [
    {"name": "crt.sh", "url": "https://crt.sh/?q=example.com&output=json",
     "expect": "json-list", "used_by": ["subdomains", "censys_enum"]},
    {"name": "rdap.org", "url": "https://rdap.org/domain/example.com",
     "expect": "json-dict", "keys": ["ldhName", "objectClassName", "handle"],
     "used_by": ["rdap"]},
    {"name": "wayback-cdx",
     "url": "http://web.archive.org/cdx/search/cdx?url=example.com"
            "&output=json&limit=1",
     "expect": "json-list", "used_by": ["wayback", "gau", "artifacts"]},
]


def _classify_output(spec: Dict[str, Any], returncode: int,
                     output: str) -> Dict[str, Any]:
    """Decide ok / drift / error from one CLI version invocation."""
    if returncode != 0 and not spec.get("nonzero_ok"):
        if _DRIFT_PATTERNS.search(output or ""):
            return {"status": "drift",
                    "detail": "flag/interface changed: " +
                              (output or "").strip().splitlines()[0][:160]}
        return {"status": "error",
                "detail": f"exit {returncode}: "
                          f"{(output or '').strip().splitlines()[0][:160]}"
                          if (output or "").strip() else f"exit {returncode}"}
    if spec.get("nonzero_ok") and _DRIFT_PATTERNS.search(output or ""):
        # e.g. `nc -h` normally exits 1; an "unknown option" message means
        # the binary is something else entirely.
        return {"status": "drift",
                "detail": "flag/interface changed: " +
                          (output or "").strip().splitlines()[0][:160]}
    version_re = spec.get("version_re")
    if version_re:
        m = re.search(version_re, output or "")
        if not m:
            return {"status": "drift",
                    "detail": "version output no longer matches "
                              f"{version_re!r}"}
        return {"status": "ok", "version": m.group(0)}
    return {"status": "ok", "version": None}


def probe_tool(spec: Dict[str, Any], *,
               which: Callable[[str], Optional[str]] = shutil.which,
               runner: Callable[..., Any] = subprocess.run,
               timeout: float = PROBE_TIMEOUT) -> Dict[str, Any]:
    """Probe one CLI tool: present, still callable, output still parseable."""
    base = {"name": spec["name"], "used_by": spec.get("used_by", []),
            "kind": "cli"}
    path = which(spec["name"])
    if not path:
        return {**base, "status": "missing",
                "detail": "not on PATH (this stage degrades, by design)"}
    try:
        cp = runner([path, *spec.get("args", [])], capture_output=True,
                    text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {**base, "status": "degraded", "path": path,
                "detail": f"version probe timed out after {timeout:g}s"}
    except Exception as e:  # noqa: BLE001 - a probe never raises
        return {**base, "status": "error", "path": path,
                "detail": f"{type(e).__name__}: {str(e)[:160]}"}
    output = f"{cp.stdout or ''}\n{cp.stderr or ''}".strip()
    verdict = _classify_output(spec, cp.returncode, output)
    return {**base, "path": path, **verdict}


def _validate_shape(spec: Dict[str, Any], body: str) -> Optional[str]:
    """None when the body still matches the parser's expectation."""
    expect = spec.get("expect")
    if expect is None:
        return None
    if expect.startswith("text"):
        needle = spec.get("contains")
        if needle and needle not in body:
            return f"response no longer contains {needle!r}"
        return None
    try:
        data = json.loads(body)
    except Exception:
        return "response is not JSON any more"
    if expect == "json-list" and not isinstance(data, list):
        return f"expected a JSON list, got {type(data).__name__}"
    if expect == "json-dict" and not isinstance(data, dict):
        return f"expected a JSON object, got {type(data).__name__}"
    keys = spec.get("keys") or []
    if keys and isinstance(data, dict) and not (set(keys) & set(data)):
        return f"none of the expected keys {keys} are present"
    return None


def probe_upstream(spec: Dict[str, Any], *,
                   client_factory: Optional[Callable[[], Any]] = None,
                   timeout: float = UPSTREAM_TIMEOUT) -> Dict[str, Any]:
    """Probe one keyless upstream API: reachable AND still the same shape."""
    base = {"name": spec["name"], "used_by": spec.get("used_by", []),
            "kind": "api", "url": spec.get("url")}
    client = None
    try:
        if client_factory is not None:
            client = client_factory()
        else:
            from . import net
            client = net.sync_client(timeout=timeout)
        resp = client.get(spec["url"], timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return {**base, "status": "degraded",
                "detail": f"unreachable: {type(e).__name__}: {str(e)[:140]}"}
    finally:
        if client is not None and client_factory is None:
            try:
                client.close()
            except Exception:
                pass
    try:
        status = int(resp.status_code)
        body = resp.text or ""
    except Exception:  # a stub response in tests
        status, body = 0, ""
    if status in (404, 405, 410, 401, 403):
        return {**base, "status": "drift", "http_status": status,
                "detail": f"endpoint answers {status} - route or auth changed"}
    if status == 429:
        return {**base, "status": "degraded", "http_status": status,
                "detail": "rate limited (429) - back off; not a drift"}
    if status >= 500 or status == 0:
        return {**base, "status": "degraded", "http_status": status,
                "detail": f"upstream unhealthy ({status or 'no status'})"}
    problem = _validate_shape(spec, body)
    if problem:
        return {**base, "status": "drift", "http_status": status,
                "detail": problem}
    return {**base, "status": "ok", "http_status": status}


def doctor(*, network: bool = False,
           tools: Optional[Sequence[str]] = None,
           client_factory: Optional[Callable[[], Any]] = None,
           which: Callable[[str], Optional[str]] = shutil.which,
           runner: Callable[..., Any] = subprocess.run) -> Dict[str, Any]:
    """Full capability report. Local probes always; upstreams on request."""
    wanted = {t.lower() for t in tools} if tools else None
    cli = [probe_tool(spec, which=which, runner=runner)
           for spec in CLI_TOOLS
           if wanted is None or spec["name"].lower() in wanted]
    api: List[Dict[str, Any]] = []
    if network:
        api = [probe_upstream(spec, client_factory=client_factory)
               for spec in UPSTREAMS]

    counts: Dict[str, int] = {}
    degraded_features: Dict[str, List[str]] = {}
    for entry in cli + api:
        status = entry["status"]
        counts[status] = counts.get(status, 0) + 1
        if status in ("missing", "drift", "degraded", "error"):
            for feature in entry.get("used_by", []):
                degraded_features.setdefault(feature, []).append(entry["name"])
    return {
        "checked": len(cli) + len(api),
        "network_probed": network,
        "counts": counts,
        "tools": cli,
        "upstreams": api,
        "degraded_features": {k: sorted(v)
                              for k, v in sorted(degraded_features.items())},
        "note": ("drift means the dependency is present but its interface "
                 "changed - fix the wrapper; missing/degraded means the "
                 "stage skips cleanly and the run is shallower than it "
                 "looks."),
    }


def health_summary(**kwargs) -> Dict[str, Any]:
    """Cheap local-only summary for /api/health (no subprocess, no network)."""
    present, absent = [], []
    for spec in CLI_TOOLS:
        (present if shutil.which(spec["name"]) else absent).append(spec["name"])
    return {"tools_present": present, "tools_absent": absent,
            "tool_count": len(CLI_TOOLS)}


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        prog="python -m app.capabilities",
        description="Check external analyzers and keyless OSINT upstreams "
                    "for missing tools and interface drift.")
    ap.add_argument("--network", action="store_true",
                    help="also probe the upstream APIs (sends 3 requests)")
    ap.add_argument("--tool", action="append", dest="tools",
                    help="only this tool (repeatable)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    report = doctor(network=args.network, tools=args.tools)
    if args.json:
        print(json.dumps(report, indent=1))
        return 0
    print(f"capabilities: {report['checked']} checked "
          f"({json.dumps(report['counts'])})")
    for entry in report["tools"] + report["upstreams"]:
        line = f"  {entry['status']:8s} {entry['name']:12s}"
        if entry.get("version"):
            line += f" {entry['version']}"
        if entry.get("detail"):
            line += f"  - {entry['detail']}"
        print(line)
    if report["degraded_features"]:
        print("degraded features:")
        for feature, deps in report["degraded_features"].items():
            print(f"  {feature}: {', '.join(deps)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
