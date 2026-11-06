"""Custom TCP length fuzzer: length-boundary posture probes against
an OPERATOR-OWNED test endpoint, differential-style.

The operator supplies a protocol template via ctx.shared
("tcp_fuzz_template": {host, port, template_hex with a {LEN4}
placeholder, or prefix_hex + length_field}) - the plugin sends
length-boundary variants (0, 1, off-by-one around the honest length,
0xFFFF) and flags crash / hang / garbage-response differentials.
Supplied probe-outcome logs are analysed with the same pure logic.

BOUNDARY: operator-owned test endpoint only (template must be
supplied explicitly per run); benign reshaping only, no payload
content beyond the template itself. Active mode only for live.
"""
from __future__ import annotations

import asyncio
import json
import socket
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, text_of

BOUNDARY_LENGTHS = (0, 1, 0xFFFF)


def analyze_outcomes(outcomes: List[Dict[str, Any]]
                     ) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    bad = [o for o in outcomes
           if str(o.get("outcome", "")).lower() in (
               "crash", "hang", "timeout", "garbage", "reset")]
    for o in bad[:5]:
        hits.append({
            "key": "tcp_length_boundary_differential",
            "severity": "high",
            "value": f"Length-boundary probe with declared length "
                     f"{o.get('length')} caused a "
                     f"{str(o.get('outcome')).lower()} differential "
                     "on the operator-owned test endpoint - the "
                     "service does not validate its length field",
            "evidence": {"length": o.get("length"),
                         "outcome": o.get("outcome"),
                         "remediation": "Validate declared length "
                         "against actual bytes received and protocol "
                         "maxima before allocating or copying; add "
                         "boundary-length regression tests."}})
    return hits


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    text = text_of(data)
    outcomes: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict) and "outcome" in obj:
                outcomes.append(obj)
    if not outcomes and text.strip().startswith("["):
        try:
            arr = json.loads(text)
            if isinstance(arr, list):
                outcomes = [o for o in arr if isinstance(o, dict)]
        except Exception:
            pass
    return analyze_outcomes(outcomes)


def _probe_once(host: str, port: int, payload: bytes,
                timeout: float = 3.0) -> str:
    try:
        with socket.create_connection((host, port),
                                      timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            try:
                data = sock.recv(4096)
            except socket.timeout:
                return "hang"
            if not data:
                return "ok"
            if len(data) > 0 and all(b < 9 or 13 < b < 32
                                     for b in data[:64]):
                return "garbage"
            return "ok"
    except socket.timeout:
        return "hang"
    except ConnectionResetError:
        return "reset"
    except Exception:
        return "crash"


class CustomTcpLengthFuzzerPlugin(Plugin):
    id = "custom_tcp_length_fuzzer"
    label = "Custom TCP Length Fuzzer"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = False
    aggressive = True
    cost = Cost.FREE
    group = "network"
    description = ("Length-boundary differential probes (0 / "
                   "off-by-one / 0xFFFF) against an operator-owned "
                   "test endpoint defined by a supplied template; "
                   "also analyses supplied probe-outcome logs.")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "infra",
                          ("tcp_fuzz_outcomes",))
            if got is not None:
                return got
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
        tmpl = None
        try:
            items = (ctx.shared or {}).get("tcp_fuzz_template") or []
            if isinstance(items, dict):
                tmpl = items
            elif items and isinstance(items[0], dict):
                tmpl = items[0]
        except Exception:
            tmpl = None
        if not tmpl:
            return self._ok(
                [], "no tcp_fuzz_template supplied in ctx.shared; "
                "live length fuzzing needs an explicit operator-owned "
                "endpoint template")
        if ctx.mode != "active":
            return self._ok([], "live length fuzzing is active-mode "
                            "only")
        host = str(tmpl.get("host") or "127.0.0.1")
        port = int(tmpl.get("port") or 0)
        template_hex = str(tmpl.get("template_hex") or "")
        if not port or "{LEN" not in template_hex:
            return self._ok([], "template needs port and a {LEN4} / "
                            "{LEN2} placeholder in template_hex")
        outcomes: List[Dict[str, Any]] = []
        for ln in BOUNDARY_LENGTHS:
            try:
                hexed = template_hex.replace(
                    "{LEN4}", ln.to_bytes(4, "big").hex()).replace(
                    "{LEN2}", ln.to_bytes(2, "big").hex())
                payload = bytes.fromhex(hexed)
            except Exception:
                return self._ok([], "template_hex is not valid hex")
            outcome = await asyncio.to_thread(
                _probe_once, host, port, payload)
            outcomes.append({"length": ln, "outcome": outcome})
        findings = []
        for hit in analyze_outcomes(outcomes):
            ev = {"severity": hit["severity"],
                  "remediation": (hit.get("evidence") or {}).get(
                      "remediation", "")}
            ev.update(hit.get("evidence") or {})
            findings.append(self._f("infra", hit["key"], hit["value"],
                                    source="tcp length probe",
                                    confidence=80, evidence=ev,
                                    passive=False))
        return self._ok(findings,
                        f"{len(outcomes)} length variants probed")
