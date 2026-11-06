"""FTP passive port check (variant of port_audit) - DETECTION-ONLY
adaptation.

port_audit already does FTP banner + anonymous-login checks. This
delta is the PASV posture pass: issue PASV (anonymous or
operator-supplied creds) on an operator-owned server, parse 227
responses across repeated calls, and flag:
- predictable / sequential passive data-port allocation
- PASV address mismatch with the control-connection host
- a wide-open passive port range in supplied configs

BOUNDARY: detection of data-channel exposure/predictability only.
No transfer is intercepted, no data port is connected to, and no
third party's session is touched.
"""
from __future__ import annotations

import asyncio
import re
import socket
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, host_port_of, text_of

_227_RE = re.compile(
    r"227[^\d]*\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)")


def parse_227(text: str) -> Optional[Tuple[str, int]]:
    m = _227_RE.search(text or "")
    if not m:
        return None
    nums = [int(g) for g in m.groups()]
    return ".".join(str(n) for n in nums[:4]), nums[4] * 256 + nums[5]


def analyze_pasv_sequence(responses: List[str], control_host: str = ""
                          ) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    parsed = [parse_227(r) for r in responses]
    parsed = [p for p in parsed if p]
    ports = [p[1] for p in parsed]
    if len(ports) >= 3:
        diffs = [b - a for a, b in zip(ports, ports[1:])]
        if all(d == 1 for d in diffs) or \
                all(0 <= d <= 2 for d in diffs):
            hits.append({
                "key": "ftp_pasv_predictable_ports",
                "severity": "medium",
                "value": f"FTP server allocates passive data ports "
                         f"predictably across PASV calls: {ports} - "
                         "an attacker can pre-connect / race the "
                         "legitimate data channel (detection only; "
                         "no interception performed)",
                "evidence": {"ports": ports,
                             "remediation": "Allocate passive ports "
                             "randomly from a restricted range and "
                             "bind each PASV port to the control "
                             "connection's client IP (PASV must "
                             "match the authenticated session)."}})
    if control_host:
        mismatched = sorted({p[0] for p in parsed
                             if p[0] != control_host})
        if mismatched:
            hits.append({
                "key": "ftp_pasv_address_mismatch",
                "severity": "medium",
                "value": f"FTP PASV replies advertise address "
                         f"{mismatched} while the control "
                         f"connection is to {control_host} - clients "
                         "can be steered to a different host's data "
                         "channel",
                "evidence": {"pasv_addresses": mismatched,
                             "control_host": control_host,
                             "remediation": "Advertise the control "
                             "host's real address in PASV replies "
                             "(fix masquerade_address) and validate "
                             "it client-side."}})
    return hits


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    text = text_of(data)
    if not text:
        return []
    host = ""
    m = re.search(r"(?i)control\s*host\s*[:=]\s*(\d+\.\d+\.\d+\.\d+)",
                  text)
    if m:
        host = m.group(1)
    responses = _227_RE.findall(text)
    raw_responses = [ln for ln in text.splitlines() if "227" in ln]
    hits = analyze_pasv_sequence(raw_responses, host)
    m2 = re.search(r"(?i)pasv[_ ]?(?:min|max|range)\D{0,12}(\d{4,5})"
                   r"\D{1,6}(\d{4,5})", text)
    if m2:
        lo, hi = int(m2.group(1)), int(m2.group(2))
        if hi - lo > 5000:
            hits.append({
                "key": "ftp_pasv_wide_port_range",
                "severity": "low",
                "value": f"Supplied FTP config opens a wide passive "
                         f"range {lo}-{hi} ({hi - lo} ports) in the "
                         "firewall",
                "evidence": {"remediation": "Narrow the passive "
                             "range and prefer FTPS/SFTP; a wide "
                             "range is a wide firewall hole."}})
    return hits[:10]


def _pasv_rounds(host: str, port: int, rounds: int = 3,
                 timeout: float = 4.0) -> List[str]:
    out: List[str] = []
    try:
        with socket.create_connection((host, port),
                                      timeout=timeout) as sock:
            sock.settimeout(timeout)
            f = sock.makefile("r", encoding="latin1", newline="\r\n")
            f.readline()
            sock.sendall(b"USER anonymous\r\n")
            f.readline()
            sock.sendall(b"PASS anonymous@\r\n")
            f.readline()
            for _ in range(rounds):
                sock.sendall(b"PASV\r\n")
                line = f.readline()
                if not line:
                    break
                out.append(line.strip())
            try:
                sock.sendall(b"QUIT\r\n")
            except Exception:
                pass
    except Exception:
        pass
    return out


class FtpPassivePortHijackerPlugin(Plugin):
    id = "ftp_passive_port_hijacker"
    label = "FTP Passive Port Posture (Detection-Only)"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = False
    cost = Cost.FREE
    group = "network"
    description = ("DETECTION ONLY - no interception: PASV "
                   "predictability, PASV/control address mismatch "
                   "and wide passive ranges, via repeated PASV on "
                   "an operator-owned server or supplied logs.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "infra",
                          ("ftp_logs", "ftp_configs"))
            if got is not None:
                return got
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
        host, port = host_port_of(target, 21)
        try:
            resps = await asyncio.to_thread(_pasv_rounds, host, port)
        except Exception:
            resps = []
        if not resps:
            return self._degraded(f"no FTP PASV responses from "
                                  f"{host}:{port}")
        findings = []
        for hit in analyze_pasv_sequence(resps, host):
            ev = {"severity": hit["severity"]}
            ev.update(hit.get("evidence") or {})
            findings.append(self._f(
                "infra", hit["key"], hit["value"],
                source="FTP PASV probe", confidence=85, evidence=ev,
                passive=False))
        return self._ok(findings,
                        f"{len(resps)} PASV response(s) analysed")
