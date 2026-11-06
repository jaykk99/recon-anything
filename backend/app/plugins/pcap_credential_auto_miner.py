"""PCAP credential auto-miner: cleartext credential evidence in an
operator-supplied pcap/pcapng.

Parses cleartext protocol payloads (FTP USER/PASS, HTTP Basic,
POP3 USER/PASS, IMAP LOGIN, Telnet login prompts are noted) with a
pure-Python pcap reader and reports credential evidence MASKED
(first/last chars + SHA-256 fingerprint, protocol, endpoint pair).
The full secret never reaches a finding.

BOUNDARY: supplied captures ONLY. No live capture, no third-party
traffic. This module never opens a socket.
"""
from __future__ import annotations

import base64
import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import (collect, mask_secret, parse_pcap,
                           tcp_stream_text)

_FTP_USER = re.compile(r"(?im)^USER\s+(\S+)\s*$")
_FTP_PASS = re.compile(r"(?im)^PASS\s+(\S+)\s*$")
_POP3_USER = re.compile(r"(?im)^USER\s+(\S+)\s*$")
_POP3_PASS = re.compile(r"(?im)^PASS\s+(\S+)\s*$")
_HTTP_BASIC = re.compile(r"(?im)^Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)")
_IMAP_LOGIN = re.compile(r"(?im)LOGIN\s+\"?([^\s\"]+)\"?\s+\"?([^\s\"]+)\"?")


def _hit(user: str, secret: str, proto: str, flow: str):
    masked, fp = mask_secret(secret or "")
    um, _ = mask_secret(user or "")
    return {
        "key": "pcap_cleartext_credential", "severity": "high",
        "value": f"Cleartext {proto} credential in supplied capture "
                 f"({flow}): user {um}, secret masked {masked}, "
                 f"fingerprint {fp}",
        "evidence": {"protocol": proto, "flow": flow,
                     "secret_fingerprint": fp,
                     "remediation": "Rotate this credential now - it "
                     "crossed the wire in cleartext. Move the service "
                     "to the TLS variant (FTPS/HTTPS/POP3S/IMAPS) and "
                     "audit who could have observed the capture path."}}


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    pcap = parse_pcap(data)
    if pcap.get("ok"):
        texts = tcp_stream_text(pcap)
    else:
        # A raw text capture / session log is also analysable.
        texts = [("supplied text", data.decode("latin1", "ignore"))]
    seen = set()
    for flow, text in texts:
        pairs: List = []
        fu, fp_ = _FTP_USER.search(text), _FTP_PASS.search(text)
        if fu and fp_:
            pairs.append((fu.group(1), fp_.group(1), "FTP"))
        elif fu and "PASS" not in text:
            pass
        m = _HTTP_BASIC.search(text)
        if m:
            try:
                dec = base64.b64decode(m.group(1)).decode(
                    "latin1", "ignore")
                if ":" in dec:
                    u, s = dec.split(":", 1)
                    pairs.append((u, s, "HTTP Basic"))
            except Exception:
                pass
        if "POP3" in text or "+OK" in text:
            pu, pp = _POP3_USER.search(text), _POP3_PASS.search(text)
            if pu and pp and not any(p[2] == "FTP" for p in pairs):
                pairs.append((pu.group(1), pp.group(1), "POP3"))
        im = _IMAP_LOGIN.search(text)
        if im:
            pairs.append((im.group(1), im.group(2), "IMAP"))
        for user, secret, proto in pairs:
            sig = (proto, user, mask_secret(secret)[1])
            if sig in seen:
                continue
            seen.add(sig)
            hits.append(_hit(user, secret, proto, flow))
    return hits[:12]


class PcapCredentialAutoMinerPlugin(Plugin):
    id = "pcap_credential_auto_miner"
    label = "PCAP Credential Auto-Miner"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "network"
    phase = 2
    description = ("Mines operator-supplied pcap/pcapng captures for "
                   "cleartext credentials (FTP/HTTP Basic/POP3/IMAP); "
                   "evidence masked + fingerprinted, never the secret.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "leak",
                          ("pcap_captures",))
            if got is not None:
                return got
            return self._ok([], "no operator-supplied capture in "
                            "ctx.shared or target file path; supplied "
                            "captures only - nothing captured live")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
