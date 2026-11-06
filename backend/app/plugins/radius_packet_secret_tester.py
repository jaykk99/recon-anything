"""RADIUS packet secret tester - DETECTION-ONLY adaptation
(BlastRADIUS posture).

The boundary forbids shared-secret dictionary testing, and none is
implemented. This plugin reads posture from operator-supplied
RADIUS captures / NAS configs only:

- an Access-Accept / Access-Reject / Accounting-Response packet
  WITHOUT a Message-Authenticator attribute (type 80) - the
  BlastRADIUS (CVE-2024-3596) forgery posture
- NAS config showing PAP-only auth or an explicit
  require-message-authenticator = no / blastradius protection off

No packets are sent and no secret is ever tested.
"""
from __future__ import annotations

import re
import struct
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, text_of

_RESPONSE_CODES = {2: "Access-Accept", 3: "Access-Reject",
                   5: "Accounting-Response", 43: "CoA-ACK"}


def parse_radius_packets(data: bytes) -> List[Dict[str, Any]]:
    """Walk a raw capture buffer for RADIUS packets. Never raises."""
    out: List[Dict[str, Any]] = []
    try:
        blob = data or b""
        pos = 0
        while pos + 20 <= len(blob) and len(out) < 256:
            code = blob[pos]
            ln = struct.unpack_from(">H", blob, pos + 2)[0]
            if code not in (1, 2, 3, 4, 5, 43) or ln < 20 or \
                    ln > 4096 or pos + ln > len(blob):
                pos += 1
                continue
            attrs = blob[pos + 20:pos + ln]
            types = []
            q = 0
            ok = True
            while q + 2 <= len(attrs):
                at, al = attrs[q], attrs[q + 1]
                if al < 2 or q + al > len(attrs):
                    ok = False
                    break
                types.append(at)
                q += al
            if not ok:
                pos += 1
                continue
            out.append({"code": code, "has_ma": 80 in types,
                        "attr_types": types})
            pos += ln
    except Exception:
        pass
    return out


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    packets = parse_radius_packets(data or b"")
    bad = [p for p in packets
           if p["code"] in _RESPONSE_CODES and not p["has_ma"]]
    if bad:
        names = sorted({_RESPONSE_CODES[p["code"]] for p in bad})
        hits.append({
            "key": "radius_response_without_message_authenticator",
            "severity": "high",
            "value": f"{len(bad)} RADIUS response packet(s) "
                     f"({', '.join(names)}) in supplied capture carry "
                     "NO Message-Authenticator attribute - "
                     "BlastRADIUS (CVE-2024-3596) forgery posture: "
                     "responses are only MD5/response-authenticator "
                     "protected",
            "evidence": {"packets": len(bad),
                         "remediation": "Require Message-"
                         "Authenticator on all RADIUS/UDP exchanges "
                         "(RFC 9429 posture), prefer RADIUS/TLS "
                         "(RadSec), and patch servers for "
                         "BlastRADIUS. Detected from the capture - "
                         "no shared secret was tested."}})
    text = text_of(data)
    if re.search(r"(?i)require[-_ ]message[-_ ]authenticator\s*[:=]\s*"
                 r"(no|false|0|off)", text) or \
            re.search(r"(?i)blastradius\s*[:=]\s*(off|disabled)", text):
        hits.append({
            "key": "radius_message_authenticator_not_required",
            "severity": "medium",
            "value": "Supplied NAS/RADIUS config does not require "
                     "Message-Authenticator (BlastRADIUS posture)",
            "evidence": {"remediation": "Set require-message-"
                         "authenticator to yes/enforced on server "
                         "and NAS, or move to RadSec."}})
    if re.search(r"(?im)auth[-_ ]?type\s*[:=]?\s*pap\b", text) and \
            re.search(r"(?i)(nas|radius|aaa)", text):
        hits.append({
            "key": "radius_pap_only_posture", "severity": "low",
            "value": "Supplied config shows PAP-only RADIUS auth "
                     "posture - credentials cross as a weakly "
                     "obfuscated password attribute on UDP",
            "evidence": {"remediation": "Prefer EAP methods with "
                         "Message-Authenticator / RadSec transport "
                         "over PAP-on-UDP."}})
    return hits[:10]


class RadiusPacketSecretTesterPlugin(Plugin):
    id = "radius_packet_secret_tester"
    label = "RADIUS Posture Tester (Detection-Only)"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "network"
    phase = 2
    description = ("DETECTION ONLY - no secret testing: BlastRADIUS "
                   "/ Message-Authenticator posture and PAP-only "
                   "config from supplied RADIUS captures / NAS "
                   "configs.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "infra",
                          ("radius_captures", "nas_configs"))
            if got is not None:
                return got
            return self._ok([], "no supplied RADIUS capture/config "
                            "in ctx.shared; detection-only lane "
                            "sends no packets and tests no secrets")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
