"""WebRTC SDP media leak check: statically parses operator-supplied
SDP offers / WebRTC config (and the target's served pages/JS) for
ICE candidates and RTC configuration leakage:

- host candidates carrying RFC1918 / LAN IPs (leaks the visitor's
  or server's internal addressing to any peer)
- TURN credentials embedded in SDP / iceServers config (masked)
- non-TLS TURN URLs combined with credentials
- srflx exposure is noted only when paired with the above

Text analysis only, keyless, no peer connection is established.
Distinct from the STUN probe (item 249): this audits SDP/config
content, it does not probe servers.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, is_private_ip, mask_secret, text_of

_CAND_RE = re.compile(
    r"candidate:\S+\s+\d+\s+(?:udp|tcp)\s+\d+\s+(\S+)\s+(\d+)\s+typ\s+"
    r"(host|srflx|prflx|relay)", re.I)
_TURN_CRED_RE = re.compile(
    r"(?i)(turns?:[^\s\"']*?):([^\s\"'@:]+):([^\s\"'@]+)@")
_ICESERVER_CRED_RE = re.compile(
    r"(?i)\"credential\"\s*:\s*\"([^\"]{4,})\"")


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    text = text_of(data)
    if not text:
        return hits
    private_hosts = set()
    for m in _CAND_RE.finditer(text):
        ip, typ = m.group(1), m.group(3).lower()
        if typ == "host" and is_private_ip(ip):
            private_hosts.add(ip)
    for ip in sorted(private_hosts)[:6]:
        hits.append({
            "key": "webrtc_host_candidate_private_ip_leak",
            "severity": "medium",
            "value": f"WebRTC host ICE candidate in supplied SDP/"
                     f"config leaks private address {ip} - any "
                     "peer (or page visitor) learns internal/LAN "
                     "addressing",
            "evidence": {"ip": ip,
                         "remediation": "Use mDNS (.local) host "
                         "candidates or suppress host candidates "
                         "where internal topology must stay private; "
                         "browsers mask these by default - a raw "
                         "RFC1918 candidate means that protection "
                         "is off or this is server-side SDP."}})
    creds = []
    for m in _TURN_CRED_RE.finditer(text):
        creds.append(m.group(3))
    for m in _ICESERVER_CRED_RE.finditer(text):
        ctx_before = text[max(0, m.start() - 200):m.start()]
        if "turn" in ctx_before.lower():
            creds.append(m.group(1))
    if creds:
        masked, fp = mask_secret(creds[0])
        hits.append({
            "key": "webrtc_turn_credentials_embedded",
            "severity": "high",
            "value": f"TURN credentials embedded in supplied SDP/"
                     f"WebRTC config (masked {masked}, fp {fp}) - "
                     "anyone with the page/config can use the TURN "
                     "server as a relay",
            "evidence": {"fingerprint": fp,
                         "remediation": "Issue short-lived TURN "
                         "credentials server-side (REST API / "
                         "ephemeral tokens); never ship static TURN "
                         "passwords to clients."}})
        if re.search(r"(?i)\bturn:[a-z0-9.\-]+:\d+", text):
            hits.append({
                "key": "webrtc_turn_non_tls_transport",
                "severity": "medium",
                "value": "TURN is configured over non-TLS turn: "
                         "URLs while credentials are present in the "
                         "same config",
                "evidence": {"remediation": "Use turns: (TLS, "
                             "5349) URLs for credentialed TURN."}})
    return hits[:10]


class WebrtcSdpMediaLeakCheckPlugin(Plugin):
    id = "webrtc_sdp_media_leak_check"
    label = "WebRTC SDP Media Leak Check"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "web"
    phase = 2
    description = ("Static SDP/config audit: host candidates "
                   "leaking RFC1918 IPs, embedded TURN credentials "
                   "(masked), non-TLS TURN with credentials. No peer "
                   "connection is established.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "web",
                          ("sdp_data", "webrtc_configs"))
            if got is not None:
                return got
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
        # Page lane: audit the target's own served homepage/JS text
        # from the shared fetch cache.
        findings = []
        try:
            page = await ctx.fetch_page(target.normalized)
        except Exception:
            page = None
        if page and page.get("text"):
            for hit in analyze(page["text"].encode(
                    "utf-8", "ignore"), "homepage"):
                ev = {"severity": hit["severity"]}
                ev.update(hit.get("evidence") or {})
                findings.append(self._f(
                    "web", hit["key"], hit["value"],
                    source="homepage WebRTC config", confidence=75,
                    evidence=ev))
        return self._ok(findings, "served-page WebRTC audit done")
