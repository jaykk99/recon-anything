"""SNMP community-string check - DETECTION-ONLY adaptation.

The list name says "brute"; the boundary does not. This plugin NEVER
guesses or dictionary-tests community strings. It detects posture
from operator-supplied device configs / banners / captures only:

- SNMP v1/v2c in use (cleartext, community-only auth model)
- a community configured with RW (read-write) access
- a community string present in a supplied config (value MASKED)
- v3 present but with noAuthNoPriv security level

The word "brute" is in the id for list traceability only; no brute
force of any kind is implemented or performed.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, mask_secret, text_of

_COMMUNITY_RES = [
    re.compile(r"(?im)^\s*snmp-server\s+community\s+(\S+)\s*(RO|RW)?"),
    re.compile(r"(?im)^\s*(rocommunity|rwcommunity)6?\s+(\S+)"),
    re.compile(r"(?im)^\s*(rocommunity|rwcommunity)\s+(\S+)"),
]
_V12C_RE = re.compile(r"(?i)\bSNMP\s*v?(1|2c)\b|snmpv2c|version\s*2c")
_V3_WEAK_RE = re.compile(
    r"(?i)snmp-server\s+group\s+\S+\s+v3\s+(noauth|authnopriv)?\b.*?"
    r"(noauth|noauthnopriv)", re.S)
_V3_USER_RE = re.compile(r"(?im)snmp-server\s+user\s+(\S+)\s+\S+\s+v3")


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    text = text_of(data)
    if not text:
        return hits
    found_rw = False
    found_ro = False
    for rx in _COMMUNITY_RES:
        for m in rx.finditer(text):
            groups = [g for g in m.groups() if g]
            secret = groups[-1] if groups else ""
            mode = ""
            if m.re is _COMMUNITY_RES[0]:
                secret = m.group(1)
                mode = (m.group(2) or "RO").upper()
            elif "rw" in m.group(1).lower():
                mode = "RW"
                secret = m.group(2)
            else:
                mode = "RO"
                secret = m.group(2)
            masked, fp = mask_secret(secret)
            if mode == "RW":
                found_rw = True
                hits.append({
                    "key": "snmp_v2c_rw_community", "severity": "high",
                    "value": f"SNMP v1/v2c community configured with "
                             f"RW access in supplied config (value "
                             f"masked {masked}, fp {fp}) - "
                             "write-capable cleartext management",
                    "evidence": {"fingerprint": fp, "access": "RW",
                                 "remediation": "Remove RW "
                                 "communities; migrate to SNMPv3 "
                                 "authPriv and restrict UDP 161 to "
                                 "management hosts."}})
            else:
                found_ro = True
    if (found_ro or _V12C_RE.search(text)) and not found_rw:
        # v1/v2c presence from an explicit community line or a
        # version statement in a banner/config.
        if found_ro or re.search(r"(?i)(community|version|banner)",
                                 text):
            hits.append({
                "key": "snmp_v1_v2c_in_use", "severity": "medium",
                "value": "SNMP v1/v2c in use (supplied config/banner) "
                         "- cleartext community-string auth model, "
                         "no encryption or per-user auth",
                "evidence": {"remediation": "Migrate to SNMPv3 "
                             "authPriv; if v2c must remain, use a "
                             "long unique read-only community and "
                             "ACL UDP 161 to management hosts only. "
                             "Detected from configuration - no "
                             "community guessing was performed."}})
    if _V3_WEAK_RE.search(text) or \
            re.search(r"(?i)v3\s+noauth", text):
        hits.append({
            "key": "snmp_v3_noauthnopriv", "severity": "medium",
            "value": "SNMPv3 configured with noAuthNoPriv posture in "
                     "supplied config - v3 in name, v1-grade "
                     "protection in practice",
            "evidence": {"remediation": "Require authPriv for all "
                         "SNMPv3 users/groups."}})
    # Dedupe by key.
    seen, out = set(), []
    for h in hits:
        if h["key"] not in seen:
            seen.add(h["key"])
            out.append(h)
    return out[:10]


class SnmpCommunityStringBrutePlugin(Plugin):
    id = "snmp_community_string_brute"
    label = "SNMP Community Posture (Detection-Only)"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "network"
    phase = 2
    description = ("DETECTION ONLY - no community guessing, ever: "
                   "flags SNMP v1/v2c-in-use, RW communities and "
                   "v3-noAuthNoPriv posture from supplied device "
                   "configs/banners, community values masked.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "infra",
                          ("snmp_configs", "device_configs"))
            if got is not None:
                return got
            return self._ok([], "no supplied device config/banner in "
                            "ctx.shared; detection-only lane does "
                            "not probe with guessed communities")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
