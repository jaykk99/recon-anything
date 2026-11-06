"""SSL pinning posture audit (Cat-7 #186, VARIANT of binex).

DETECTION ONLY - posture finding. No pinning removal, no Frida
script, no traffic interception. Parses res/xml network-security-
config (pin-set, cleartext flags) and detects OkHttp
CertificatePinner / TrustManager / Conscrypt use in DEX strings.
Verdict: pinned-strong / pinned-bypassable-pattern / no pinning.
"""
from __future__ import annotations

import re
from typing import Dict, List

from ._cat7_common import Cat7Plugin, finding

PIN_CODE = ("CertificatePinner", "certificatePinner", "PinningTrustManager",
            "Conscrypt", "TrustKit", "ssl_pinning")


def analyze_pinning(art: Dict) -> List[Dict]:
    out: List[Dict] = []
    nsc = ""
    for name, text in (art.get("texts") or {}).items():
        if "network_security_config" in name or \
                name.endswith("network-security-config.xml"):
            nsc = text
            break
    dex = (art.get("dex_text") or "") + "\n" + (art.get("all_text") or "")
    has_pinset = "<pin-set" in nsc or "<pin " in nsc or "digest=" in nsc
    cleartext = bool(re.search(
        r"cleartextTrafficPermitted\s*=\s*\"true\"", nsc)) or \
        "cleartextTrafficPermitted=\"true\"" in (art.get("manifest") or "")
    code_pinning = sorted(p for p in PIN_CODE if p in dex)
    trust_all = "checkServerTrusted" in dex and \
        ("X509TrustManager" in dex or "ALLOW_ALL" in dex)
    if trust_all:
        out.append(finding(
            "pinning_trust_all_pattern",
            "Pinning verdict pinned-bypassable-pattern: custom "
            "TrustManager with trust-all shaped code present",
            "high", source="DEX strings", confidence=78,
            verdict="pinned-bypassable-pattern"))
    if cleartext:
        out.append(finding(
            "pinning_cleartext_permitted",
            "network-security-config permits cleartext traffic "
            "(cleartextTrafficPermitted=true)",
            "high", source="network_security_config.xml", confidence=88,
            verdict="cleartext-permitted"))
    if not has_pinset and not code_pinning and not trust_all:
        out.append(finding(
            "pinning_absent",
            "Pinning verdict no-pinning: no pin-set in network "
            "security config and no CertificatePinner/TrustManager "
            "pinning code in DEX",
            "medium", source="APK", confidence=78,
            verdict="no-pinning"))
    return out


class SslPinningRemoverFridaPlugin(Cat7Plugin):
    id = "ssl_pinning_remover_frida"
    label = "SSL Pinning (posture only)"
    description = ("DETECTION ONLY: static certificate-pinning "
                   "posture audit of an operator-supplied APK. No "
                   "pinning removal, no interception.")

    def analyze(self, art: Dict) -> List[Dict]:
        return analyze_pinning(art)
