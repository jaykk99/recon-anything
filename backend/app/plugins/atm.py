"""ATM security assessment plugin (authorized engagements only).

Detection-only. No jackpotting payloads, malware, PIN capture, or bypass
guidance. Skips unless module_overrides["atm"] == "authorized".
"""
from __future__ import annotations

import asyncio
import datetime as dt
import time
from typing import Dict, List, Tuple

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# ATM remote-management ports: open = finding.
ATM_MGMT_PORTS: List[Tuple[int, str]] = [
    (5900, "VNC"), (3389, "RDP"), (23, "Telnet"), (22, "SSH"),
]

# Verified public ATM CVEs (vendor keyword -> list of CVEs).
# Keep only IDs confirmed against public advisories.
ATM_CVES: Dict[str, List[Dict[str, str]]] = {
    "diebold": [
        {"id": "CVE-2018-9094",
         "title": "Opteva AFD platform: physical and authentication bypass, "
                  "unauthenticated cash vending possible (IOActive, 2017)"},
        {"id": "CVE-2018-9100",
         "title": "Diebold Nixdorf ATM flaws allowed firmware modification and "
                  "black-box protection bypass (Positive Technologies)"},
    ],
    "wincor": [
        {"id": "CVE-2018-9100",
         "title": "Wincor Cineo (RM3/CMD-V5) owned by Diebold Nixdorf: firmware "
                  "modification bypassed black-box protections (Positive Technologies)"},
    ],
    "ncr": [
        {"id": "CVE-2020-10124",
         "title": "SelfServ APTRA XFS: no encryption/auth on host <-> BNA "
                  "message bus (CERT/CC)"},
        {"id": "CVE-2020-10147",
         "title": "SelfServ APTRA XFS 05.01.00: missing authentication for "
                  "critical function, deposit forgery risk (CERT/CC)"},
        {"id": "CVE-2020-10123",
         "title": "SelfServ APTRA XFS 05.01.00: dispenser session-key "
                  "generation not authenticated, cash dispense possible (CERT/CC)"},
    ],
}

# Vendor keywords we match against shared tech/banner findings.
VENDOR_HINTS = ("diebold", "wincor", "ncr", "hyosung", "aptra", "opteva",
                "pro cash", "procash", "selfserv", "atm")

# Wireless-ish service banners flagged from scan data (best effort).
WIRELESS_HINTS = ("bluetooth", "wifi", "wi-fi", "802.11", "nfc",
                  "wireless", "hotspot")


class AtmPlugin(Plugin):
    id = "atm"
    label = "ATM Security Assessment"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("ATM footprint: locations, exposed mgmt, known CVEs "
                   "(authorized only).")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        if ctx.module_overrides.get("atm") != "authorized":
            return self._skipped(
                "ATM module requires explicit authorization "
                "(module_overrides atm=authorized)")
        findings: List[Finding] = []
        ts = dt.datetime.now(dt.timezone.utc).isoformat()

        # Paper-trail finding: authorization was claimed for this run.
        findings.append(self._f(
            "infra", "atm_auth_claim",
            f"Authorization claimed for ATM assessment at {ts}",
            source="atm authorization gate", confidence=100, passive=True,
            evidence={"note": "Read-only detection only. No exploits run."}))

        domain = domain_from_target(target.type, target.normalized)
        host = domain or (target.normalized if target.type == "ip" else "")
        if host:
            findings.extend(await self._check_mgmt_ports(host))

        findings.extend(self._match_cves(ctx))
        findings.extend(self._flag_wireless(ctx))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"ATM recon on {host or target.raw}")
        res.duration_ms = dur
        return res

    async def _check_mgmt_ports(self, host: str) -> List[Finding]:
        async def probe(port: int, service: str):
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=2.5)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return (port, service, True)
            except Exception:
                return (port, service, False)

        results = await asyncio.gather(
            *[probe(p, s) for p, s in ATM_MGMT_PORTS])
        out = []
        for port, service, is_open in results:
            if is_open:
                out.append(self._f(
                    "infra", "atm_exposed_mgmt",
                    f"ATM remote-mgmt port OPEN on {host}: {port} ({service})",
                    source="atm mgmt probe", confidence=95, passive=False,
                    evidence={"severity": "high",
                              "note": "Remote management exposed on an ATM "
                                      "network host. Verify in scope, then "
                                      "restrict to jump hosts."}))
        return out

    def _match_cves(self, ctx: Ctx) -> List[Finding]:
        hay = " ".join(
            str(x) for items in ctx.shared.values() for x in items).lower()
        matched = [v for v in VENDOR_HINTS if v in hay]
        if not matched:
            return []
        out = []
        seen = set()
        for hint in matched:
            for vendor, cves in ATM_CVES.items():
                if vendor in hint or hint in vendor:
                    for c in cves:
                        if c["id"] in seen:
                            continue
                        seen.add(c["id"])
                        out.append(self._f(
                            "infra", "atm_cve",
                            f"{c['id']}: {c['title']}",
                            source="atm CVE matcher", confidence=70,
                            evidence={"severity": "high", "vendor": vendor,
                                      "matched_hint": hint}))
        return out

    def _flag_wireless(self, ctx: Ctx) -> List[Finding]:
        """Best-effort: flag Bluetooth/WiFi/NFC service banners in scan data."""
        out = []
        for items in ctx.shared.values():
            for x in items:
                s = str(x)
                if any(h in s.lower() for h in WIRELESS_HINTS):
                    out.append(self._f(
                        "infra", "atm_wireless",
                        f"Wireless interface hint in scan data: {s[:200]}",
                        source="atm wireless check", confidence=60,
                        evidence={"severity": "medium",
                                  "note": "Wireless interfaces on ATM hardware "
                                          "widen the attack surface. Verify in "
                                          "scope."}))
                    return out  # one finding is enough
        return out
