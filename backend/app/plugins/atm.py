"""ATM infrastructure detection plugin.

Detection-only: finds ATM-related subdomains, portals, management
interfaces, vendor fingerprints and known CVEs. No jackpotting payloads,
no malware, no PIN capture, no auth bypass, no credential use. Every
check is a read-only DNS lookup or HTTP GET, or a connect-only TCP
probe (active mode only).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import re
import socket
import time
from typing import Dict, List, Tuple

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# ATM remote-management ports: open = finding (active mode only,
# connect-only, never authenticates).
ATM_MGMT_PORTS: List[Tuple[int, str]] = [
    (5900, "VNC"), (3389, "RDP"), (23, "Telnet"), (22, "SSH"),
]

# ATM-related subdomains worth resolving.
ATM_SUBDOMAINS = (
    "atm", "atms", "atm-locator", "atmlocator", "atm-finder", "atmfinder",
    "cash", "cash-locator", "cashlocator", "locations",
)

# ATM portal / locator paths probed on the target domain (GET only).
ATM_PORTAL_PATHS = (
    "/atm", "/atms", "/atm-locator", "/atm-locations", "/atm-finder",
    "/cash", "/cash-locator", "/locations/atm",
)

# Paths that smell like ATM remote-management interfaces (GET only,
# never submit credentials or attempt login).
ATM_MGMT_PATHS = (
    "/atm/admin", "/atm/manage", "/atm/remote", "/terminal",
    "/remote", "/xfs", "/aptra", "/opteva", "/selfserv",
)

# Verified public ATM CVEs (vendor keyword -> list of CVEs).
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

# Vendor keywords matched against page content / banners.
VENDOR_HINTS = ("diebold", "wincor", "ncr", "hyosung", "aptra", "opteva",
                "pro cash", "procash", "selfserv", "atm")

# Wireless-ish service banners flagged from scan data (best effort).
WIRELESS_HINTS = ("bluetooth", "wifi", "wi-fi", "802.11", "nfc",
                  "wireless", "hotspot")

# OpenStreetMap Overpass: keyless public ATM location lookup.
OVERPASS_URL = "https://overpass-api.de/api/interpreter"


class AtmPlugin(Plugin):
    id = "atm"
    label = "ATM Infrastructure Detection"
    accepts = ["domain", "url", "ip", "poi"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("ATM footprint: subdomains, portals, mgmt interfaces, "
                   "locations, vendor CVEs. Detection only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        mode = ctx.mode
        findings: List[Finding] = []
        ts = dt.datetime.now(dt.timezone.utc).isoformat()

        domain = domain_from_target(target.type, target.normalized)
        host = domain or (target.normalized if target.type == "ip" else "")

        # POI targets carry lat/lon + OSM metadata instead of a host.
        poi = getattr(target, "poi", None)
        if poi:
            findings.append(self._f(
                "infra", "atm_poi",
                f"ATM location: {poi.get('name', 'unknown')} - "
                f"{poi.get('address', 'no address')} "
                f"({poi.get('lat')},{poi.get('lon')})",
                source="OpenStreetMap", confidence=100, passive=True,
                evidence={"severity": "low", "lat": poi.get("lat"),
                          "lon": poi.get("lon"),
                          "operator": poi.get("operator", ""),
                          "website": poi.get("website", ""),
                          "phone": poi.get("phone", "")}))
            if poi.get("website"):
                findings.append(self._f(
                    "infra", "atm_website",
                    f"ATM operator website: {poi['website']} - "
                    f"run a website scan on it for full assessment",
                    source="atm plugin", confidence=90, passive=True,
                    evidence={"severity": "low"}))
            # Nearby ATMs via keyless Overpass API (public data).
            lat, lon = poi.get("lat"), poi.get("lon")
            if lat and lon:
                findings.extend(
                    await self._nearby_atms(float(lat), float(lon), ctx))

        if host and target.type != "ip":
            findings.extend(await self._atm_subdomains(host, ctx))
        if host:
            base = (target.normalized if target.type == "url"
                    else f"https://{host}/")
            findings.extend(
                await self._portal_paths(base, host, mode, ctx))
            findings.extend(
                await self._mgmt_paths(base, host, mode, ctx))
            findings.extend(await self._vendor_fingerprint(base, ctx))
            if mode == "active":
                findings.extend(await self._check_mgmt_ports(host))

        findings.extend(self._match_cves(ctx))
        findings.extend(self._flag_wireless(ctx))

        if not findings:
            findings.append(self._f(
                "infra", "atm_no_footprint",
                f"No ATM infrastructure footprint found on {host or target.raw} "
                f"at {ts}: no ATM subdomains, portals, mgmt interfaces, "
                f"vendor fingerprints, or CVEs detected",
                source="atm plugin", confidence=70, passive=True,
                evidence={"severity": "low",
                          "note": "Clean result is still a result: the scan "
                                  "checked and found nothing exposed."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"ATM recon on {host or target.raw}")
        res.duration_ms = dur
        return res

    async def _resolve(self, name: str) -> bool:
        """True if the hostname resolves (DNS only, no connection)."""
        try:
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(
                loop.getaddrinfo(name, 443, type=socket.SOCK_STREAM),
                timeout=4)
            return True
        except Exception:
            return False

    async def _atm_subdomains(self, domain: str, ctx: Ctx) -> List[Finding]:
        out = []
        results = await asyncio.gather(
            *[self._resolve(f"{sub}.{domain}") for sub in ATM_SUBDOMAINS])
        for sub, alive in zip(ATM_SUBDOMAINS, results):
            if alive:
                fqdn = f"{sub}.{domain}"
                ctx.publish("subdomains", fqdn)
                out.append(self._f(
                    "infra", "atm_subdomain",
                    f"ATM-related subdomain resolves: {fqdn}",
                    source="atm subdomain discovery", confidence=95,
                    passive=True,
                    evidence={"severity": "medium", "subdomain": fqdn,
                              "remediation": "Verify the subdomain is "
                              "intended to be public; remove or restrict "
                              "it if it exposes ATM infrastructure."}))
        return out

    async def _portal_paths(self, base: str, host: str, mode: str,
                            ctx: Ctx) -> List[Finding]:
        out = []
        passive = (mode == "passive")
        probes = await asyncio.gather(
            *[ctx.probe(base.rstrip("/") + p) for p in ATM_PORTAL_PATHS])
        for path, pr in zip(ATM_PORTAL_PATHS, probes):
            if pr.get("status") == 200:
                url = base.rstrip("/") + path
                ctx.publish("endpoints", url)
                title = self._title(pr.get("text", ""))
                out.append(self._f(
                    "infra", "atm_portal",
                    f"ATM portal page live on {host}: {path}"
                    + (f" ({title})" if title else ""),
                    source="atm portal probe", source_url=url,
                    confidence=85, passive=passive,
                    evidence={"severity": "medium", "path": path,
                              "remediation": "Confirm the portal is meant "
                              "to be public and carries no exposed "
                              "management functions."}))
        return out

    async def _mgmt_paths(self, base: str, host: str, mode: str,
                          ctx: Ctx) -> List[Finding]:
        out = []
        passive = (mode == "passive")
        probes = await asyncio.gather(
            *[ctx.probe(base.rstrip("/") + p) for p in ATM_MGMT_PATHS])
        for path, pr in zip(ATM_MGMT_PATHS, probes):
            if pr.get("status") == 200:
                url = base.rstrip("/") + path
                title = self._title(pr.get("text", ""))
                out.append(self._f(
                    "infra", "atm_mgmt_interface",
                    f"Possible ATM management interface exposed on {host}: "
                    f"{path}" + (f" ({title})" if title else ""),
                    source="atm mgmt probe", source_url=url,
                    confidence=75, passive=passive,
                    evidence={"severity": "high",
                              "remediation": "Restrict management "
                              "interfaces to private networks / VPN "
                              "immediately; never expose them publicly. "
                              "Detection only: no login attempted."}))
        return out

    async def _vendor_fingerprint(self, base: str, ctx: Ctx) -> List[Finding]:
        out = []
        page = await ctx.fetch_page(base, timeout=10)
        if not page:
            return out
        text = (page.get("text", "") or "")
        headers = page.get("headers", {}) or {}
        blob = text + "\n" + "\n".join(
            f"{k}:{v}" for k, v in headers.items())
        low = blob.lower()
        for hint in VENDOR_HINTS:
            if hint in low and hint not in ("atm",):
                out.append(self._f(
                    "infra", "atm_vendor",
                    f"ATM vendor fingerprint on page: '{hint}'",
                    source="atm vendor fingerprint",
                    source_url=page.get("url", base),
                    confidence=70, passive=True,
                    evidence={"severity": "medium", "vendor": hint,
                              "remediation": "Vendor disclosure helps "
                              "attackers target known CVEs; strip "
                              "vendor strings from public pages."}))
                break
        return out

    async def _nearby_atms(self, lat: float, lon: float,
                           ctx: Ctx) -> List[Finding]:
        """Keyless Overpass lookup: ATMs within 2km of the POI (public data)."""
        out = []
        try:
            query = (f'[out:json][timeout:10];node["amenity"="atm"]'
                     f'(around:2000,{lat},{lon});out 20;')
            resp = await ctx.http.get(OVERPASS_URL, params={"data": query},
                                      timeout=12)
            if resp.status_code != 200:
                return out
            data = resp.json()
            for el in (data.get("elements") or [])[:20]:
                tags = el.get("tags", {}) or {}
                name = tags.get("name") or tags.get("operator") or "ATM"
                alat, alon = el.get("lat"), el.get("lon")
                out.append(self._f(
                    "infra", "atm_nearby",
                    f"Nearby ATM (public OSM data): {name} "
                    f"({alat},{alon})",
                    source="OpenStreetMap Overpass", confidence=90,
                    passive=True,
                    evidence={"severity": "low", "lat": alat, "lon": alon,
                              "operator": tags.get("operator", "")}))
        except Exception:
            pass
        return out

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
                              "remediation": "Restrict remote management "
                              "to jump hosts / VPN. Detection only: "
                              "connect-only probe, no authentication "
                              "attempted."}))
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
                            passive=True,
                            evidence={"severity": "high", "vendor": vendor,
                                      "matched_hint": hint,
                                      "remediation": "Patch ATM software "
                                      "to vendor-fixed versions."}))
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
                        passive=True,
                        evidence={"severity": "medium",
                                  "remediation": "Wireless interfaces on "
                                  "ATM hardware widen the attack surface; "
                                  "verify they are in scope and secured."}))
                    return out  # one finding is enough
        return out

    @staticmethod
    def _title(html: str) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", html,
                      re.IGNORECASE | re.DOTALL)
        return (m.group(1).strip()[:80] if m else "")
