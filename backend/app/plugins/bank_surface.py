"""Bank web-surface leak + fleet panel detection.

Two detection-only checks on a bank's public web surface:

1. Internal leaks on public pages. Branch/ATM locator pages, homepages
   and their scripts sometimes leak RFC1918 IPs, loopback URLs and
   internal hostnames (*.local, *.corp, intranet.*) - a map of the
   internal network, published by accident.
2. ATM fleet-management panel fingerprints. Pages that fingerprint as
   fleet platforms (KAL Kalignite, NCR APTRA, Gasper, Postilion,
   Base24...) on public paths are flagged: existence + fingerprint
   only, read-only GETs. We never log in, never submit credentials,
   never interact with a panel beyond reading its public page.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import List, Tuple
from urllib.parse import urljoin

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

TIMEOUT = 10

# Branch / ATM locator paths worth reading for internal leaks.
LOCATOR_PATHS = (
    "/atm-locator", "/branch-locator", "/branch-and-atm-locator",
    "/locations", "/find-a-branch", "/branches", "/atms", "/atm",
    "/find-atm", "/find-an-atm", "/atm-finder", "/branch-finder",
    "/find-us", "/find-a-location", "/locate-us", "/locator",
    "/branch-atm-locator", "/atm-branch-locator", "/where-to-bank",
    "/en/locations", "/personal/locations", "/about/locations",
    "/contact/locations", "/maps", "/store-locator",
)

# Paths that smell like fleet-management / payment-switch consoles
# (GET existence + fingerprint only, same pattern as the atm plugin's
# mgmt paths - never a login attempt).
PANEL_PATHS = (
    "/kalignite", "/aptra", "/aptra-activate", "/gasper",
    "/postilion", "/base24", "/fleet-manager", "/terminal-manager",
    "/vynamic", "/opticash", "/moniview", "/esq", "/inetco",
    "/auriga", "/wws", "/bankworld", "/tranzware", "/smartvista",
    "/way4", "/tango", "/switch-manager", "/atm-monitoring",
    "/terminal-management", "/device-manager", "/fleet", "/nmc",
    "/network-management", "/atmmonitor", "/atm-manager",
)

# ATM fleet / payment-switch platform fingerprints:
# (display name, distinctive pattern). Covers ATM fleet-management,
# ATM software stacks, and the core payment switches a financial
# institution runs. Fingerprint = identify the platform from a public
# page; detection only, no interaction beyond a read.
FLEET_PLATFORMS = (
    # --- ATM fleet-management / monitoring ---
    ("KAL Kalignite", r"kalignite"),
    ("NCR APTRA", r"\baptra\b"),
    ("NCR Vision (fleet monitoring)", r"ncr\s+vision|\baptra\s+vision"),
    ("NCR OptiCash (cash management)", r"opticash"),
    ("Gasper (NCR Gasper V5)", r"\bgasper\b"),
    ("Diebold Nixdorf Vynamic", r"vynamic"),
    ("Diebold Agilis", r"\bagilis\b"),
    ("Nautilus Hyosung MoniView", r"moniview"),
    ("Auriga WWS (WinWebServer)", r"\bauriga\b|winwebserver|\bwws\b"),
    ("Phoenix Interactive / Vista ATM", r"vista\s+atm|phoenix\s+interactive"),
    ("ESQ Operations Bridge", r"esq\s+operations\s+bridge|\besq\b\s+bridge"),
    ("INETCO Insight", r"inetco"),
    ("Cennox / fleet services", r"\bcennox\b"),
    # --- payment switches / processors (bank core) ---
    ("Postilion (ACI Postilion)", r"postilion"),
    ("BASE24 (ACI BASE24-eps)", r"base24"),
    ("Compass Plus TranzWare", r"tranzware|compass\s+plus"),
    ("OpenWay WAY4", r"\bway4\b|openway"),
    ("BPC SmartVista", r"smartvista|\bbpc\b"),
    ("Lusis TANGO", r"lusis|\btango\b\s+(switch|payments)"),
    ("CR2 BankWorld", r"bankworld|\bcr2\b"),
    ("FIS (payment processing)", r"\bfis\s+global|fis\s+payment"),
    ("Fiserv", r"\bfiserv\b"),
    ("Jack Henry / Symitar", r"jack\s+henry|symitar"),
    ("Euronet", r"euronet"),
    ("Worldline / Six Payment", r"worldline"),
    ("Clear2Pay / Open Payment", r"clear2pay"),
    ("FICO (fraud / Falcon)", r"\bfalcon\b\s+fraud|\bfico\b\s+falcon"),
)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_INTERNAL_HOST_RE = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:local|lan|corp|internal|intranet|home\.arpa)\b"
    r"|\b(?:intranet|internal|vpn-internal)\.[a-z0-9.-]+\.[a-z]{2,}\b",
    re.IGNORECASE)
_LOOPBACK_RE = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1)(?::\d{2,5})?(?:/[^\s\"'<>]*)?",
    re.IGNORECASE)


def _is_private_ipv4(ip: str) -> bool:
    """True for RFC1918 + loopback + link-local addresses."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        o = [int(p) for p in parts]
    except ValueError:
        return False
    if any(p < 0 or p > 255 for p in o):
        return False
    if o[0] == 10 or o[0] == 127:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    if o[0] == 169 and o[1] == 254:
        return True
    return False


def find_internal_leaks(text: str) -> List[Tuple[str, str]]:
    """Scan page text for internal-network leaks.

    Returns deduped (kind, value) pairs: kind is "private_ip",
    "internal_hostname", or "loopback_url". Pure + fixture-testable.
    """
    out: List[Tuple[str, str]] = []
    seen = set()

    def add(kind: str, value: str) -> None:
        v = value.strip().rstrip(".,;)")
        key = (kind, v.lower())
        if v and key not in seen:
            seen.add(key)
            out.append((kind, v))

    for m in _IPV4_RE.finditer(text or ""):
        if _is_private_ipv4(m.group(0)):
            add("private_ip", m.group(0))
    for m in _INTERNAL_HOST_RE.finditer(text or ""):
        add("internal_hostname", m.group(0))
    for m in _LOOPBACK_RE.finditer(text or ""):
        add("loopback_url", m.group(0))
    return out


def match_fleet_platforms(text: str) -> List[str]:
    """Distinctive fleet-platform fingerprints in page text."""
    low = (text or "").lower()
    return [name for name, pat in FLEET_PLATFORMS
            if re.search(pat, low, re.IGNORECASE)]


class BankSurfacePlugin(Plugin):
    id = "bank_surface"
    label = "Bank Surface Leaks & Fleet Panels"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "financial"
    description = ("Internal IPs / hostnames leaked on branch & ATM "
                   "locator pages, ATM fleet-management panel "
                   "fingerprints. Detection only, read-only GETs.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List[Finding] = []
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no host for this target type")
        base = (target.normalized if target.type == "url"
                else f"https://{domain}/")
        if not base.endswith("/"):
            base += "/"

        pages = await self._gather_pages(base, ctx)
        if not pages:
            res = self._ok(findings,
                           f"could not fetch any page on {domain}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        leak_pages = 0
        for url, text in pages:
            leaks = find_internal_leaks(text)
            if leaks:
                leak_pages += 1
            for kind, value in leaks:
                findings.append(self._f(
                    "financial", f"bank_{kind}_leak",
                    f"Internal network detail leaked on a public page: "
                    f"{value} ({kind.replace('_', ' ')})",
                    source="bank surface scan", source_url=url,
                    confidence=90, passive=True,
                    evidence={
                        "severity": "medium", "leak_kind": kind,
                        "leaked_value": value, "page": url,
                        "remediation": "Remove internal IPs, hostnames "
                        "and loopback URLs from public pages, scripts "
                        "and locator data feeds; publish only public "
                        "endpoints."}))
            for platform in match_fleet_platforms(text):
                is_panel_path = any(p in url for p in PANEL_PATHS)
                findings.append(self._f(
                    "financial", "atm_fleet_panel",
                    (f"ATM fleet-management panel fingerprint exposed "
                     f"on a public path: {platform}"
                     if is_panel_path else
                     f"ATM fleet platform fingerprint on public site: "
                     f"{platform}"),
                    source="bank surface scan", source_url=url,
                    confidence=85 if is_panel_path else 65,
                    passive=True,
                    evidence={
                        "severity": "medium" if is_panel_path else "low",
                        "platform": platform, "page": url,
                        "panel_path": is_panel_path,
                        "remediation": "Fleet-management consoles must "
                        "not be reachable from the public internet; "
                        "restrict to the management network / VPN and "
                        "verify no unauthenticated access is possible."}))

        if not findings:
            findings.append(self._f(
                "financial", "bank_surface_clean",
                f"No internal leaks or fleet-panel fingerprints found "
                f"on {domain} ({len(pages)} public pages read, "
                f"including branch/ATM locator paths)",
                source="bank surface scan", confidence=70, passive=True,
                evidence={"severity": "low",
                          "note": "Clean result is still a result: the "
                                  "checked pages publish no internal "
                                  "addresses and no fleet console."}))
        res = self._ok(findings,
                       f"bank surface scan on {domain}: "
                       f"{len(pages)} pages, {leak_pages} leaking")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def _gather_pages(self, base: str,
                            ctx: Ctx) -> List[Tuple[str, str]]:
        """Homepage + locator + panel paths (bounded, GET only)."""
        urls = [base]
        urls += [urljoin(base, p.lstrip("/")) for p in LOCATOR_PATHS]
        urls += [urljoin(base, p.lstrip("/")) for p in PANEL_PATHS]
        pages = await asyncio.gather(
            *[ctx.fetch_page(u, timeout=TIMEOUT) for u in urls],
            return_exceptions=True)
        out: List[Tuple[str, str]] = []
        for url, page in zip(urls, pages):
            if page is None or isinstance(page, Exception):
                continue
            status = page.get("status_code") or page.get("status") or 0
            text = page.get("text", "") or ""
            if status and status != 200:
                continue
            if text:
                out.append((page.get("url") or url, text))
        return out
