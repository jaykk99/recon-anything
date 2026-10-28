"""ATM web-surface detectors (fin_* pack, ATM family).

Eight detection-only checks aimed at the web surface around ATM
fleets: monitoring dashboards, per-terminal status APIs, software
update distribution points, locator feeds carrying hardware data,
remote-access gateways, electronic-journal/receipt data, terminal
switch configuration files, and bank-run network status pages.
Read-only GETs only. Nothing here touches an ATM device, submits a
credential, or interacts with a terminal session.
"""
from __future__ import annotations

import re
from typing import Dict, List

from .bankpack_util import (FinPlugin, fetch_paths, find_internal_leaks,
                            parse_json_text)
from .base import Ctx, PluginResult, Target

# ---------------------------------------------------------------------------
# 9. fin_atm_monitor - ATM monitoring dashboards (beyond fleet panels)
# ---------------------------------------------------------------------------

MONITOR_PATHS = (
    "/atm-monitor", "/atm-status", "/atmops", "/terminal-monitor",
    "/monitoring/atms", "/atm/dashboard", "/atm-monitoring",
    "/fleet-status",
)
MONITOR_FINGERPRINTS = (
    ("Hyosung MoniView", r"moniview"),
    ("NCR Vision", r"ncr\s+vision"),
    ("KAL K-Monitor", r"k-?monitor"),
    ("Diebold ProView", r"\bproview\b"),
    ("OptiCash", r"opticash"),
    ("ATM Web Viewer", r"atm\s+web\s+viewer"),
    ("Terminal Status Dashboard", r"terminal\s+status\s+dashboard"),
)


def match_atm_monitor(text: str) -> List[str]:
    low = (text or "").lower()
    return [name for name, pat in MONITOR_FINGERPRINTS
            if re.search(pat, low)]


class FinAtmMonitorPlugin(FinPlugin):
    id = "fin_atm_monitor"
    label = "ATM Monitoring Dashboard Exposure"
    description = ("ATM monitoring dashboards (MoniView, NCR Vision, "
                   "K-Monitor, ProView...) reachable on public paths. "
                   "Fingerprint only; no interaction with the console.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, MONITOR_PATHS):
            hits = match_atm_monitor(text)
            if hits:
                findings.append(self.fin_finding(
                    "fin_atm_monitor_dashboard",
                    f"ATM monitoring dashboard exposed at {url}: "
                    f"{', '.join(hits)}",
                    url, "high",
                    "Monitoring consoles reveal fleet state and are an "
                    "attack beachhead; restrict them to the management "
                    "network / VPN with MFA.",
                    dashboards=hits))
        if not findings:
            return self._ok([], f"no ATM dashboards found on {domain}")
        return self._ok(findings,
                        f"{len(findings)} ATM dashboard page(s) on {domain}")


# ---------------------------------------------------------------------------
# 10. fin_atm_status_api - per-terminal status APIs with sensitive fields
# ---------------------------------------------------------------------------

STATUS_API_PATHS = (
    "/api/atm-status", "/api/terminals", "/api/atms/status",
    "/atm/api/status", "/api/v1/terminals", "/api/fleet/status",
)
_TERMINAL_FIELD_RE = re.compile(
    r"(terminal_?ip|internal_?ip|ip_?address|firmware|software_?version|"
    r"cassette|cash_?level|denomination|technician|error_?code|"
    r"device_?serial)", re.IGNORECASE)


def analyze_terminal_payload(data) -> List[Dict]:
    """Sensitive per-terminal fields in a status API payload."""
    out: List[Dict] = []
    items = []
    if isinstance(data, list):
        items = [d for d in data if isinstance(d, dict)]
    elif isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                items = [d for d in v if isinstance(d, dict)]
                break
        if not items:
            items = [data]
    seen = set()
    for item in items[:50]:
        for k, v in item.items():
            if _TERMINAL_FIELD_RE.search(str(k)) and v not in (None, ""):
                key = str(k)
                if key not in seen:
                    seen.add(key)
                    out.append({"field": key, "value": str(v)[:60]})
    return out


class FinAtmStatusApiPlugin(FinPlugin):
    id = "fin_atm_status_api"
    label = "ATM Status API Sensitive Fields"
    description = ("Public APIs returning per-terminal ATM status with "
                   "internal IPs, firmware versions, cassette/cash "
                   "levels or technician data.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, STATUS_API_PATHS):
            for issue in analyze_terminal_payload(parse_json_text(text)):
                findings.append(self.fin_finding(
                    "fin_atm_status_field",
                    f"ATM status API {url} exposes per-terminal field "
                    f"{issue['field']}: {issue['value']}",
                    url, "high",
                    "Per-terminal IPs, firmware and cash levels are "
                    "targeting data for ATM attacks; status APIs must "
                    "require authentication and return public fields "
                    "only (up/down) to anonymous callers.",
                    field=issue["field"]))
        if not findings:
            return self._ok([], f"ATM status APIs clean on {domain}")
        return self._ok(findings,
                        f"{len(findings)} terminal field(s) on {domain}")


# ---------------------------------------------------------------------------
# 11. fin_atm_updates - ATM software update / config distribution points
# ---------------------------------------------------------------------------

UPDATE_PATHS = (
    "/atm-updates", "/updates/atms", "/swdist", "/terminal-updates",
    "/atm/software", "/updates/manifest.json", "/atm-updates/manifest.json",
    "/software-distribution",
)
_PACKAGE_RE = re.compile(
    r"[\w.\-/]+\.(?:pkg|msi|zip|tar\.gz|bin|img)\b", re.IGNORECASE)
_VERSION_RE = re.compile(r"\b(?:version|ver|release)\s*[:#]?\s*v?\d+\.\d+"
                         r"(?:\.\d+)?", re.IGNORECASE)


def analyze_update_surface(text: str) -> List[Dict]:
    """Software packages + versions in an update manifest/listing."""
    out: List[Dict] = []
    pkgs = sorted(set(_PACKAGE_RE.findall(text or "")))[:10]
    vers = sorted(set(_VERSION_RE.findall(text or "")))[:5]
    if pkgs:
        out.append({"issue": "package_list", "value": ", ".join(pkgs)})
    if pkgs and vers:
        out.append({"issue": "package_versions", "value": ", ".join(vers)})
    return out


class FinAtmUpdatesPlugin(FinPlugin):
    id = "fin_atm_updates"
    label = "ATM Software Update Exposure"
    description = ("ATM software-update / distribution endpoints "
                   "listing terminal packages and versions - a map of "
                   "exactly what unpatched software the fleet runs.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, UPDATE_PATHS):
            for issue in analyze_update_surface(text):
                findings.append(self.fin_finding(
                    "fin_atm_update_surface",
                    f"ATM software distribution at {url}: "
                    f"{issue['value']}",
                    url, "high",
                    "Update distribution must be authenticated and "
                    "signed; a public package/version listing tells "
                    "attackers which terminal CVEs apply fleet-wide.",
                    issue=issue["issue"]))
        if not findings:
            return self._ok([], f"no ATM update surfaces on {domain}")
        return self._ok(findings,
                        f"{len(findings)} update surface(s) on {domain}")


# ---------------------------------------------------------------------------
# 12. fin_atm_locator_feed - ATM locator feeds with hardware data
# ---------------------------------------------------------------------------

ATM_FEED_PATHS = (
    "/atm-locator.json", "/api/atm-locator", "/feeds/atms.json",
    "/data/atms.json", "/atms.json", "/api/atms",
)
_HARDWARE_FIELD_RE = re.compile(
    r"(model|firmware|hardware|asset_?tag|asset_?id|internal_?id|"
    r"install|vendor|service_?provider|serial)", re.IGNORECASE)


def analyze_atm_feed(data) -> List[Dict]:
    """Hardware/asset fields in an ATM locator feed payload."""
    out: List[Dict] = []
    items = []
    if isinstance(data, list):
        items = [d for d in data if isinstance(d, dict)]
    elif isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                items = [d for d in v if isinstance(d, dict)]
                break
        if not items:
            items = [data]
    seen = set()
    for item in items[:50]:
        for k, v in item.items():
            if _HARDWARE_FIELD_RE.search(str(k)) and v not in (None, ""):
                key = str(k)
                if key not in seen:
                    seen.add(key)
                    out.append({"field": key, "value": str(v)[:60]})
    return out


class FinAtmLocatorFeedPlugin(FinPlugin):
    id = "fin_atm_locator_feed"
    label = "ATM Locator Feed Hardware Data"
    description = ("ATM locator feeds that go beyond location: "
                   "terminal hardware models, firmware versions, "
                   "internal asset tags and service vendors.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, ATM_FEED_PATHS):
            for issue in analyze_atm_feed(parse_json_text(text)):
                findings.append(self.fin_finding(
                    "fin_atm_feed_field",
                    f"ATM locator feed {url} exposes hardware field "
                    f"{issue['field']}: {issue['value']}",
                    url, "medium",
                    "Locator feeds should carry location and hours "
                    "only; hardware models + firmware versions let "
                    "attackers pick terminal-specific exploits.",
                    field=issue["field"]))
        if not findings:
            return self._ok([], f"ATM locator feeds clean on {domain}")
        return self._ok(findings,
                        f"{len(findings)} feed field(s) on {domain}")


# ---------------------------------------------------------------------------
# 13. fin_atm_remote_access - remote-access gateways on the ATM surface
# ---------------------------------------------------------------------------

REMOTE_PATHS = (
    "/guacamole", "/remote", "/remote-access", "/webrdp", "/rdp",
    "/atm/remote", "/remote-desktop", "/support-access",
)
REMOTE_FINGERPRINTS = (
    ("Apache Guacamole", r"guacamole"),
    ("Thinfinity Remote Desktop", r"thinfinity"),
    ("Ericom AccessNow", r"ericom|accessnow"),
    ("WebRDP", r"webrdp"),
    ("Remote Desktop Gateway", r"remote\s+desktop\s+(gateway|web)"),
    ("Splashtop Gateway", r"splashtop"),
)


def match_remote_access(text: str) -> List[str]:
    low = (text or "").lower()
    return [name for name, pat in REMOTE_FINGERPRINTS
            if re.search(pat, low)]


class FinAtmRemoteAccessPlugin(FinPlugin):
    id = "fin_atm_remote_access"
    label = "ATM Remote-Access Gateway Exposure"
    description = ("Browser remote-access gateways (Guacamole, "
                   "Thinfinity, Ericom...) reachable on the bank/ATM "
                   "web surface. Fingerprint only; no session is "
                   "started and no credential is tried.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, REMOTE_PATHS):
            hits = match_remote_access(text)
            if hits:
                findings.append(self.fin_finding(
                    "fin_remote_access_gateway",
                    f"Remote-access gateway exposed at {url}: "
                    f"{', '.join(hits)}",
                    url, "high",
                    "Remote-access gateways must sit behind VPN + MFA "
                    "and never be enumerable from the public internet; "
                    "they are the front door to terminal sessions.",
                    gateways=hits))
        if not findings:
            return self._ok([], f"no remote-access gateways on {domain}")
        return self._ok(findings,
                        f"{len(findings)} gateway page(s) on {domain}")


# ---------------------------------------------------------------------------
# 14. fin_atm_journal - electronic journal / receipt data exposure
# ---------------------------------------------------------------------------

JOURNAL_PATHS = (
    "/ejournal", "/ej", "/journal", "/atm/journal", "/receipts",
    "/ejournal/view", "/transactions/journal",
)
_PAN_FRAGMENT_RE = re.compile(r"\b\d{6}\*+\d{4}\b|\*{4,}\d{4}\b")
_JOURNAL_MARKER_RE = re.compile(
    r"(electronic\s+journal|ejournal|dispense|card\s+capture|"
    r"transaction\s+journal|resp(?:onse)?\s*code)", re.IGNORECASE)
_AMOUNT_RE = re.compile(r"\$\s?\d{1,3}(?:,\d{3})*\.\d{2}")


def analyze_journal_text(text: str) -> List[Dict]:
    """Journal records: needs journal markers AND transaction data
    (PAN fragments or amounts) - either alone is not enough."""
    out: List[Dict] = []
    if not text or not _JOURNAL_MARKER_RE.search(text):
        return out
    pans = _PAN_FRAGMENT_RE.findall(text)
    amounts = _AMOUNT_RE.findall(text)
    if pans:
        out.append({"issue": "pan_fragments",
                    "value": f"{len(pans)} masked PAN fragment(s), "
                             f"e.g. {pans[0]}"})
    if amounts:
        out.append({"issue": "amounts",
                    "value": f"{len(amounts)} amount(s), "
                             f"e.g. {amounts[0]}"})
    return out


class FinAtmJournalPlugin(FinPlugin):
    id = "fin_atm_journal"
    label = "ATM Journal Data Exposure"
    description = ("Electronic-journal / receipt data served on the "
                   "web surface: transaction records with masked PAN "
                   "fragments, amounts and response codes. Fragments "
                   "are reported as found (already masked at source).")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target for this check")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, JOURNAL_PATHS):
            for issue in analyze_journal_text(text):
                findings.append(self.fin_finding(
                    "fin_atm_journal_data",
                    f"ATM journal data at {url}: {issue['value']}",
                    url, "high",
                    "Electronic journals are PCI-scoped data; they "
                    "must never be served from a public web path. "
                    "Remove, authenticate, and audit access.",
                    issue=issue["issue"]))
        if not findings:
            return self._ok([], f"no ATM journal data on {domain}")
        return self._ok(findings,
                        f"{len(findings)} journal exposure(s) on {domain}")


# ---------------------------------------------------------------------------
# 15. fin_atm_switch_config - terminal / switch configuration files
# ---------------------------------------------------------------------------

SWITCH_CONFIG_PATHS = (
    "/config/terminal.xml", "/atm/config.xml", "/terminal-config.xml",
    "/config/atm.xml", "/xfs/config.xml", "/config/switch.xml",
    "/atm-config.xml",
)
_HOST_ELEM_RE = re.compile(
    r"<(switchhost|hostname|switch|host|server|node|endpoint)"
    r"(?:\s[^>]*)?>\s*([^<\s]{3,80})\s*</",
    re.IGNORECASE)
_HOST_ATTR_RE = re.compile(
    r"(?:switch|host|server)(?:host|addr|ip|url)?\s*=\s*[\"']([^\"']{3,80})"
    r"[\"']", re.IGNORECASE)


def analyze_switch_config(text: str) -> List[Dict]:
    """Switch/host endpoints inside a terminal config file."""
    out: List[Dict] = []
    seen = set()
    if not text:
        return out
    for m in _HOST_ELEM_RE.finditer(text):
        v = m.group(2)
        if v not in seen:
            seen.add(v)
            out.append({"field": m.group(1).lower(), "value": v})
    for m in _HOST_ATTR_RE.finditer(text):
        v = m.group(1)
        if v not in seen:
            seen.add(v)
            out.append({"field": "host_attribute", "value": v})
    for kind, leak in find_internal_leaks(text):
        if leak not in seen:
            seen.add(leak)
            out.append({"field": kind, "value": leak})
    return out[:10]


class FinAtmSwitchConfigPlugin(FinPlugin):
    id = "fin_atm_switch_config"
    label = "ATM Switch Config Exposure"
    description = ("Terminal/switch configuration files served "
                   "publicly, disclosing transaction-switch hosts, "
                   "ports and internal addresses.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base,
                                               SWITCH_CONFIG_PATHS):
            for issue in analyze_switch_config(text):
                findings.append(self.fin_finding(
                    "fin_atm_switch_config",
                    f"ATM config at {url} discloses {issue['field']}: "
                    f"{issue['value']}",
                    url, "high",
                    "Terminal configuration belongs on the management "
                    "network only; switch endpoints in public files "
                    "give attackers the fleet's core targets.",
                    field=issue["field"]))
        if not findings:
            return self._ok([], f"no ATM switch configs on {domain}")
        return self._ok(findings,
                        f"{len(findings)} switch config value(s) on {domain}")


# ---------------------------------------------------------------------------
# 16. fin_atm_network_status - bank-run ATM network status pages
# ---------------------------------------------------------------------------

NETWORK_STATUS_PATHS = (
    "/network-status", "/atm-network", "/status/atm",
    "/network/status", "/atm-network-status",
)
_INTERNAL_SYSTEM_RE = re.compile(
    r"\b[A-Z]{2,5}-(?:PROD|CORE|SW|ATM|NET)-\d+\b")
_NETWORK_MARKER_RE = re.compile(
    r"(terminal\s+network|switch\s+status|interchange|terminals?\s+"
    r"online|network\s+status)", re.IGNORECASE)
_TICKET_RE = re.compile(r"\bINC\d{5,}\b")


def analyze_network_status(text: str) -> List[Dict]:
    """Internal system names / ticket IDs on a network status page.

    Fires only when the page is actually about the terminal network
    (marker present) and leaks internal naming.
    """
    out: List[Dict] = []
    if not text or not _NETWORK_MARKER_RE.search(text):
        return out
    for name in sorted(set(_INTERNAL_SYSTEM_RE.findall(text)))[:5]:
        out.append({"issue": "internal_system_name", "value": name})
    for tid in sorted(set(_TICKET_RE.findall(text)))[:3]:
        out.append({"issue": "internal_ticket_id", "value": tid})
    return out


class FinAtmNetworkStatusPlugin(FinPlugin):
    id = "fin_atm_network_status"
    label = "ATM Network Status Internals"
    description = ("Bank-published ATM network status pages that name "
                   "internal switch/core systems or internal incident "
                   "ticket IDs.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base,
                                               NETWORK_STATUS_PATHS):
            for issue in analyze_network_status(text):
                findings.append(self.fin_finding(
                    "fin_atm_network_internals",
                    f"ATM network status page {url} names internal "
                    f"{issue['issue'].replace('_', ' ')}: {issue['value']}",
                    url, "medium",
                    "Public status pages should use customer-facing "
                    "service names; internal hostnames and ticket IDs "
                    "map the estate for attackers.",
                    issue=issue["issue"]))
        if not findings:
            return self._ok([], f"no network-status internals on {domain}")
        return self._ok(findings,
                        f"{len(findings)} internal name(s) on {domain}")
