"""CISA Known Exploited Vulnerabilities (KEV) flagging.

Detection only: a CVE that appears in CISA's public KEV catalog is
known to be actively exploited in the wild, so its finding gets a
badge and ranks first (see prioritizer.priority_key). A CVE that is
not in the catalog is never invented as KEV: on any catalog fetch
failure the lookup degrades to kev=False / unknown, never a fake
match.

Live source (keyless, public JSON):
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    Shape: {"vulnerabilities": [{"cveID": "CVE-...", "vendorProject": ...,
    "product": ..., "dateAdded": "YYYY-MM-DD", "dueDate": ...,
    "shortDescription": ...}, ...]}

Offline fallback: KEV_FIXTURE below is a small snapshot of real KEV
entries (each listed here is genuinely in the CISA catalog; the
snapshot exists so unit tests and offline scans still badge the
best-known exploited CVEs instead of failing). The live catalog,
when fetchable, always wins over the fixture.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

KEV_LABEL = "CISA KEV - actively exploited"

# Real KEV entries (snapshot fallback only; live catalog wins).
# dateAdded values are the catalog's own dates for these CVEs.
KEV_FIXTURE: List[Dict[str, str]] = [
    {"cveID": "CVE-2021-41773", "vendorProject": "Apache",
     "product": "HTTP Server", "dateAdded": "2021-10-06",
     "dueDate": "2021-10-20",
     "shortDescription": "Apache HTTP Server path traversal and file disclosure / RCE."},
    {"cveID": "CVE-2021-44228", "vendorProject": "Apache",
     "product": "Log4j", "dateAdded": "2021-12-10",
     "dueDate": "2021-12-24",
     "shortDescription": "Apache Log4j2 remote code execution (Log4Shell)."},
    {"cveID": "CVE-2024-3400", "vendorProject": "Palo Alto Networks",
     "product": "PAN-OS", "dateAdded": "2024-04-12",
     "dueDate": "2024-05-03",
     "shortDescription": "PAN-OS GlobalProtect command injection."},
    {"cveID": "CVE-2023-4966", "vendorProject": "Citrix",
     "product": "NetScaler ADC and NetScaler Gateway", "dateAdded": "2023-10-18",
     "dueDate": "2023-11-08",
     "shortDescription": "Citrix NetScaler buffer overflow (Citrix Bleed session hijacking)."},
    {"cveID": "CVE-2024-21887", "vendorProject": "Ivanti",
     "product": "Connect Secure", "dateAdded": "2024-01-11",
     "dueDate": "2024-01-31",
     "shortDescription": "Ivanti Connect Secure command injection."},
]

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def extract_cves(text: str) -> List[str]:
    """All CVE ids in a string, uppercased, order-preserving, deduped."""
    seen: List[str] = []
    for m in _CVE_RE.finditer(text or ""):
        cve = m.group(0).upper()
        if cve not in seen:
            seen.append(cve)
    return seen


def parse_kev_catalog(data: Any) -> Dict[str, Dict[str, str]]:
    """Parse CISA KEV JSON into {CVE: entry}. Bad shapes -> {}."""
    out: Dict[str, Dict[str, str]] = {}
    if not isinstance(data, dict):
        return out
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list):
        return out
    for v in vulns:
        if not isinstance(v, dict):
            continue
        cve = str(v.get("cveID") or "").strip().upper()
        if not _CVE_RE.fullmatch(cve):
            continue
        out[cve] = {
            "cve": cve,
            "vendor": str(v.get("vendorProject") or ""),
            "product": str(v.get("product") or ""),
            "date_added": str(v.get("dateAdded") or ""),
            "due_date": str(v.get("dueDate") or ""),
            "description": str(v.get("shortDescription") or ""),
        }
    return out


def fixture_catalog() -> Dict[str, Dict[str, str]]:
    """The bundled snapshot, as a catalog dict."""
    return parse_kev_catalog({"vulnerabilities": KEV_FIXTURE})


async def load_catalog(ctx: Any) -> Dict[str, Dict[str, str]]:
    """Live KEV catalog via the run cache, fixture on any failure.

    Never raises, never returns a fake match: on fetch/parse failure
    the caller gets the fixture snapshot (real entries only). A CVE
    absent from both live and fixture catalogs is simply not KEV.
    """
    try:
        from .ratelimit import fetch as _fetch

        async def _live() -> Any:
            try:
                resp = await _fetch(ctx.http, ctx.limiter, "GET",
                                    KEV_CATALOG_URL, timeout=15)
                if resp.status_code != 200:
                    return None
                return resp.json()
            except Exception:
                return None

        data, _hit = await ctx.cache.cached("kev", "catalog", _live)
        catalog = parse_kev_catalog(data)
        if catalog:
            return catalog
    except Exception:
        pass
    return fixture_catalog()


def kev_entry_for(cve: str, catalog: Dict[str, Dict[str, str]]) -> Optional[Dict[str, str]]:
    """Catalog entry for one CVE id, or None (never invented)."""
    if not cve:
        return None
    return catalog.get(cve.strip().upper())


def is_kev(cve: str, catalog: Dict[str, Dict[str, str]]) -> bool:
    return kev_entry_for(cve, catalog) is not None


def annotate_finding(finding: Any, catalog: Dict[str, Dict[str, str]]) -> bool:
    """Badge a finding in place if any of its CVEs is in the catalog.

    Works on Finding dataclasses and on dict-shaped findings. Returns
    True when badged. Non-KEV findings get kev=False so downstream
    code can distinguish 'checked, not KEV' from 'never checked'
    (kev=None means never checked).
    """
    ev = None
    value = ""
    if isinstance(finding, dict):
        ev = finding.get("evidence")
        if not isinstance(ev, dict):
            ev = {}
            finding["evidence"] = ev
        value = str(finding.get("value") or "")
        cves = extract_cves(str(finding.get("evidence", {}).get("cve") or "") + " " + value)
    else:
        ev = getattr(finding, "evidence", None)
        if not isinstance(ev, dict):
            ev = {}
            try:
                finding.evidence = ev
            except Exception:
                return False
        value = str(getattr(finding, "value", "") or "")
        cves = extract_cves(str(ev.get("cve") or "") + " " + value)
    for cve in cves:
        entry = kev_entry_for(cve, catalog)
        if entry:
            ev["kev"] = True
            ev["kev_label"] = KEV_LABEL
            ev["kev_cve"] = cve
            ev["kev_date_added"] = entry["date_added"]
            ev["kev_product"] = entry["product"]
            # Visible badge in the value, once only.
            if KEV_LABEL not in value:
                try:
                    if isinstance(finding, dict):
                        finding["value"] = value + f" [{KEV_LABEL}]"
                    else:
                        finding.value = value + f" [{KEV_LABEL}]"
                except Exception:
                    pass
            return True
    ev["kev"] = False
    return False


def annotate_findings(findings: List[Any], catalog: Dict[str, Dict[str, str]]) -> List[Any]:
    """Badge every finding in a list; returns the same list."""
    for f in findings:
        try:
            annotate_finding(f, catalog)
        except Exception:
            continue
    return findings
