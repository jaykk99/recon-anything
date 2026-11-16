"""CISA Known Exploited Vulnerabilities (KEV) lookup.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
Feed (keyless, no sign-in): the catalog JSON. A CVE that appears here is
ground truth for "actively exploited in the wild" - the strongest
exploitability signal a triage pipeline can get without a key.

Design: stdlib only, fail-open everywhere. The KEV snapshot ships in the
repo at backend/app/data/kev.json so lookups work offline. refresh()
re-downloads it; a failed refresh keeps the old snapshot. Nothing in here
raises to callers: a missing or malformed cache behaves as "no KEV data",
never as an error that could break a scan.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

KEV_FEED_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json")

DEFAULT_CACHE = Path(__file__).resolve().parent / "data" / "kev.json"

_CACHE: Optional[Dict[str, Dict[str, Any]]] = None
_CACHE_MTIME: float = 0.0


def _parse(feed: Any) -> Dict[str, Dict[str, Any]]:
    """Feed JSON -> {CVE-ID: entry}. Malformed input yields {}."""
    out: Dict[str, Dict[str, Any]] = {}
    if not isinstance(feed, dict):
        return out
    vulns = feed.get("vulnerabilities")
    if not isinstance(vulns, list):
        return out
    for v in vulns:
        if not isinstance(v, dict):
            continue
        cve = str(v.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        out[cve] = {
            "cve": cve,
            "vendor": str(v.get("vendorProject") or ""),
            "product": str(v.get("product") or ""),
            "vulnerability_name": str(v.get("vulnerabilityName") or ""),
            "date_added": str(v.get("dateAdded") or ""),
            "due_date": str(v.get("dueDate") or ""),
            "description": str(v.get("shortDescription") or ""),
            "required_action": str(v.get("requiredAction") or ""),
        }
    return out


def load_index(cache_path: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Load the KEV index from the local snapshot (cached in-process).

    Returns {} when the snapshot is missing or unreadable.
    """
    global _CACHE, _CACHE_MTIME
    path = Path(cache_path) if cache_path else DEFAULT_CACHE
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    if _CACHE is not None and mtime == _CACHE_MTIME:
        return _CACHE
    try:
        with open(path, "r", encoding="utf-8") as fh:
            feed = json.load(fh)
    except Exception:
        return {}
    _CACHE = _parse(feed)
    _CACHE_MTIME = mtime
    return _CACHE


def kev_entry(cve_id: str, cache_path: Optional[str] = None
              ) -> Optional[Dict[str, Any]]:
    """KEV entry for a CVE id, or None when it is not listed / no data."""
    if not cve_id:
        return None
    return load_index(cache_path).get(str(cve_id).strip().upper())


def is_exploited(cve_id: str, cache_path: Optional[str] = None) -> bool:
    """True when the CVE is in the CISA KEV catalog (actively exploited)."""
    return kev_entry(cve_id, cache_path) is not None


def refresh(cache_path: Optional[str] = None, timeout: int = 30) -> int:
    """Re-download the KEV feed and rewrite the local snapshot.

    Returns the number of entries stored. Raises on network failure so
    the caller can decide; the old snapshot is left untouched on failure
    (download to temp, then atomic replace).
    """
    path = Path(cache_path) if cache_path else DEFAULT_CACHE
    req = urllib.request.Request(KEV_FEED_URL, headers={
        "User-Agent": "ReconAnything-KEV-refresh/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
    feed = json.loads(raw.decode("utf-8"))
    index = _parse(feed)
    if not index:
        raise ValueError("KEV feed parsed to zero entries, refusing refresh")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(feed, fh)
    os.replace(tmp, path)
    global _CACHE, _CACHE_MTIME
    _CACHE = index
    try:
        _CACHE_MTIME = os.path.getmtime(path)
    except OSError:
        _CACHE_MTIME = time.time()
    return len(index)
