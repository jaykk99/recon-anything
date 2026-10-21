"""The agents' library: a curated registry of well-known public
recon/red-team references, plus a fetch-and-cache layer.

Rules (license respect):
- The registry stores the catalog entry (name, URL, category, kind,
  attribution). Only small openly-licensed derived lists are bundled
  in this repo (see packs.py).
- Everything else is fetched at runtime from its canonical source and
  cached in the resource_cache table WITH its source URL and
  attribution recorded. Content is never rebranded as ours.
- Hunters resolve wordlists/patterns/fingerprints through this module
  (via the data service), falling back to bundled packs when a fetch
  fails or a resource is reference-only (HTML books/guides are catalog
  entries for methodology, not machine-consumed lists).
"""
from __future__ import annotations

import datetime as dt
from typing import Dict, List, Optional

MAX_CACHE_BYTES = 2_000_000  # hard cap per cached resource

# kind: wordlist | patterns | methodology | fingerprints | cheatsheet | intel-feed
REGISTRY: List[Dict] = [
    {"id": "seclists-discovery", "name": "SecLists Discovery wordlists",
     "url": "https://github.com/danielmiessler/SecLists/tree/master/Discovery",
     "category": "wordlists", "kind": "wordlist",
     "used_by": ["subdomain_hunter", "endpoint_hunter", "archive_hunter"],
     "attribution": "SecLists by Daniel Miessler and contributors, MIT License",
     "fetch_url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"},
    {"id": "seclists-subdomains", "name": "SecLists subdomain wordlist (n0kovo top 5000)",
     "url": "https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/n0kovo_subdomains.txt",
     "category": "wordlists", "kind": "wordlist",
     "used_by": ["subdomain_hunter"],
     "attribution": "SecLists by Daniel Miessler and contributors, MIT License",
     "fetch_url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"},
    {"id": "payloadsallthethings", "name": "PayloadsAllTheThings",
     "url": "https://github.com/swisskyrepo/PayloadsAllTheThings",
     "category": "methodology", "kind": "methodology",
     "used_by": ["secret_hunter", "endpoint_hunter", "graph_gap_hunter"],
     "attribution": "PayloadsAllTheThings by swisskyrepo and contributors, MIT License",
     "fetch_url": None},
    {"id": "hacktricks", "name": "HackTricks",
     "url": "https://book.hacktricks.xyz/",
     "category": "methodology", "kind": "methodology",
     "used_by": ["graph_gap_hunter", "cloud_hunter", "port_hunter"],
     "attribution": "HackTricks by Carlos Polop and contributors (hacktricks.xyz)",
     "fetch_url": None},
    {"id": "owasp-wstg", "name": "OWASP Web Security Testing Guide (WSTG)",
     "url": "https://owasp.org/www-project-web-security-testing-guide/",
     "category": "methodology", "kind": "methodology",
     "used_by": ["endpoint_hunter", "fingerprint_hunter", "graph_gap_hunter"],
     "attribution": "OWASP Foundation, CC BY-SA 4.0",
     "fetch_url": None},
    {"id": "owasp-api-checklist", "name": "OWASP API Security checklist",
     "url": "https://github.com/OWASP/API-Security",
     "category": "cheatsheets", "kind": "cheatsheet",
     "used_by": ["endpoint_hunter"],
     "attribution": "OWASP Foundation, CC BY-SA 4.0",
     "fetch_url": None},
    {"id": "assetnote-wordlists", "name": "Assetnote wordlists",
     "url": "https://wordlists.assetnote.io/",
     "category": "wordlists", "kind": "wordlist",
     "used_by": ["endpoint_hunter", "subdomain_hunter"],
     "attribution": "Assetnote (wordlists.assetnote.io)",
     "fetch_url": "https://wordlists-cdn.assetnote.io/data/automated/httparchive_parameters_top_1m_20240102.txt"},
    {"id": "projectdiscovery-datasets", "name": "ProjectDiscovery datasets",
     "url": "https://github.com/projectdiscovery/datasets",
     "category": "fingerprints", "kind": "fingerprints",
     "used_by": ["fingerprint_hunter", "port_hunter"],
     "attribution": "ProjectDiscovery datasets, MIT License",
     "fetch_url": None},
    {"id": "nuclei-templates", "name": "Nuclei template index (reference only)",
     "url": "https://github.com/projectdiscovery/nuclei-templates",
     "category": "patterns", "kind": "patterns",
     "used_by": ["fingerprint_hunter", "secret_hunter"],
     "attribution": "ProjectDiscovery nuclei-templates, MIT License. Reference index only: hunters run this repo's own detection plugins, never external templates.",
     "fetch_url": None},
    {"id": "gitleaks-config", "name": "Gitleaks default rule set",
     "url": "https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml",
     "category": "patterns", "kind": "patterns",
     "used_by": ["secret_hunter", "repo_hunter", "js_miner"],
     "attribution": "Gitleaks by Zachary Rice and contributors, MIT License",
     "fetch_url": "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"},
    {"id": "trufflehog-detectors", "name": "TruffleHog detector reference",
     "url": "https://github.com/trufflesecurity/trufflehog",
     "category": "patterns", "kind": "patterns",
     "used_by": ["secret_hunter"],
     "attribution": "TruffleHog by Truffle Security, AGPL-3.0. Reference only, no code or rules copied.",
     "fetch_url": None},
    {"id": "crtsh", "name": "crt.sh certificate transparency search",
     "url": "https://crt.sh/",
     "category": "intel-feeds", "kind": "intel-feed",
     "used_by": ["cert_hunter", "subdomain_hunter"],
     "attribution": "crt.sh, operated by Sectigo",
     "fetch_url": None},
    {"id": "wayback-cdx", "name": "Internet Archive Wayback CDX API",
     "url": "https://web.archive.org/",
     "category": "intel-feeds", "kind": "intel-feed",
     "used_by": ["archive_hunter", "endpoint_hunter"],
     "attribution": "Internet Archive (web.archive.org)",
     "fetch_url": None},
    {"id": "xposedornot", "name": "XposedOrNot breach API",
     "url": "https://xposedornot.com/",
     "category": "intel-feeds", "kind": "intel-feed",
     "used_by": ["breach_hunter", "email_hunter"],
     "attribution": "XposedOrNot. Breach metadata only, never credential contents.",
     "fetch_url": None},
    {"id": "hacktricks-cloud", "name": "HackTricks Cloud",
     "url": "https://cloud.hacktricks.xyz/",
     "category": "methodology", "kind": "methodology",
     "used_by": ["cloud_hunter", "supplychain_hunter"],
     "attribution": "HackTricks Cloud by Carlos Polop and contributors (cloud.hacktricks.xyz)",
     "fetch_url": None},
    {"id": "portdb-services", "name": "IANA service-name/port-number registry",
     "url": "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml",
     "category": "fingerprints", "kind": "fingerprints",
     "used_by": ["port_hunter"],
     "attribution": "IANA service names and port numbers registry",
     "fetch_url": None},
]

_BY_ID = {r["id"]: r for r in REGISTRY}


def get_resource(resource_id: str) -> Optional[Dict]:
    return _BY_ID.get(resource_id)


def catalog(session=None) -> List[Dict]:
    """Registry entries merged with live cache status (when a session
    is given). Never dumps cached content."""
    cached = {}
    if session is not None:
        try:
            from ..models import ResourceCache
            for row in session.query(ResourceCache).all():
                cached[row.id] = row
        except Exception:
            cached = {}
    out = []
    for r in REGISTRY:
        row = cached.get(r["id"])
        out.append({
            "id": r["id"], "name": r["name"], "url": r["url"],
            "category": r["category"], "kind": r["kind"],
            "used_by": list(r["used_by"]),
            "attribution": r["attribution"],
            "fetchable": bool(r.get("fetch_url")),
            "cached": row is not None,
            "cached_at": (row.fetched_at.isoformat()
                          if row is not None and row.fetched_at else None),
            "cached_bytes": row.size_bytes if row is not None else 0,
        })
    return out


def fetch_resource(session, resource_id: str, http_get=None) -> Dict:
    """Fetch a resource's content from its canonical source and cache
    it with source URL + attribution. Reference-only resources (no
    fetch_url) are never fetched. Returns a status dict.

    http_get: injectable for tests; defaults to httpx.get.
    """
    res = _BY_ID.get(resource_id)
    if res is None:
        return {"ok": False, "error": "unknown resource"}
    if not res.get("fetch_url"):
        return {"ok": False, "error": "reference-only resource, not fetchable"}
    if http_get is None:
        import httpx
        def http_get(url):  # noqa: F811
            return httpx.get(url, timeout=30, follow_redirects=True,
                             headers={"User-Agent": "ReconAnything/1.0"})
    try:
        resp = http_get(res["fetch_url"])
        if getattr(resp, "status_code", 0) != 200:
            return {"ok": False,
                    "error": f"source returned HTTP {resp.status_code}"}
        content = resp.text[:MAX_CACHE_BYTES]
    except Exception as e:
        return {"ok": False, "error": f"fetch failed: {str(e)[:150]}"}
    from ..models import ResourceCache
    row = session.query(ResourceCache).filter_by(id=resource_id).first()
    if row is None:
        row = ResourceCache(id=resource_id)
        session.add(row)
    row.source_url = res["fetch_url"]
    row.attribution = res["attribution"]
    row.content = content
    row.size_bytes = len(content.encode("utf-8", "replace"))
    row.fetched_at = dt.datetime.now(dt.timezone.utc)
    session.commit()
    return {"ok": True, "id": resource_id, "bytes": row.size_bytes,
            "source_url": row.source_url, "attribution": row.attribution}


def cached_lines(session, resource_id: str) -> List[str]:
    """Cached content of a resource as clean lines (wordlist use)."""
    from ..models import ResourceCache
    row = session.query(ResourceCache).filter_by(id=resource_id).first()
    if row is None or not row.content:
        return []
    return [ln.strip() for ln in row.content.splitlines()
            if ln.strip() and not ln.strip().startswith("#")]
