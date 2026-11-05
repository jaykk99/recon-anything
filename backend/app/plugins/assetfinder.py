"""Assetfinder-style fast subdomain discovery (Tier-1 OSINT).

Native re-implementation of the assetfinder idea: pull hostnames for
a domain from certificate transparency (crt.sh) and the Common Crawl
URL index plus the Wayback CDX index, dedupe against the discovery
bus, and filter out names that only exist because of a wildcard DNS
record (a random-label probe establishes the wildcard address set;
names resolving solely to it are reported as wildcard-covered, not
as real assets). Keyless and read-only; DNS checks go through DNS-
over-HTTPS (dns.google) so no raw sockets are needed.
"""
from __future__ import annotations

import json
import secrets
import time
from typing import Dict, List, Optional, Set
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, \
    safe_json_list


def clean_subdomain(raw: str, domain: str) -> str:
    s = (raw or "").strip().lower()
    s = s.lstrip("*.")
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/")[0].split(":")[0].strip(".")
    if not s or s == domain or not s.endswith("." + domain):
        return ""
    if "*" in s or " " in s or ".." in s:
        return ""
    return s


def parse_cc_index(text: str) -> List[str]:
    """Common Crawl index NDJSON -> hostnames from each row's url."""
    out: List[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except Exception:
            continue
        url = str(row.get("url", "")) if isinstance(row, dict) else ""
        host = url.split("://", 1)[-1].split("/")[0].split(":")[0]
        if host:
            out.append(host)
    return out


async def resolve_a(ctx: Ctx, name: str) -> List[str]:
    """A records for name via keyless DoH (dns.google). [] on failure."""
    try:
        resp = await fetch(
            ctx.http, ctx.limiter, "GET",
            f"https://dns.google/resolve?name={quote(name)}&type=A",
            timeout=20, max_retries=1,
            headers={"accept": "application/dns-json"})
        if resp.status_code != 200:
            return []
        data = resp.json()
        return [str(a.get("data")) for a in data.get("Answer", [])
                if isinstance(a, dict) and a.get("type") == 1
                and a.get("data")]
    except Exception:
        return []


class AssetfinderPlugin(Plugin):
    timeout_s = 90
    id = "assetfinder"
    label = "Assetfinder Subdomain Discovery"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("Fast subdomain discovery via certificate "
                   "transparency + Common Crawl / Wayback indexes, "
                   "with dedupe and wildcard-DNS filtering.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        candidates: Dict[str, str] = {}  # sub -> first source

        # crt.sh (certificate transparency)
        try:
            resp = await fetch(ctx.http, ctx.limiter, "GET",
                               f"https://crt.sh/?q=%25.{quote(domain)}"
                               f"&output=json", timeout=20, max_retries=1)
            if resp.status_code == 200:
                for row in safe_json_list(resp):
                    for field in ("name_value", "common_name"):
                        for name in str(row.get(field) or "").splitlines():
                            sub = clean_subdomain(name, domain)
                            if sub:
                                candidates.setdefault(sub, "crt.sh")
        except Exception:
            pass

        # Common Crawl URL index
        try:
            resp = await fetch(
                ctx.http, ctx.limiter, "GET",
                f"https://index.commoncrawl.org/collinfo.json",
                timeout=15, max_retries=1)
            index = None
            if resp.status_code == 200:
                rows = safe_json_list(resp)
                if rows:
                    index = str(rows[0].get("cdx-index") or "") or None
            if index:
                resp = await fetch(
                    ctx.http, ctx.limiter, "GET",
                    f"{index}?url=*.{quote(domain)}&output=json&limit=2000",
                    timeout=20, max_retries=1)
                if resp.status_code == 200:
                    for host in parse_cc_index(resp.text):
                        sub = clean_subdomain(host, domain)
                        if sub:
                            candidates.setdefault(sub, "Common Crawl")
        except Exception:
            pass

        # Wayback CDX hostnames
        try:
            resp = await fetch(
                ctx.http, ctx.limiter, "GET",
                f"https://web.archive.org/cdx/search/cdx?url=*."
                f"{quote(domain)}&output=json&fl=original&collapse=urlkey"
                f"&limit=2000", timeout=20, max_retries=1)
            if resp.status_code == 200:
                try:
                    rows = resp.json()
                except Exception:
                    rows = []
                if isinstance(rows, list):
                    for row in rows:
                        url = ""
                        if isinstance(row, list) and row:
                            url = str(row[-1])
                        elif isinstance(row, dict):
                            url = str(row.get("original", ""))
                        host = url.split("://", 1)[-1].split("/")[0]
                        sub = clean_subdomain(host.split(":")[0], domain)
                        if sub:
                            candidates.setdefault(sub, "Wayback CDX")
        except Exception:
            pass

        seen: Set[str] = set(ctx.consume("subdomains"))
        fresh = sorted(s for s in candidates if s not in seen)

        # Wildcard probe: a random label that should not exist.
        wildcard_ips: Set[str] = set()
        if fresh:
            probe = f"af-{secrets.token_hex(5)}.{domain}"
            wildcard_ips = set(await resolve_a(ctx, probe))
        if wildcard_ips:
            findings.append(self._f(
                "dns", "wildcard_dns",
                f"*.{domain} resolves to {', '.join(sorted(wildcard_ips))}",
                source="assetfinder/DoH", confidence=70, passive=True,
                evidence={"severity": "low",
                          "remediation": "Review the wildcard DNS record; "
                                         "it can mask dangling subdomains."}))

        kept = 0
        wildcarded = 0
        for sub in fresh:
            if wildcard_ips:
                ips = set(await resolve_a(ctx, sub))
                if ips and ips <= wildcard_ips:
                    wildcarded += 1
                    continue
            kept += 1
            ctx.publish("subdomains", sub)
            findings.append(self._f(
                "dns", "subdomain", sub,
                source=f"assetfinder/{candidates[sub]}",
                confidence=75, passive=True))
            self._checkpoint(findings)
        res = self._ok(findings, f"{kept} subdomains kept"
                                 + (f", {wildcarded} wildcard-only filtered"
                                    if wildcarded else ""))
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
