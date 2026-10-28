"""Passive subdomain sources, round 2 (detection only).

The main subdomains plugin already covers crt.sh, AlienVault OTX,
urlscan.io and ThreatCrowd. This plugin wires in three more keyless,
public, passive sources and merges them with strict dedup and a
same-target filter:

  * CertSpotter (api.certspotter.com) - certificate-transparency
    issuances for the domain, subdomains included.
  * Wayback CDX (web.archive.org) - archived URLs under *.domain.
  * Bufferover (dns.bufferover.run) - public passive-DNS index.

No DNS brute force, no port scanning, no requests to any host other
than the three public indexes and never to the target itself beyond
what these indexes already publish. Every source is fetched through
the shared rate limiter, each with a short timeout, and a dead source
degrades to a note instead of failing the plugin. Results are
published to the discovery bus ("subdomains") so the takeover checker
and other chain plugins can consume them, deduped against anything
already published.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import List, Set
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def clean_subdomain(raw: str, domain: str) -> str:
    """Normalize one candidate: lowercase, strip wildcard/port/path.

    Returns "" unless it is a real subdomain of `domain` (the bare
    domain itself is not a subdomain finding).
    """
    s = (raw or "").strip().lower()
    s = s.lstrip("*.")
    # Strip scheme, path, port if a source returned a URL/host:port.
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/")[0].split(":")[0].strip(".")
    if not s or s == domain or not s.endswith("." + domain):
        return ""
    # Reject wildcards / garbage that slipped through.
    if "*" in s or " " in s or ".." in s:
        return ""
    return s


def dedupe_subdomains(candidates, domain: str, existing=None) -> List[str]:
    """Clean + dedupe candidates, excluding anything already seen."""
    seen: Set[str] = set(existing or [])
    out: List[str] = []
    for raw in candidates:
        sub = clean_subdomain(raw, domain)
        if sub and sub not in seen:
            seen.add(sub)
            out.append(sub)
    return sorted(out)


async def _fetch_json(ctx: Ctx, url: str, timeout: int = 20):
    """GET JSON through the limiter; None on any failure."""
    try:
        resp = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=timeout)
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


async def _fetch_text(ctx: Ctx, url: str, timeout: int = 20):
    try:
        resp = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=timeout)
        if resp.status_code != 200:
            return None
        return resp.text
    except Exception:
        return None


def parse_certspotter(data) -> List[str]:
    """CertSpotter issuances -> dns_names (list of hostnames)."""
    out: List[str] = []
    if not isinstance(data, list):
        return out
    for item in data:
        if isinstance(item, dict):
            for name in item.get("dns_names") or []:
                out.append(str(name))
    return out


def parse_bufferover(data) -> List[str]:
    """Bufferover passive DNS -> hostnames from FDNS_A / RDNS rows.

    Rows arrive as "ip,hostname" strings or [ip, hostname] pairs;
    both parts are returned and clean_subdomain() keeps only the
    parts that are actually subdomains of the target.
    """
    out: List[str] = []
    if not isinstance(data, dict):
        return out
    for key in ("FDNS_A", "RDNS"):
        for row in data.get(key) or []:
            if isinstance(row, str):
                out.extend(row.split(","))
            elif isinstance(row, list):
                out.extend(str(x) for x in row)
    return out


def _cdx_host(url: str) -> str:
    return url.split("://", 1)[-1].split("/")[0].split(":")[0]


def parse_wayback_cdx(text: str) -> List[str]:
    """Wayback CDX -> hostnames from archived URLs.

    Accepts both shapes: one JSON array of rows (output=json) and
    newline-delimited JSON rows. Row shape: [url, ...] or
    {"url": ...}. Header rows ("original") yield no hostname and
    are dropped by clean_subdomain().
    """
    out: List[str] = []
    if not text:
        return out
    rows: List = []
    try:
        doc = json.loads(text)
        if isinstance(doc, list):
            rows = doc
        else:
            rows = [doc]
    except Exception:
        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    for row in rows:
        url = ""
        if isinstance(row, list) and row:
            url = str(row[0])
        elif isinstance(row, dict):
            url = str(row.get("url", ""))
        if url:
            host = _cdx_host(url)
            # Skip the CDX header row ("original") and any non-host.
            if "." in host:
                out.append(host)
    return out


class PassiveSubdomainsPlugin(Plugin):
    timeout_s = 90
    id = "passive_subdomains"
    label = "Passive Subdomain Sources"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("Extra passive subdomain sources: CertSpotter CT, "
                   "Wayback CDX and Bufferover passive DNS. Deduped, "
                   "same-target only, no brute force.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        already = set(ctx.consume("subdomains"))

        async def certspotter():
            return await _fetch_json(
                ctx,
                f"https://api.certspotter.com/v1/issuances?domain={quote(domain)}"
                f"&include_subdomains=true&expand=dns_names", timeout=20)

        async def bufferover():
            return await _fetch_json(
                ctx,
                f"https://dns.bufferover.run/dns?q=.{quote(domain)}",
                timeout=20)

        async def wayback():
            return await _fetch_text(
                ctx,
                f"https://web.archive.org/cdx/search/cdx?url=*.{quote(domain)}"
                f"&output=json&fl=original&collapse=urlkey&limit=5000",
                timeout=25)

        cs_data, bo_data, wb_text = await asyncio.gather(
            ctx.cache.cached("certspotter", domain, certspotter),
            ctx.cache.cached("bufferover", domain, bufferover),
            ctx.cache.cached("wayback_subs", domain, wayback),
        )
        sources = [
            ("CertSpotter CT", parse_certspotter(cs_data[0] if isinstance(cs_data, tuple) else cs_data)),
            ("Bufferover passive DNS", parse_bufferover(bo_data[0] if isinstance(bo_data, tuple) else bo_data)),
            ("Wayback CDX", parse_wayback_cdx(wb_text[0] if isinstance(wb_text, tuple) else wb_text)),
        ]
        seen = set(already)
        total = 0
        for source_name, raw in sources:
            new = dedupe_subdomains(raw, domain, existing=seen)
            if not new:
                continue
            seen.update(new)
            total += len(new)
            findings.append(self._f(
                "dns", "subdomain_enum_note",
                f"{source_name} added {len(new)} subdomains",
                source=source_name, confidence=70, passive=True))
            for sub in new:
                ctx.publish("subdomains", sub)
                findings.append(self._f(
                    "dns", "subdomain", sub,
                    source=source_name, confidence=75, passive=True))
            self._checkpoint(findings)
        if total == 0:
            findings.append(self._f(
                "dns", "subdomain_enum_note",
                "passive sources returned no new subdomains "
                "(sources may be down or already covered)",
                source="passive subdomain sources", confidence=40,
                passive=True))
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{total} new subdomains from passive sources")
        res.duration_ms = dur
        return res
