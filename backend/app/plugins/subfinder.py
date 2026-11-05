"""Subfinder-style passive subdomain enumeration (Tier-1 OSINT).

Native re-implementation of the subfinder idea: aggregate keyless,
public passive sources and merge them with strict dedup and a
same-target filter. Sources (all keyless, all read-only):

  * crt.sh          - certificate transparency name_value entries
  * HackerTarget    - api.hackertarget.com/hostsearch (plain text)
  * AnubisDB        - anubisdb.com/anubis/subdomains (JSON list)
  * RapidDNS        - rapiddns.io/subdomain page (HTML table scrape)

No DNS brute force, no requests to the target itself. A dead source
degrades silently; results are published to the discovery bus
("subdomains") for chain plugins. Detection only.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Set
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, \
    safe_json_list

SOURCE_NAMES = ("crt.sh", "HackerTarget", "AnubisDB", "RapidDNS")


def clean_subdomain(raw: str, domain: str) -> str:
    """Normalize one candidate; "" unless a true subdomain of domain."""
    s = (raw or "").strip().lower().strip(",")
    s = s.lstrip("*.")
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/")[0].split(":")[0].strip(".")
    if not s or s == domain or not s.endswith("." + domain):
        return ""
    if "*" in s or " " in s or ".." in s:
        return ""
    return s


def dedupe(candidates, domain: str, existing=None) -> List[str]:
    seen: Set[str] = set(existing or [])
    out: List[str] = []
    for raw in candidates:
        sub = clean_subdomain(str(raw), domain)
        if sub and sub not in seen:
            seen.add(sub)
            out.append(sub)
    return sorted(out)


def parse_crtsh(data) -> List[str]:
    out: List[str] = []
    for row in data or []:
        if isinstance(row, dict):
            for field in ("name_value", "common_name"):
                val = row.get(field) or ""
                out.extend(str(val).splitlines())
    return out


def parse_hackertarget(text: str) -> List[str]:
    out: List[str] = []
    for line in (text or "").splitlines():
        # rows are "host,ip" or bare hosts; errors start with "error"
        host = line.split(",")[0].strip()
        if host and not host.lower().startswith("error"):
            out.append(host)
    return out


def parse_anubis(data) -> List[str]:
    if isinstance(data, list):
        return [str(x) for x in data]
    return []


def parse_rapiddns(html: str, domain: str) -> List[str]:
    if not html:
        return []
    pat = re.compile(r"[\w.-]+\." + re.escape(domain) + r"\b")
    return pat.findall(html.lower())


async def _get(ctx: Ctx, url: str, timeout: int = 20):
    try:
        resp = await fetch(ctx.http, ctx.limiter, "GET", url,
                           timeout=timeout, max_retries=1)
        if resp.status_code != 200:
            return None
        return resp
    except Exception:
        return None


class SubfinderPlugin(Plugin):
    timeout_s = 90
    id = "subfinder"
    label = "Subfinder Passive Enumeration"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("Subdomain enumeration from keyless passive sources "
                   "(crt.sh, HackerTarget, AnubisDB, RapidDNS), deduped "
                   "and same-target filtered. No brute force.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        per_source: Dict[str, List[str]] = {}

        resp = await _get(ctx, f"https://crt.sh/?q=%25.{quote(domain)}"
                               f"&output=json")
        if resp is not None:
            per_source["crt.sh"] = parse_crtsh(safe_json_list(resp))

        resp = await _get(ctx, f"https://api.hackertarget.com/hostsearch/"
                               f"?q={quote(domain)}")
        if resp is not None:
            per_source["HackerTarget"] = parse_hackertarget(resp.text)

        resp = await _get(ctx, f"https://anubisdb.com/anubis/subdomains/"
                               f"{quote(domain)}")
        if resp is not None:
            try:
                per_source["AnubisDB"] = parse_anubis(resp.json())
            except Exception:
                per_source["AnubisDB"] = []

        resp = await _get(ctx, f"https://rapiddns.io/subdomain/"
                               f"{quote(domain)}?full=1")
        if resp is not None:
            per_source["RapidDNS"] = parse_rapiddns(resp.text, domain)

        seen: Set[str] = set(ctx.consume("subdomains"))
        total = 0
        for source_name, raw in per_source.items():
            new = dedupe(raw, domain, existing=seen)
            if not new:
                continue
            seen.update(new)
            total += len(new)
            for sub in new:
                ctx.publish("subdomains", sub)
                findings.append(self._f(
                    "dns", "subdomain", sub, source=f"subfinder/{source_name}",
                    confidence=75, passive=True))
            self._checkpoint(findings)
        res = self._ok(findings, f"{total} subdomains from passive sources "
                                 f"({', '.join(per_source) or 'no source up'})")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
