"""Shared helpers for the fin_* bank / ATM detector pack.

The pack adds 40 financial-sector detectors (bankpack_portals.py,
bankpack_atm.py, bankpack_pay.py, bankpack_docs.py, bankpack_infra.py)
that plug into Bank/ATM mode's financial set. Everything here is
detection-only: read-only GETs through the shared Ctx (fetch_page /
probe), public DNS-over-HTTPS answers, and - for the certificate trio -
a TLS handshake that reads the presented certificate and nothing else.
No logins, no credential use, no form submissions, ever.

Secret handling: anything credential-shaped is reported MASKED
(first 6 / last 4 characters) plus a short SHA-256 fingerprint, the
same treatment the crypto pack uses. Full secrets never reach a
finding, the database, or a report.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .bank_surface import find_internal_leaks  # noqa: F401  (re-export)

TIMEOUT = 10

# Values that are documentation placeholders, not real secrets.
PLACEHOLDER_RE = re.compile(
    r"(example|sample|dummy|placeholder|your[-_ ]|xxx+|changeme|"
    r"test[-_ ]?key|redacted|\*{3,}|<[^>]+>|\.\.\.)", re.IGNORECASE)


def mask_secret(value: str) -> Tuple[str, str]:
    """(masked, fingerprint) for a credential-shaped value."""
    v = (value or "").strip()
    fp = hashlib.sha256(v.encode("utf-8", "ignore")).hexdigest()[:12]
    if len(v) <= 12:
        masked = v[:2] + "***"
    else:
        masked = f"{v[:6]}...{v[-4:]}"
    return masked, fp


def looks_like_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER_RE.search(value or ""))


async def base_for(target: Target, ctx: Ctx) -> Tuple[Optional[str],
                                                      Optional[str]]:
    """(domain, scheme-aware base url) for a domain/url target."""
    domain = domain_from_target(target.type, target.normalized)
    if not domain:
        return None, None
    try:
        base = await web_base(ctx, target, domain)
    except Exception:
        base = (target.normalized if target.type == "url"
                else f"https://{domain}/")
    if not base.endswith("/"):
        base += "/"
    return domain, base


async def fetch_text(ctx: Ctx, url: str,
                     timeout: int = TIMEOUT) -> Optional[Tuple[str, str,
                                                                Dict]]:
    """One page via the shared cache. (final_url, text, headers) or
    None when unreachable / non-200."""
    try:
        page = await ctx.fetch_page(url, timeout=timeout)
    except Exception:
        return None
    if not page:
        return None
    status = page.get("status_code") or page.get("status") or 0
    text = page.get("text", "") or ""
    if status and status != 200:
        return None
    if not text:
        return None
    headers = page.get("headers") or {}
    return (page.get("url") or url, text, headers)


async def fetch_paths(ctx: Ctx, base: str, paths,
                      timeout: int = TIMEOUT) -> List[Tuple[str, str, Dict]]:
    """Fetch base + each path (bounded, GET only), 200s only."""
    out: List[Tuple[str, str, Dict]] = []
    for p in paths:
        got = await fetch_text(ctx, urljoin(base, p.lstrip("/")),
                               timeout=timeout)
        if got:
            out.append(got)
    return out


_SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']",
                            re.IGNORECASE)


def script_urls(html: str, base: str, same_host_only: bool = True,
                cap: int = 5) -> List[str]:
    """Script URLs referenced by a page (deduped, capped)."""
    from urllib.parse import urlparse
    base_host = urlparse(base).netloc
    out: List[str] = []
    for m in _SCRIPT_SRC_RE.finditer(html or ""):
        u = urljoin(base, m.group(1))
        if same_host_only and urlparse(u).netloc != base_host:
            continue
        if u not in out:
            out.append(u)
        if len(out) >= cap:
            break
    return out


async def collect_texts(ctx: Ctx, base: str, extra_paths=(),
                        include_js: bool = True,
                        timeout: int = TIMEOUT) -> List[Tuple[str, str]]:
    """Homepage + its same-host scripts + extra paths as (url, text).

    The standard evidence pool for the content-scanning fin_* plugins.
    """
    out: List[Tuple[str, str]] = []
    seen = set()

    def add(url: str, text: str) -> None:
        if url not in seen and text:
            seen.add(url)
            out.append((url, text))

    home = await fetch_text(ctx, base, timeout=timeout)
    home_text = ""
    if home:
        add(home[0], home[1])
        home_text = home[1]
    if include_js and home_text:
        for js_url in script_urls(home_text, base):
            got = await fetch_text(ctx, js_url, timeout=timeout)
            if got:
                add(got[0], got[1])
    for url, text, _h in await fetch_paths(ctx, base, extra_paths,
                                           timeout=timeout):
        add(url, text)
    return out


def parse_json_text(text: str):
    """json.loads that returns None instead of raising."""
    try:
        return json.loads(text or "")
    except Exception:
        return None


async def doh(ctx: Ctx, name: str, rtype: str) -> List[str]:
    """DNS-over-HTTPS answers (data strings) for name/rtype.

    Public resolver, read-only. Returns [] on any failure - callers
    treat "no answer" as "no evidence", never as an error.
    """
    url = (f"https://dns.google/resolve?name={name}&type={rtype}")
    got = await fetch_text(ctx, url, timeout=8)
    if not got:
        return []
    data = parse_json_text(got[1])
    if not isinstance(data, dict):
        return []
    out = []
    for ans in data.get("Answer") or []:
        if isinstance(ans, dict) and ans.get("data"):
            out.append(str(ans["data"]).rstrip("."))
    return out


class FinPlugin(Plugin):
    """Base for the fin_* pack: financial group, domain/url, passive,
    and a run() wrapper that can never raise out (a broken check
    degrades to ok(0) with a note, per the plugin contract).

    id is blank so the registry skips this base class itself; every
    concrete detector sets its own fin_* id.
    """
    id = ""
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "financial"

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            res = await self.check(target, ctx)
        except Exception as e:  # noqa: BLE001 - degrade, never throw
            res = self._ok([], f"{self.id}: check could not complete "
                               f"({type(e).__name__})")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        raise NotImplementedError

    # -- shared finding helpers -------------------------------------
    def fin_finding(self, key: str, value: str, source_url: Optional[str],
                    severity: str, remediation: str,
                    confidence: int = 85, **evidence) -> Finding:
        ev = {"severity": severity, "remediation": remediation}
        ev.update(evidence)
        return self._f("financial", key, value,
                       source="bank/atm detector pack",
                       source_url=source_url, confidence=confidence,
                       passive=True, evidence=ev)

    async def domain_base(self, target: Target,
                          ctx: Ctx) -> Tuple[Optional[str], Optional[str]]:
        return await base_for(target, ctx)
