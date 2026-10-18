"""Shared helpers for injection-detection plugins.

This module defines no Plugin subclass, so the registry ignores it.
It just holds the URL discovery and probe-building code that every
injection plugin needs.
"""
from __future__ import annotations

import re
from typing import Set, Tuple
from urllib.parse import urlencode, urlparse, urlunparse

from ..ratelimit import fetch
from .base import Ctx


async def fetch_homepage(ctx: Ctx, base: str) -> Tuple[str, str]:
    """Fetch the target homepage. Returns (html, final_url)."""
    r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                    follow_redirects=True)
    return r.text[:300000], str(r.url)


def param_urls(html: str, page_url: str, domain: str, ctx: Ctx) -> Set[str]:
    """Collect same-domain URLs with query params from page + bus."""
    urls = set()
    for m in re.finditer(r'href=["\']([^"\']+\?[^"\']+)["\']', html, re.I):
        u = m.group(1)
        if u.startswith("/"):
            p = urlparse(page_url)
            u = f"{p.scheme}://{p.netloc}{u}"
        if domain in urlparse(u).netloc:
            urls.add(u)
    for eu in ctx.consume("endpoints"):
        if isinstance(eu, str) and "?" in eu and \
                domain in urlparse(eu).netloc:
            urls.add(eu)
    return urls


def probe_url(parts, params, name: str, value: str) -> str:
    """Rebuild URL with one param's value replaced by the probe."""
    probe = [(n, value if n == name else v) for n, v in params]
    return urlunparse(parts._replace(query=urlencode(probe)))
