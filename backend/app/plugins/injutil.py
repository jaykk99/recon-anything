"""Shared helpers for injection-detection plugins.

This module defines no Plugin subclass, so the registry ignores it.
It just holds the URL discovery and probe-building code that every
injection plugin needs.
"""
from __future__ import annotations

import re
from typing import Set, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

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


# Parameter names historically tied to injection sinks. URLs carrying
# these are tested first when a plugin caps how many URLs it probes.
INTERESTING_PARAMS = frozenset({
    "id", "cmd", "command", "exec", "run", "file", "path", "page",
    "include", "template", "url", "q", "query", "querystring", "search",
    "keyword", "kw", "s", "name", "user", "username", "input", "data",
    "item", "product", "article", "cat", "category", "pid", "sid", "uid",
    "action", "do", "view", "p", "text", "title", "content", "msg",
    "message", "comment", "email", "redirect", "next", "return", "dest",
    "target", "callback", "load", "read", "show", "display", "key",
    "token", "ref", "lang", "sort", "order", "filter", "dir", "folder",
    "doc", "document", "download", "attachment", "img", "image", "pic",
    "photo", "avatar", "thumb", "ip", "host", "hostname", "domain",
    "ping", "test", "debug", "val", "value", "param", "arg",
    # common app params: missing these caused real false negatives
    "artist", "author", "album", "song", "track", "video", "movie",
    "post", "thread", "topic", "event", "job", "listing", "property",
    "car", "hotel", "room", "table", "row", "record", "field", "col",
    "column", "select", "where", "query_id", "report", "invoice",
    "order", "cart", "sku", "barcode", "serial", "model", "make",
    "year", "date", "day", "month", "filter2",
})


def _interesting_score(url: str) -> int:
    """Higher = more likely to hide an injection sink."""
    try:
        params = parse_qsl(urlparse(url).query, keep_blank_values=True)
    except Exception:
        return 0
    return sum(2 for n, _ in params if n.lower() in INTERESTING_PARAMS) \
        + (1 if params else 0)


def _path_key(url: str) -> str:
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path}"
    except Exception:
        return url


def sample_urls(urls, limit: int) -> list:
    """Deterministic, interesting-first URL sampling (P0 false-negative fix).

    `list(urls)[:N]` on a set samples ARBITRARILY: on targets with many
    parameterized URLs, vulnerable endpoints were silently skipped purely
    by set ordering. This dedups by path (keeping the variant with the
    most params), then sorts interesting-param URLs first and the rest
    alphabetically, so the cap keeps scan time bounded without gambling
    on which URLs get tested.
    """
    by_path = {}
    for u in set(urls):
        k = _path_key(u)
        try:
            n_params = len(parse_qsl(urlparse(u).query,
                                     keep_blank_values=True))
        except Exception:
            n_params = 0
        prev = by_path.get(k)
        if prev is None or n_params > prev[1]:
            by_path[k] = (u, n_params)
    deduped = [u for u, _ in by_path.values()]
    return sorted(deduped,
                  key=lambda u: (-_interesting_score(u), u))[:limit]
