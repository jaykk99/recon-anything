"""Waymore-style archive mining: response-code history (Tier-3).

Master already mines archive URLs three ways (wayback: snapshots +
interesting URLs across CDX/CommonCrawl/Arquivo; waybackurls: every
CDX URL; gau: OTX + Wayback + Common Crawl aggregation). None of them
reports the RESPONSE-CODE HISTORY Waymore is known for: how each
URL's archived HTTP status changed over time. This plugin is that
remainder only - an UNCOLLAPSED CDX query (every capture, not one
row per URL) grouped per URL into a status timeline.

Signals worth reporting:
  * status_flip: a URL whose captures show 2+ distinct status codes
    (e.g. 200 -> 404 -> 200): content that appeared, vanished, or
    came back - a classic forgotten-endpoint trail.
  * gone_200: a URL with historical 200 captures whose LATEST capture
    is not a 200: was live, now is not (or is now protected).

Read-only archive query; the target itself is never requested.
"""
from __future__ import annotations

import time
from typing import Dict, List
from urllib.parse import quote, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, bounded

MAX_FLIP_FINDINGS = 40
MAX_GONE_FINDINGS = 40


def build_history(rows) -> Dict[str, List]:
    """Pure: CDX rows (header + [timestamp, original, statuscode])
    -> {url: [(timestamp, status), ...] sorted by timestamp}."""
    history: Dict[str, List] = {}
    if not isinstance(rows, list) or len(rows) < 2:
        return history
    header = rows[0] if isinstance(rows[0], list) else []
    try:
        ts_i = header.index("timestamp")
        url_i = header.index("original")
        st_i = header.index("statuscode")
    except (ValueError, AttributeError):
        ts_i, url_i, st_i = 0, 1, 2
    for row in rows[1:]:
        if not isinstance(row, (list, tuple)) or len(row) <= max(
                ts_i, url_i, st_i):
            continue
        url = str(row[url_i] or "")
        if not url:
            continue
        history.setdefault(url, []).append(
            (str(row[ts_i] or ""), str(row[st_i] or "")))
    for url in history:
        history[url].sort()
    return history


def classify_history(history: Dict[str, List]) -> Dict[str, List]:
    """Pure: split a history map into flip / gone-200 URL lists."""
    flips: List = []
    gone: List = []
    for url, timeline in sorted(history.items()):
        codes = [code for _ts, code in timeline if code and code != "-"]
        distinct = sorted(set(codes))
        if len(distinct) >= 2:
            flips.append((url, timeline, distinct))
        if codes and "200" in codes[:-1] and codes[-1] != "200":
            gone.append((url, timeline, distinct))
    return {"flips": flips, "gone": gone}


class WaymorePlugin(Plugin):
    id = "waymore"
    label = "Waymore Status History"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 60
    phase = 2
    description = ("Waymore-style archive mining of response-code "
                   "history: per-URL status timelines from an "
                   "uncollapsed Wayback CDX query (status flips and "
                   "was-200-now-gone endpoints).")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        cdx_url = ("https://web.archive.org/cdx/search/cdx?url="
                   + quote(domain)
                   + "/*&output=json&fl=timestamp,original,statuscode"
                     "&limit=2000")
        try:
            r = await bounded(fetch(ctx.http, ctx.limiter, "GET", cdx_url,
                                    timeout=20, max_retries=0), 24)
            if r is None or r.status_code != 200:
                res = self._degraded(
                    f"CDX unavailable: HTTP "
                    f"{r.status_code if r is not None else 'timeout'}")
                res.duration_ms = int((time.monotonic() - t0) * 1000)
                return res
            rows = r.json()
        except Exception as e:
            res = self._degraded(
                f"CDX query failed: {type(e).__name__}: {str(e)[:100]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        history = build_history(rows)
        # Same-domain gate (archives return off-target captures).
        history = {u: tl for u, tl in history.items()
                   if ((urlparse(u).hostname or "").lower() == domain
                       or (urlparse(u).hostname or "").lower().endswith(
                           "." + domain))}
        for u in history:
            ctx.publish("urls", u)
        classes = classify_history(history)
        findings: List[Finding] = []
        for url, timeline, distinct in classes["flips"][:MAX_FLIP_FINDINGS]:
            trail = " -> ".join(
                f"{ts[:8]}:{code}" for ts, code in timeline[:8])
            findings.append(self._f(
                "web", "archived_status_flip",
                f"{url} status history {', '.join(distinct)}: {trail}",
                source="waymore/wayback-cdx", source_url=url,
                confidence=70,
                evidence={"severity": "low", "statuses": distinct,
                          "captures": len(timeline),
                          "remediation": "Review this URL's history: "
                                         "content that flipped status "
                                         "often marks a forgotten or "
                                         "re-exposed endpoint."},
                passive=True))
        for url, timeline, _d in classes["gone"][:MAX_GONE_FINDINGS]:
            if any(url == f_url for f_url, _t, _c in
                   classes["flips"][:MAX_FLIP_FINDINGS]):
                continue  # already reported as a flip
            findings.append(self._f(
                "web", "archived_was_live",
                f"{url} was 200 in archives, latest capture "
                f"{timeline[-1][1]} at {timeline[-1][0][:8]}",
                source="waymore/wayback-cdx", source_url=url,
                confidence=65,
                evidence={"severity": "low",
                          "captures": len(timeline),
                          "remediation": "This endpoint existed and "
                                         "served 200s historically; "
                                         "confirm its removal was "
                                         "intended and complete."},
                passive=True))
        total_captures = sum(len(tl) for tl in history.values())
        res = self._ok(findings,
                       f"{total_captures} captures across "
                       f"{len(history)} URLs: "
                       f"{len(classes['flips'])} status-flip, "
                       f"{len(classes['gone'])} was-200-now-gone")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
