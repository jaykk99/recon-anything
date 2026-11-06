"""ParamSpider-style archived parameter mining (Tier-3, native).

Mines the Wayback CDX index (keyless) for a domain's archived URLs,
then does the one thing the existing archive plugins (wayback,
waybackurls, gau) do NOT do: parse every query string and report the
unique parameter names and the parameterized endpoints they were seen
on. Param names are the seed list for parameter fuzzing, so they are
published to the discovery bus ("params") alongside the endpoints.

Read-only archive query; the target itself is never requested.
Payload-shaped archive rows (captured probe strings) are dropped.
"""
from __future__ import annotations

import time
from typing import Dict, List, Set
from urllib.parse import parse_qsl, quote, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, bounded

MAX_ENDPOINT_FINDINGS = 60
MAX_PARAM_FINDINGS = 80


def _is_junk(url: str) -> bool:
    try:
        parts = urlparse(url)
    except Exception:
        return True
    rest = (parts.path + "?" + parts.query).lower()
    return any(m in rest for m in (
        "http://", "https://", '"', "'", "<", ">", " ", "�"))


def mine_params(urls) -> Dict[str, Dict]:
    """Pure mining: url -> {param: {"count": n, "example": url}} plus
    per-endpoint param sets. Returns {"params": ..., "endpoints": ...}.
    """
    params: Dict[str, Dict] = {}
    endpoints: Dict[str, Set[str]] = {}
    for raw in urls or []:
        u = str(raw or "").strip()
        if not u or _is_junk(u):
            continue
        try:
            parts = urlparse(u)
        except Exception:
            continue
        if parts.scheme not in ("http", "https") or not parts.query:
            continue
        names = [k for k, _ in parse_qsl(parts.query,
                                         keep_blank_values=True) if k]
        if not names:
            continue
        endpoint = f"{parts.scheme}://{parts.netloc}{parts.path}"
        endpoints.setdefault(endpoint, set()).update(names)
        for name in names:
            slot = params.setdefault(name, {"count": 0, "example": u})
            slot["count"] += 1
    return {"params": params, "endpoints": endpoints}


class ParamSpiderPlugin(Plugin):
    id = "paramspider"
    label = "ParamSpider Archive Param Mining"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 60
    phase = 2
    description = ("Mine Wayback CDX archives for parameterized "
                   "endpoints; report unique parameter names for "
                   "downstream fuzzing. Keyless, archive-only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        cdx_url = ("https://web.archive.org/cdx/search/cdx?url="
                   + quote(domain) + "/*&output=json&fl=original"
                     "&collapse=urlkey&limit=2000")
        urls: List[str] = []
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
            if isinstance(rows, list):
                for row in rows[1:]:
                    if row and row[0]:
                        urls.append(str(row[0]))
        except Exception as e:
            res = self._degraded(
                f"CDX query failed: {type(e).__name__}: {str(e)[:100]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # Keep only same-domain URLs (archives return off-target rows).
        own = []
        for u in urls:
            try:
                host = (urlparse(u).hostname or "").lower()
            except Exception:
                continue
            if host == domain or host.endswith("." + domain):
                own.append(u)

        mined = mine_params(own)
        params, endpoints = mined["params"], mined["endpoints"]
        findings: List[Finding] = []
        for name in sorted(params)[:MAX_PARAM_FINDINGS]:
            info = params[name]
            ctx.publish("params", name)
            findings.append(self._f(
                "web", "archived_param", name,
                source="paramspider/wayback-cdx",
                source_url=info["example"], confidence=70,
                evidence={"severity": "low", "seen_count": info["count"],
                          "example": info["example"],
                          "remediation": "Inventory archived parameters: "
                                         "validate them server-side and "
                                         "remove dead ones; archived "
                                         "params are prime fuzzing "
                                         "targets."},
                passive=True))
        for ep in sorted(endpoints)[:MAX_ENDPOINT_FINDINGS]:
            ctx.publish("endpoints", ep)
            findings.append(self._f(
                "web", "parameterized_endpoint",
                f"{ep} (params: {', '.join(sorted(endpoints[ep]))})",
                source="paramspider/wayback-cdx", source_url=ep,
                confidence=65,
                evidence={"severity": "low",
                          "params": sorted(endpoints[ep]),
                          "remediation": "Verify this archived endpoint "
                                         "is still live and intended; "
                                         "check its parameters for "
                                         "authorization flaws."},
                passive=True))
        res = self._ok(findings,
                       f"{len(own)} archived URLs mined: "
                       f"{len(params)} unique params across "
                       f"{len(endpoints)} parameterized endpoints")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
