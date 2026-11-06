"""httpx-style HTTP probing (native, keyless).

Probes the target over HTTP and HTTPS (plus common alt web ports for
domain targets): status code, page title, Server header, technology
hints, redirect chain and content length for every responding URL.
Read-only GETs through the shared rate limiter.
"""
from __future__ import annotations

import time
from typing import Dict, List
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ._tier2_common import extract_title, host_of, tech_hints
from .base import Cost, Ctx, Plugin, PluginResult, Target, bounded

MAX_REDIRECTS = 5


def probe_urls(target: Target, host: str) -> List[str]:
    """Candidate base URLs to probe for a target - pure helper."""
    if target.type == "url":
        p = urlparse(target.normalized)
        if p.scheme and p.netloc:
            return [f"{p.scheme}://{p.netloc}/"]
    urls = [f"https://{host}/", f"http://{host}/"]
    return urls


class HttpxProbePlugin(Plugin):
    id = "httpx_probe"
    label = "httpx Probe"
    accepts = ["domain", "url", "ip"]
    passive = False
    cost = Cost.FREE
    group = "web"
    timeout_s = 90
    description = ("HTTP probing of resolved hosts: status, title, "
                   "server, tech hints, redirect chain, content length "
                   "over HTTP and HTTPS.")

    async def _probe_one(self, ctx: Ctx, start_url: str) -> Dict:
        """GET with a manual redirect walk. Returns a probe dict."""
        chain = []
        url = start_url
        status = 0
        headers: Dict[str, str] = {}
        body = ""
        final_url = start_url
        for _ in range(MAX_REDIRECTS + 1):
            try:
                r = await bounded(fetch(
                    ctx.http, ctx.limiter, "GET", url, timeout=10,
                    follow_redirects=False, max_retries=0), 12)
            except Exception:
                break
            if r is None:
                break
            status = r.status_code
            headers = {k.lower(): v for k, v in r.headers.items()}
            body = r.text or ""
            final_url = str(r.url)
            chain.append(status)
            loc = r.headers.get("location")
            if status in (301, 302, 303, 307, 308) and loc:
                url = urljoin(final_url, loc)
                continue
            break
        length = 0
        try:
            length = int(headers.get("content-length", 0)) or len(body)
        except Exception:
            length = len(body)
        return {"status": status, "headers": headers, "body": body,
                "chain": chain, "length": length, "final_url": final_url}

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        host = host_of(target)
        if not host:
            return self._skipped("no host for this target type")
        findings = []
        for url in probe_urls(target, host):
            data = await self._probe_one(ctx, url)
            if not data["status"]:
                continue
            title = extract_title(data["body"])
            hints = tech_hints(data["headers"], data["body"])
            server = data["headers"].get("server", "")
            value = (f"{url} -> {data['status']}"
                     + (f" [{data['final_url']}]"
                        if data["final_url"] != url else "")
                     + (f" title: {title}" if title else "")
                     + (f" server: {server}" if server else "")
                     + f" length: {data['length']}")
            findings.append(self._f(
                "web", "httpx_http_service", value,
                source="httpx_probe", source_url=url, confidence=90,
                passive=False,
                evidence={"severity": "low", "status": data["status"],
                          "title": title, "server": server,
                          "tech": hints,
                          "redirect_chain": data["chain"],
                          "content_length": data["length"],
                          "final_url": data["final_url"],
                          "remediation": "Informational: confirm this "
                                         "service is intended to be "
                                         "public and keep it patched."}))
            for hint in hints:
                ctx.publish("tech", hint)
            if len(data["chain"]) > 1:
                findings.append(self._f(
                    "web", "httpx_redirect_chain",
                    f"{url} redirects {' -> '.join(str(s) for s in data['chain'])} "
                    f"to {data['final_url']}",
                    source="httpx_probe", source_url=url, confidence=85,
                    passive=False,
                    evidence={"severity": "low",
                              "redirect_chain": data["chain"],
                              "final_url": data["final_url"],
                              "remediation": "Keep redirect chains short "
                                             "and HTTPS-only."}))
        res = self._ok(findings,
                       f"{len(findings)} probe findings")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
