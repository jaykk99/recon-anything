"""Cloudflare presence + challenge detection (Tier-1 OSINT).

DETECTION ONLY. Reports whether a target sits behind Cloudflare and
whether Cloudflare is serving bot-management / challenge responses:

  * response headers: server: cloudflare, cf-ray, cf-cache-status,
    cf-apitig-token / cf-mitigated
  * cookies: __cf_bm, cf_clearance, __cflb
  * challenge-page signatures in the body: "Attention Required!",
    challenge-platform scripts, "Checking your browser before
    accessing", /cdn-cgi/ markers
  * /cdn-cgi/trace probe confirming the Cloudflare edge (fl=/h=
    fields)

Nothing here bypasses, solves or evades any challenge - it only
observes and reports what the edge serves, like any passive scanner.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import urlparse

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

CHALLENGE_MARKERS = (
    "attention required! | cloudflare",
    "/cdn-cgi/challenge-platform",
    "challenge-platform/h/g/orchestrate",
    "checking your browser before accessing",
    "cf-challenge",
    "just a moment...",
    "enable javascript and cookies to continue",
)
CF_COOKIES = ("__cf_bm", "cf_clearance", "__cflb", "__cfruid")


def analyze(headers: dict, html: str) -> dict:
    """Pure analysis: cloudflare? challenge? evidence bits."""
    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    body = (html or "").lower()
    signals: List[str] = []
    if hdrs.get("server", "").strip().lower() == "cloudflare":
        signals.append("server: cloudflare")
    if hdrs.get("cf-ray"):
        signals.append("cf-ray header")
    if hdrs.get("cf-cache-status"):
        signals.append("cf-cache-status header")
    if hdrs.get("cf-mitigated", "").lower() == "challenge":
        signals.append("cf-mitigated: challenge")
    cookie_blob = hdrs.get("set-cookie", "")
    for name in CF_COOKIES:
        if name in cookie_blob:
            signals.append(f"cookie {name}")
    if "/cdn-cgi/" in body:
        signals.append("/cdn-cgi/ path in page")
    challenge = any(m in body for m in CHALLENGE_MARKERS)
    if challenge:
        signals.append("challenge page body")
    return {"cloudflare": bool(signals), "challenge": challenge,
            "signals": signals}


def base_url(target: Target) -> str:
    if target.type == "url":
        p = urlparse(target.normalized)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}/"
    return f"https://{target.normalized.strip('/')}/"


class CloudflareDetectPlugin(Plugin):
    timeout_s = 60
    id = "cloudflare_detect"
    label = "Cloudflare Detection"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Detects Cloudflare fronting (headers, cookies, "
                   "/cdn-cgi/ markers, /cdn-cgi/trace) and whether a "
                   "challenge page is being served. Detection only - "
                   "no challenge bypassing of any kind.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        url = base_url(target)
        page = await ctx.fetch_page(url)
        if page is None:
            return self._degraded(f"could not fetch {url}")
        headers = dict(page.get("headers") or {})
        html = page.get("text") or ""
        result = analyze(headers, html)
        findings: List[Finding] = []

        # /cdn-cgi/trace corroboration (a plain GET of a diagnostic
        # path Cloudflare itself serves publicly).
        trace = await ctx.probe(url.rstrip("/") + "/cdn-cgi/trace",
                                timeout=8)
        trace_text = (trace or {}).get("text") or ""
        on_cf_edge = "fl=" in trace_text and "h=" in trace_text \
            and (trace or {}).get("status") == 200
        if on_cf_edge and not result["cloudflare"]:
            result["cloudflare"] = True
            result["signals"].append("/cdn-cgi/trace answered")

        if result["cloudflare"]:
            findings.append(self._f(
                "infra", "cloudflare_fronted",
                f"{urlparse(url).netloc} is behind Cloudflare "
                f"({'; '.join(result['signals'])})",
                source="cloudflare_detect/headers", source_url=url,
                confidence=90, passive=True,
                evidence={"signals": result["signals"],
                          "severity": "low"}))
            ctx.publish("tech", "cloudflare")
        if result["challenge"]:
            findings.append(self._f(
                "infra", "cloudflare_challenge",
                "Cloudflare challenge / bot-management page is being "
                "served to automated clients",
                source="cloudflare_detect/body", source_url=url,
                confidence=85, passive=True,
                evidence={"signals": result["signals"],
                          "severity": "low",
                          "remediation": "Expected when bot management "
                                         "is on; verify legitimate "
                                         "scanners/APIs are allow-listed "
                                         "if they must reach the origin."}))
        res = self._ok(findings, "Cloudflare detected"
                                 if result["cloudflare"]
                                 else "no Cloudflare signals")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
