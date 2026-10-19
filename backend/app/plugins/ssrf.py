"""SSRF sink detector (Milestone: critical findings).

Non-destructive and honest about limits: without a callback server we
cannot confirm server-side fetching, so this plugin finds SSRF-prone
parameters (url=, redirect=, image=, etc.), checks whether the app
reflects or acts on them, and flags cloud-metadata references in JS.

Active mode adds a safe OOB canary test: URL-ish params get a unique
canary value (your own callback server via OOB_CALLBACK_BASE, or a
harmless https://example.com/?recon_canary=<token> URL). Detection is
based on reflection / redirect / error-message leakage only - the
plugin never requests internal addresses itself.

OOB_CALLBACK_BASE: export it to your own callback endpoint (e.g. a
Burp Collaborator / interactsh URL) for real out-of-band confirmation:
    export OOB_CALLBACK_BASE="https://abc123.interactsh.com"
Without it, canary tests fall back to the example.com reflection check
(which detects echo/redirect sinks but not silent server-side fetches).
"""
from __future__ import annotations

import asyncio
import os
import re
import secrets
import time
from typing import List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

SSRF_PARAMS = {"url", "redirect", "redirect_url", "next", "return",
               "returnurl", "image", "img", "avatar", "file", "path",
               "page", "template", "feed", "rss", "webhook", "callback",
               "fetch", "proxy", "src", "dest", "destination", "u", "uri"}

METADATA_PATTERNS = [
    (r"169\.254\.169\.254", "AWS/GCP cloud metadata IP"),
    (r"metadata\.google\.internal", "GCP metadata hostname"),
    (r"metadata\.google\.com", "GCP metadata alt hostname"),
    (r"100\.100\.100\.200", "Alibaba metadata IP"),
    (r"169\.254\.169\.123", "Oracle Cloud metadata IP"),
    (r"169\.254\.170\.2", "AWS ECS metadata endpoint"),
    (r"fd00:ec2::254", "AWS IPv6 metadata"),
    (r"instance\.metadata\.azure\.com", "Azure metadata hostname"),
    (r"169\.254\.169\.254/metadata", "Generic cloud metadata path"),
]

# Cloud metadata URLs for bounty reference
CLOUD_METADATA_URLS = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/computeMetadata/v1/ (GCP, needs Metadata-Flavor header)",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/ (Alibaba)",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Azure, needs Metadata:true header)",
    "http://169.254.169.123/opc/v1/instance/ (Oracle)",
    "http://169.254.170.2/v2/credentials/ (AWS ECS)",
]

# Internal-IP / metadata indicators that show up in error messages or
# page sources when an app has tried to reach internal addresses.
# Never requested by this plugin - only pattern-matched in responses.
INTERNAL_IP_PATTERNS = [
    (r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "RFC1918 10.x address"),
    (r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "RFC1918 192.168.x address"),
    (r"\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b", "RFC1918 172.16-31.x address"),
    (r"169\.254\.169\.254", "cloud metadata IP"),
    (r"metadata\.google\.internal", "GCP metadata hostname"),
    (r"instance\.metadata\.azure\.com", "Azure metadata hostname"),
]

OOB_ENV_VAR = "OOB_CALLBACK_BASE"

REMEDIATION = ("Allowlist fetch destinations, block cloud metadata IPs "
               "(169.254.169.254) and RFC1918 ranges at the egress layer, "
               "and never let user input control outbound request URLs.")


class SsrfPlugin(Plugin):
    id = "ssrf"
    aggressive = True  # suppressed on WAF-protected hosts
    label = "SSRF Sink Finder"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Find SSRF-prone params and metadata references (verify manually)."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        try:
            # Shared homepage cache: first plugin pays, the rest read from cache.
            page = await ctx.fetch_page(base, timeout=25)
            if page is None:
                raise RuntimeError("homepage fetch failed")
            html = page["text"][:400000]
            page_url = page["url"]
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # 1. SSRF-prone parameter names in links and forms.
        # Also pull params published on the discovery bus by the
        # param-discovery plugin, so canary tests cover found params.
        seen_params = set()
        for bp in ctx.consume("params"):
            try:
                bn = str(bp.get("name", "") if isinstance(bp, dict) else bp).lower()
            except Exception:
                bn = ""
            if bn in SSRF_PARAMS:
                seen_params.add(bn)
        for m in re.finditer(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', html):
            pname = m.group(1).lower()
            if pname in SSRF_PARAMS and pname not in seen_params:
                seen_params.add(pname)
                findings.append(self._f(
                    "web", "ssrf_prone_param",
                    f"HIGH: SSRF-prone parameter '{m.group(1)}' found on site. "
                    f"CRITICAL if it can reach cloud metadata. Test targets: "
                    f"AWS 169.254.169.254, GCP metadata.google.internal, "
                    f"Azure 169.254.169.254/metadata, Alibaba 100.100.100.200, "
                    f"Oracle 169.254.169.123. "
                    f"Cloud credential theft via SSRF pays $5k+.",
                    source="HTML param mining", source_url=page_url,
                    confidence=60, passive=passive,
                    evidence={"severity": "high", "parameter": m.group(1),
                              "cloud_targets": CLOUD_METADATA_URLS,
                              "bounty_note": "SSRF to cloud metadata = $5k+ payout. Test with your own callback first.",
                              "remediation": REMEDIATION,
                              "scope_note": "Candidate only: confirm with your own callback server on an authorized target."}))

        # 2. metadata references in page and JS
        texts = [("homepage HTML", html, page_url)]
        for sm in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            from urllib.parse import urljoin
            full = urljoin(page_url, sm.group(1))
            if urlparse(full).netloc.endswith(domain):
                try:
                    jr = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=15)
                    if jr.status_code == 200:
                        texts.append(("JS bundle", jr.text[:500000], full))
                except Exception:
                    continue
            if len(texts) > 12:
                break

        seen_meta = set()
        for where, text, url in texts:
            for pat, label in METADATA_PATTERNS:
                if re.search(pat, text) and (pat, where) not in seen_meta:
                    seen_meta.add((pat, where))
                    findings.append(self._f(
                        "leak", "cloud_metadata_ref",
                        f"HIGH: cloud metadata reference ({label}) in {where}. "
                        f"May indicate SSRF-reachable metadata service - verify manually.",
                        source=f"metadata scan: {where}", source_url=url,
                        confidence=60, passive=passive,
                        evidence={"severity": "high", "reference": label,
                                  "note": "String reference only - not confirmed reachable. "
                                          "Test SSRF manually on authorized targets.",
                                  "remediation": REMEDIATION,
                                  "scope_note": "Authorized testing only."}))

        # 3. Internal-IP / metadata indicators in page sources and error
        # messages (passive): an app that echoes RFC1918 or metadata IPs
        # has likely tried to reach internal addresses.
        seen_internal = set()
        for where, text, url in texts:
            for pat, label in INTERNAL_IP_PATTERNS:
                if pat in [p for p, _ in METADATA_PATTERNS]:
                    continue  # already covered above
                for m in re.finditer(pat, text):
                    key = (m.group(0), where)
                    if key in seen_internal:
                        continue
                    seen_internal.add(key)
                    findings.append(self._f(
                        "leak", "internal_ip_indicator",
                        f"MEDIUM: internal address reference ({label}: "
                        f"{m.group(0)}) in {where}. May indicate the app "
                        f"touches internal network ranges - check for SSRF "
                        f"or internal exposure.",
                        source=f"internal-IP scan: {where}", source_url=url,
                        confidence=50, passive=passive,
                        evidence={"severity": "medium", "indicator": m.group(0),
                                  "indicator_type": label,
                                  "remediation": REMEDIATION,
                                  "scope_note": "Indicator only: no internal "
                                                "address was requested by "
                                                "this plugin."}))

        # 4. Safe OOB canary test (active mode only): set URL-ish params to
        # a unique canary and look for reflection / redirect / error leaks.
        # Never requests an internal address.
        if not passive and seen_params:
            oob_base = os.environ.get(OOB_ENV_VAR, "").strip().rstrip("/")
            token = "rc" + secrets.token_hex(6)
            canary = (f"{oob_base}/{token}" if oob_base
                      else f"https://example.com/?recon_canary={token}")
            oob_note = (f"using your callback {oob_base} - check it for a "
                        f"hit on /{token}"
                        if oob_base else
                        "no OOB_CALLBACK_BASE set - reflection/redirect "
                        "check only. Set OOB_CALLBACK_BASE to your own "
                        "callback URL (e.g. interactsh) for real "
                        "out-of-band confirmation.")
            sem = asyncio.Semaphore(5)
            test_params = list(seen_params)[:5]

            async def canary_test(pname: str):
                async with sem:
                    try:
                        parts = urlparse(page_url)
                        q = dict(parse_qsl(parts.query, keep_blank_values=True))
                        q[pname] = canary
                        test_url = urlunparse(parts._replace(
                            query=urlencode(q)))
                        r = await fetch(ctx.http, ctx.limiter, "GET", test_url,
                                        timeout=10, follow_redirects=False,
                                        max_retries=1)
                    except Exception:
                        return None
                    body = ""
                    try:
                        body = r.text[:20000]
                    except Exception:
                        pass
                    loc = r.headers.get("location", "")
                    return pname, r.status_code, body, loc, test_url

            for result in await asyncio.gather(
                    *(canary_test(p) for p in test_params)):
                if not result:
                    continue
                pname, status, body, loc, test_url = result
                if token in body:
                    findings.append(self._f(
                        "web", "ssrf_canary_reflected",
                        f"MEDIUM: canary token reflected in response body "
                        f"when '{pname}' was set to {canary[:60]}. "
                        f"The param value is echoed - may be a fetch/echo "
                        f"sink. {oob_note}",
                        source="SSRF canary test", source_url=test_url,
                        confidence=65, passive=False,
                        evidence={"severity": "medium", "parameter": pname,
                                  "canary_token": token,
                                  "remediation": REMEDIATION,
                                  "scope_note": "Reflection only - no "
                                                "internal request was made."}))
                if token in loc or "example.com" in loc:
                    findings.append(self._f(
                        "web", "ssrf_open_redirect",
                        f"MEDIUM: setting '{pname}' to the canary URL "
                        f"redirects to {loc[:120]} - open redirect / "
                        f"redirect sink. {oob_note}",
                        source="SSRF canary test", source_url=test_url,
                        confidence=80, passive=False,
                        evidence={"severity": "medium", "parameter": pname,
                                  "redirect_to": loc[:200],
                                  "remediation": REMEDIATION}))
                leak = next((m.group(0) for pat, _ in INTERNAL_IP_PATTERNS
                             for m in [re.search(pat, body)] if m), None)
                if leak:
                    findings.append(self._f(
                        "web", "ssrf_error_leak",
                        f"HIGH: error response for '{pname}={canary[:40]}...' "
                        f"leaks internal indicator ({leak}). The server "
                        f"attempted or resolved an internal address - "
                        f"strong SSRF signal. Verify manually.",
                        source="SSRF canary test", source_url=test_url,
                        confidence=75, passive=False,
                        exploitability="public_poc",
                        evidence={"severity": "high", "parameter": pname,
                                  "leaked_indicator": leak,
                                  "remediation": REMEDIATION,
                                  "scope_note": "Leak observed in an error "
                                                "response; the plugin itself "
                                                "never requested internal "
                                                "addresses."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(seen_params)} SSRF-prone params, "
                                 f"{len(seen_meta)} metadata refs, "
                                 f"{len(seen_internal)} internal-IP indicators")
        res.duration_ms = dur
        return res
