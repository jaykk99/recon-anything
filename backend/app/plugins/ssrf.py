"""SSRF sink detector (Milestone: critical findings).

Non-destructive and honest about limits: without a callback server we
cannot confirm server-side fetching, so this plugin finds SSRF-prone
parameters (url=, redirect=, image=, etc.), checks whether the app
reflects or acts on them, and flags cloud-metadata references in JS.
All findings are "verify manually" candidates, never confirmed
exploitation. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
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

REMEDIATION = ("Allowlist fetch destinations, block cloud metadata IPs "
               "(169.254.169.254) and RFC1918 ranges at the egress layer, "
               "and never let user input control outbound request URLs.")


class SsrfPlugin(Plugin):
    id = "ssrf"
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
        base = f"https://{domain}" if target.type == "domain" else target.normalized
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                            follow_redirects=True)
            html = r.text[:400000]
            page_url = str(r.url)
        except Exception as e:
            res = self._error(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # 1. SSRF-prone parameter names in links and forms
        seen_params = set()
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
                        f"CRITICAL: cloud metadata reference ({label}) in {where}. "
                        f"May indicate SSRF-reachable metadata service.",
                        source=f"metadata scan: {where}", source_url=url,
                        confidence=75, passive=passive,
                        evidence={"severity": "critical", "reference": label,
                                  "remediation": REMEDIATION,
                                  "scope_note": "Authorized testing only."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(seen_params)} SSRF-prone params, "
                                 f"{len(seen_meta)} metadata refs")
        res.duration_ms = dur
        return res
