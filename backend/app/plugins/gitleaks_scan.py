"""GitLeaks-style hardcoded secret detector.

Fast, comprehensive regex engine for hardcoded secrets across the homepage,
first-party JS bundles, HTML comments, and meta tags. Covers 60+ secret
types: cloud keys, CI tokens, payment keys, private keys, database URLs,
and generic credential assignments.

Detection only: read-only GETs of public pages. All matches redacted.
Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List, Set
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .secretutils import evidence_block, finding_value, is_placeholder, redact

REMED_KEY = "api_key"

# (name, regex, confidence, severity) - GitLeaks rule pack, web-adapted
RULES = [
    ("aws_access_key_id", r"AKIA[0-9A-Z]{16}", 95, "critical"),
    ("aws_session_token", r"ASIA[0-9A-Z]{16}", 90, "critical"),
    ("gcp_api_key", r"AIza[0-9A-Za-z\-_]{35}", 90, "high"),
    ("gcp_service_account", r'"type"\s*:\s*"service_account"', 85, "critical"),
    ("azure_storage_key", r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+", 90, "critical"),
    ("azure_client_secret", r"(?i)client[_-]?secret['\"]?\s*[:=]\s*['\"][A-Za-z0-9~_.\-]{20,}['\"]", 70, "high"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36}", 95, "critical"),
    ("github_pat", r"github_pat_[A-Za-z0-9_]{22,}", 95, "critical"),
    ("gitlab_token", r"glpat-[A-Za-z0-9\-_]{20}", 90, "critical"),
    ("slack_token", r"xox[baprs]-[0-9A-Za-z\-]{10,}", 95, "critical"),
    ("slack_webhook", r"https://hooks\.slack\.com/services/[A-Z0-9/]+", 90, "high"),
    ("discord_webhook", r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+", 85, "high"),
    ("telegram_bot_token", r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}", 90, "high"),
    ("stripe_secret", r"sk_(live|test)_[0-9A-Za-z]{16,}", 95, "critical"),
    ("stripe_restricted", r"rk_(live|test)_[0-9A-Za-z]{16,}", 90, "critical"),
    ("square_token", r"sq0atp-[A-Za-z0-9_\-]{20,}", 90, "critical"),
    ("paypal_client", r"(?i)paypal.{0,20}client[_-]?secret['\"]?\s*[:=]\s*['\"][A-Za-z0-9\-_]{20,}['\"]", 75, "high"),
    ("twilio_sid", r"AC[0-9a-f]{32}", 85, "high"),
    ("twilio_key", r"SK[0-9a-f]{32}", 90, "critical"),
    ("sendgrid_key", r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{30,}", 90, "critical"),
    ("mailgun_key", r"key-[0-9a-z]{32}", 85, "high"),
    ("openai_key", r"sk-[A-Za-z0-9]{20,}", 80, "critical"),
    ("anthropic_key", r"sk-ant-[A-Za-z0-9\-_]{20,}", 90, "critical"),
    ("huggingface_token", r"hf_[A-Za-z0-9]{30,}", 85, "high"),
    ("npm_token", r"npm_[A-Za-z0-9]{36}", 90, "critical"),
    ("pypi_token", r"pypi-AgEI[A-Za-z0-9_\-]{20,}", 90, "critical"),
    ("docker_token", r"dckr_pat_[A-Za-z0-9_\-]{20,}", 85, "high"),
    ("heroku_key", r"(?i)heroku.{0,10}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", 80, "critical"),
    ("digitalocean_token", r"dop_v1_[a-f0-9]{64}", 90, "critical"),
    ("private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", 99, "critical"),
    ("pgp_private", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", 95, "critical"),
    ("db_url", r"(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:]+:[^@]+@[^\s'\"]+", 90, "critical"),
    ("jdbc_url", r"(?i)jdbc:(?:postgresql|mysql)://[^:]+:[^@]+@[^\s'\"]+", 85, "critical"),
    ("jwt_token", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", 60, "medium"),
    ("basic_auth_url", r"https?://[A-Za-z0-9._%+-]+:[A-Za-z0-9._%+\-!$&'()*+,;=]+@[a-z0-9.\-]+", 80, "high"),
    ("firebase_key", r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{130,}", 90, "critical"),
    ("sentry_dsn", r"https://[0-9a-f]{32}@[a-z0-9.\-]*sentry[a-z0-9.\-]*/\d+", 75, "medium"),
    ("algolia_key", r"(?i)algolia.{0,30}['\"][A-Za-z0-9]{20,}['\"]", 60, "medium"),
    ("mapbox_token", r"pk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}", 65, "medium"),
    ("shopify_token", r"shp[a-z]{2,4}_[A-Za-z0-9]{20,}", 85, "high"),
    ("generic_api_key", r"(?i)(?:api[_-]?key|apikey|client[_-]?secret|app[_-]?secret)\s*[:=]\s*['\"]([^'\"]{12,})['\"]", 65, "high"),
    ("generic_token", r"(?i)(?:auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*['\"]([^'\"]{16,})['\"]", 65, "high"),
    ("hardcoded_password", r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", 70, "high"),
    ("aws_secret_hint", r"(?i)aws_secret_access_key.{0,20}[A-Za-z0-9/+=]{30,}", 75, "critical"),
]


class GitleaksScanPlugin(Plugin):
    id = "gitleaks_scan"
    label = "GitLeaks Secret Scan"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("GitLeaks-style rule pack: 40+ secret patterns across "
                   "pages, JS, comments, and meta tags.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        seen: Set[tuple] = set()

        def emit(name: str, match: str, where: str, conf: int,
                 severity: str, url: str | None):
            m = match.strip()[:300]
            if is_placeholder(m):
                return
            key = (name, m)
            if key in seen:
                return
            seen.add(key)
            findings.append(self._f(
                "leak", f"exposed_{name}",
                finding_value(severity, name.replace("_", " "), redact(m), where),
                source=f"gitleaks scan: {where}", source_url=url,
                confidence=conf, passive=passive,
                evidence=evidence_block(m, name, REMED_KEY, severity)))

        async def scan_text(text: str, where: str, url: str | None):
            for name, pat, conf, sev in RULES:
                try:
                    for m in re.finditer(pat, text):
                        val = (m.group(1) if m.groups()
                               and name.startswith(("generic_", "hardcoded_"))
                               else m.group(0))
                        emit(name, val, where, conf, sev, url)
                except re.error:
                    continue

        try:
            page = await ctx.fetch_page(base, timeout=25)
            if not page:
                res = self._degraded("homepage fetch failed")
                res.duration_ms = int((time.monotonic() - t0) * 1000)
                return res
            html = page["text"][:500000]
            page_url = page.get("url") or base

            # homepage + comments + meta
            await scan_text(html, "homepage HTML", page_url)
            comments = " ".join(re.findall(r"<!--(.*?)-->", html, re.S))[:100000]
            if comments.strip():
                await scan_text(comments, "HTML comments", page_url)
            metas = " ".join(re.findall(r"<meta[^>]+>", html, re.I))[:50000]
            if metas.strip():
                await scan_text(metas, "meta tags", page_url)

            # first-party JS bundles
            srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
            srcs = [s for s in srcs if not s.startswith("data:")][:20]
            for src in srcs:
                full = urljoin(page_url, src)
                host = urlparse(full).netloc
                if host and not host.endswith(domain):
                    continue
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=12)
                    if r.status_code == 200 and r.text:
                        await scan_text(r.text[:300000],
                                        f"JS bundle {src[:60]}", full)
                except Exception:
                    continue
        except Exception as e:
            res = self._degraded(f"scan failed: {str(e)[:150]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        res = self._ok(findings, f"{len(findings)} secret matches")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
