"""Exposed API key finder (Milestone: secret findings).

Scans the homepage HTML and every first-party JS bundle for 35+ API key
and token patterns. Read-only GETs of public pages. Findings are
CRITICAL, redacted in the value, full match in evidence with rotation
advice. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .secretutils import evidence_block, finding_value, is_placeholder, redact

# (name, regex, confidence, severity)
PATTERNS = [
    ("aws_access_key_id", r"AKIA[0-9A-Z]{16}", 95, "critical"),
    ("aws_secret_key_hint", r"aws_secret_access_key.{0,20}[A-Za-z0-9/+=]{30,}", 75, "critical"),
    ("github_token", r"gh[pousr]_[A-Za-z0-9]{36}", 95, "critical"),
    ("github_pat_legacy", r"github_pat_[A-Za-z0-9_]{22,}", 95, "critical"),
    ("stripe_secret_key", r"sk_(live|test)_[0-9A-Za-z]{16,}", 95, "critical"),
    ("stripe_restricted_key", r"rk_(live|test)_[0-9A-Za-z]{16,}", 90, "critical"),
    ("stripe_publishable", r"pk_(live|test)_[0-9A-Za-z]{16,}", 70, "medium"),
    ("google_api_key", r"AIza[0-9A-Za-z\-_]{35}", 90, "high"),
    ("google_oauth_secret", r"GOCSPX-[A-Za-z0-9\-_]{20,}", 90, "critical"),
    ("openai_key", r"sk-[A-Za-z0-9]{20,}", 80, "critical"),
    ("anthropic_key", r"sk-ant-[A-Za-z0-9\-_]{20,}", 90, "critical"),
    ("slack_token", r"xox[baprs]-[0-9A-Za-z\-]{10,}", 95, "critical"),
    ("slack_webhook", r"https://hooks\.slack\.com/services/[A-Z0-9/]+", 90, "high"),
    ("discord_webhook", r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+", 85, "high"),
    ("discord_bot_token", r"[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}", 85, "critical"),
    ("telegram_bot_token", r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}", 90, "high"),
    ("twilio_sid", r"AC[0-9a-f]{32}", 85, "high"),
    ("twilio_api_key", r"SK[0-9a-f]{32}", 90, "critical"),
    ("sendgrid_key", r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{30,}", 90, "critical"),
    ("mailgun_key", r"key-[0-9a-z]{32}", 85, "high"),
    ("firebase_fcm_key", r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{130,}", 90, "critical"),
    ("heroku_key", r"heroku[a-z]*.{0,10}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", 80, "critical"),
    ("digitalocean_token", r"dop_v1_[a-f0-9]{64}", 90, "critical"),
    ("npm_token", r"npm_[A-Za-z0-9]{36}", 90, "critical"),
    ("pypi_token", r"pypi-AgEI[A-Za-z0-9_\-]{20,}", 90, "critical"),
    ("shopify_token", r"shp[a-z]{2,4}_[A-Za-z0-9]{20,}", 85, "high"),
    ("shopify_shared", r"shpss_[a-f0-9]{32}", 85, "high"),
    ("square_token", r"sq0atp-[A-Za-z0-9_\-]{20,}", 90, "critical"),
    ("jwt_token", r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", 60, "medium"),
    ("private_key_block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", 99, "critical"),
    ("azure_conn_str", r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+", 90, "critical"),
    ("generic_api_key_assign", r"(?i)(?:api[_-]?key|apikey|client[_-]?secret|app[_-]?secret)\s*[:=]\s*['\"]([^'\"]{12,})['\"]", 65, "high"),
    ("generic_token_assign", r"(?i)(?:auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*['\"]([^'\"]{16,})['\"]", 65, "high"),
    ("sentry_dsn", r"https://[0-9a-f]{32}@[a-z0-9.\-]*sentry[a-z0-9.\-]*/\d+", 75, "medium"),
]

REMED_KEY = "api_key"


class SecretsPlugin(Plugin):
    id = "secrets"
    label = "Exposed API Keys"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Mine pages and JS bundles for 35+ API key and token patterns."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        seen = set()

        async def get_home():
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                                follow_redirects=True)
                return {"html": r.text[:500000], "url": str(r.url)}
            except Exception as e:
                return {"error": str(e)[:200]}

        home, _ = await ctx.cache.cached("http", f"secrets:{base}", get_home)
        if home.get("error"):
            res = self._degraded(f"fetch failed: {home['error']}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        html = home["html"]
        page_url = home["url"]

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
                source=f"secret scan: {where}", source_url=url,
                confidence=conf, passive=passive,
                evidence=evidence_block(m, name, REMED_KEY, severity)))

        for name, pat, conf, sev in PATTERNS:
            try:
                for m in re.finditer(pat, html):
                    val = m.group(1) if m.groups() and name.startswith("generic_") else m.group(0)
                    emit(name, val, "homepage HTML", conf, sev, page_url)
            except re.error:
                continue

        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        srcs = [s for s in srcs if not s.startswith("data:")][:25]
        for src in srcs:
            full = urljoin(page_url, src)
            host = urlparse(full).netloc
            if host and not host.endswith(domain):
                continue
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=20)
                if r.status_code != 200:
                    continue
                js = r.text[:800000]
            except Exception:
                continue
            for name, pat, conf, sev in PATTERNS:
                try:
                    for m in re.finditer(pat, js):
                        val = m.group(1) if m.groups() and name.startswith("generic_") else m.group(0)
                        emit(name, val, f"JS bundle {host or 'inline'}", conf, sev, full)
                except re.error:
                    continue

        dur = int((time.monotonic() - t0) * 1000)
        crit = sum(1 for f in findings if f.evidence and f.evidence.get("severity") == "critical")
        res = self._ok(findings,
                       f"scanned page + {len(srcs)} bundles, {len(findings)} secrets ({crit} critical)")
        res.duration_ms = dur
        return res
