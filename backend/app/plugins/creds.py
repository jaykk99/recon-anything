"""Hardcoded credential finder (Milestone: secret findings).

Hunts username/password pairs, database URLs with embedded creds,
basic-auth headers, framework secret keys and weak default logins in
public pages and JS. Read-only GETs. Findings are CRITICAL, redacted in
the value, full match in evidence with rotation advice. Authorized
testing only.
"""
from __future__ import annotations

import base64
import re
import time
from typing import List
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .secretutils import evidence_block, finding_value, is_placeholder, redact

PATTERNS = [
    # (name, regex, confidence, severity)
    ("db_url_mongo", r"mongodb(\+srv)?://([^:/\s]+):([^@/\s]+)@", 90, "critical"),
    ("db_url_postgres", r"postgres(?:ql)?://([^:/\s]+):([^@/\s]+)@", 90, "critical"),
    ("db_url_mysql", r"mysql://([^:/\s]+):([^@/\s]+)@", 90, "critical"),
    ("db_url_redis", r"redis://(?::([^@/\s]+)@)?", 75, "high"),
    ("ftp_creds", r"ftp://([^:/\s]+):([^@/\s]+)@", 90, "critical"),
    ("basic_auth_header", r"Authorization['\"]?\s*:\s*['\"]Basic ([A-Za-z0-9+/=]{12,})", 85, "high"),
    ("django_secret_key", r"SECRET_KEY\s*=\s*['\"]([^'\"]{20,})['\"]", 85, "critical"),
    ("laravel_app_key", r"APP_KEY=base64:([A-Za-z0-9+/=]{20,})", 85, "critical"),
    ("rails_secret", r"secret_key_base.{0,30}[\"']([a-f0-9]{32,})[\"']", 80, "high"),
    ("wp_salts", r"define\(\s*['\"](?:AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY)['\"]\s*,\s*['\"]([^'\"]{20,})['\"]", 80, "high"),
    ("htpasswd_bcrypt", r"(?m)^([a-zA-Z0-9_.\-]{2,40}):\$2[aby]\$[./A-Za-z0-9]{53}", 85, "high"),
    ("htpasswd_md5", r"(?m)^([a-zA-Z0-9_.\-]{2,40}):\$apr1\$[./A-Za-z0-9]{22}\$[./A-Za-z0-9]{22}", 85, "high"),
    ("password_assign", r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,120})['\"]", 60, "high"),
    ("userpass_pair", r"(?i)(?:user(?:name)?|login|email)\s*[:=]\s*['\"]([^'\"]{2,80})['\"].{0,60}?(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,120})['\"]", 75, "critical"),
]

# user:pass embedded in the pair pattern above is redacted as a unit.
WEAK_DEFAULTS = [
    (r"(?i)\badmin\b\s*[:=]\s*['\"]admin['\"]", "admin/admin"),
    (r"(?i)\badmin\b\s*[:=]\s*['\"]password['\"]", "admin/password"),
    (r"(?i)\broot\b\s*[:=]\s*['\"]root['\"]", "root/root"),
    (r"(?i)\bguest\b\s*[:=]\s*['\"]guest['\"]", "guest/guest"),
]

REMED_KEY = "credential"


class CredsPlugin(Plugin):
    id = "creds"
    label = "Hardcoded Credentials"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Find hardcoded logins, DB URLs, basic-auth and framework secrets."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized
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
                return {"error": str(e)[:200] or type(e).__name__}

        home, _ = await ctx.cache.cached("http", f"creds:{base}", get_home)
        if "error" in home:
            res = self._degraded(f"fetch failed: {home['error']}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        html = home["html"]
        page_url = home["url"]
        texts = [("homepage HTML", html, page_url)]

        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        srcs = [s for s in srcs if not s.startswith("data:")][:25]
        for src in srcs:
            full = urljoin(page_url, src)
            host = urlparse(full).netloc
            if host and not host.endswith(domain):
                continue
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=20)
                if r.status_code == 200:
                    texts.append((f"JS bundle {host or 'inline'}", r.text[:800000], full))
            except Exception:
                continue

        def emit(name: str, match: str, where: str, conf: int,
                 severity: str, url: str | None, remed: str = REMED_KEY):
            m = match.strip()[:300]
            if is_placeholder(m):
                return
            key = (name, m)
            if key in seen:
                return
            seen.add(key)
            findings.append(self._f(
                "leak", f"cred_{name}",
                finding_value(severity, name.replace("_", " "), redact(m), where),
                source=f"credential scan: {where}", source_url=url,
                confidence=conf, passive=passive,
                evidence=evidence_block(m, name, remed, severity)))

        for where, text, url in texts:
            for name, pat, conf, sev in PATTERNS:
                try:
                    for m in re.finditer(pat, text):
                        if name == "userpass_pair" and m.groups() and len(m.groups()) >= 2:
                            val = f"{m.group(1)}:{m.group(2)}"
                        elif name == "basic_auth_header":
                            try:
                                val = base64.b64decode(m.group(1)).decode("utf-8", "replace")[:120]
                            except Exception:
                                val = m.group(0)
                        elif m.groups():
                            val = m.group(1)
                        else:
                            val = m.group(0)
                        emit(name, val, where, conf, sev, url)
                except re.error:
                    continue
            for pat, label in WEAK_DEFAULTS:
                if re.search(pat, text):
                    emit("weak_default_login", label, where, 70, "high", url,
                         remed="default_cred")

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} credential findings")
        res.duration_ms = dur
        return res
