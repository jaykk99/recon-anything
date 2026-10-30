"""Deep JavaScript secret mining (aggressive detection, passive).

Fetches the homepage plus every same-domain JS bundle (inline scripts,
<script src>, crawler-discovered js_files), scans with 60+ secret
patterns (cloud keys, provider tokens, private keys, JWTs, generic
assignments), mines HTML comments for secrets, discovers source maps
(sourceMappingURL + .map guessing) and scans sourcesContent too.

GET only. Findings carry full values as found, plus
rotation remediation. Authorized testing only.
"""
from __future__ import annotations

import json
import re
import time
from typing import List, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .injutil import same_domain
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .secretutils import is_placeholder

# (pattern, label, severity) - full values shown in findings
SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID", "critical"),
    (r"aws_secret[^a-zA-Z0-9]{0,10}[\"']?([A-Za-z0-9/+=]{30,})[\"']?", "AWS secret key", "critical"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private key block", "critical"),
    (r"ghp_[A-Za-z0-9]{20,}", "GitHub personal token", "critical"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "GitHub fine-grained PAT", "critical"),
    (r"gho_[A-Za-z0-9]{20,}", "GitHub OAuth token", "critical"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token", "high"),
    (r"sk_live_[A-Za-z0-9]{16,}", "Stripe live secret key", "critical"),
    (r"rk_live_[A-Za-z0-9]{16,}", "Stripe restricted key", "high"),
    (r"pk_live_[A-Za-z0-9]{16,}", "Stripe publishable key", "medium"),
    (r"AIza[0-9A-Za-z_-]{35}", "Google API key", "high"),
    (r"ya29\.[0-9A-Za-z_-]{20,}", "Google OAuth token", "high"),
    (r"sk-[A-Za-z0-9]{32,}", "OpenAI-style API key", "high"),
    (r"sk-ant-[A-Za-z0-9-]{20,}", "Anthropic API key", "high"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT", "high"),
    (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP private key", "critical"),
    (r"mongodb(\+srv)?://[^\"'\\s]{8,}", "MongoDB connection string", "critical"),
    (r"postgres(ql)?://[^\"'\\s]{8,}", "Postgres connection string", "critical"),
    (r"mysql://[^\"'\\s]{8,}", "MySQL connection string", "critical"),
    (r"redis://[^\"'\\s]{8,}", "Redis connection string", "high"),
    (r"amqp://[^\"'\\s]{8,}", "AMQP connection string", "high"),
    (r"-----BEGIN CERTIFICATE-----[^-]{50}", "certificate block", "medium"),
    (r"ssh-rsa AAAA[0-9A-Za-z+/]{20,}", "SSH public key", "medium"),
    (r"discord[_-]?token[\"']?\s*[:=]\s*[\"'][A-Za-z0-9._-]{20,}[\"']", "Discord token", "high"),
    (r"telegram[_-]?bot[_-]?token[\"']?\s*[:=]\s*[\"'][0-9]+:[A-Za-z0-9_-]{20,}[\"']", "Telegram bot token", "high"),
    (r"twilio[_-]?account[_-]?sid[\"']?\s*[:=]\s*[\"']AC[a-f0-9]{32}[\"']", "Twilio SID", "high"),
    (r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", "SendGrid API key", "high"),
    (r"key-[A-Za-z0-9]{32}", "Mailgun API key", "high"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key ID", "critical"),
    (r"heroku[a-z0-9]{32}", "Heroku API key", "high"),
    (r"npm_[A-Za-z0-9]{24,}", "npm token", "high"),
    (r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}", "PyPI token", "high"),
    (r"glpat-[A-Za-z0-9_-]{20,}", "GitLab PAT", "high"),
    (r"sq0atp-[A-Za-z0-9_-]{20,}", "Square token", "high"),
    (r"live_[A-Za-z0-9]{24,}", "generic live secret", "high"),
    (r"secret[_-]?key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_./+=~-]{16,})[\"']", "secret_key assignment", "high"),
    (r"api[_-]?key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_./+=~-]{16,})[\"']", "api_key assignment", "high"),
    (r"apikey[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_./+=~-]{16,})[\"']", "apikey assignment", "high"),
    (r"client[_-]?secret[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_./+=~-]{12,})[\"']", "client_secret assignment", "high"),
    (r"auth[_-]?token[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_./+=~-]{16,})[\"']", "auth token assignment", "high"),
    (r"access[_-]?token[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_./+=~-]{16,})[\"']", "access token assignment", "high"),
    (r"private[_-]?key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_./+=~-]{16,})[\"']", "private_key assignment", "high"),
    (r"db[_-]?password[\"']?\s*[:=]\s*[\"']([^\"']{6,})[\"']", "DB password", "high"),
    (r"password[\"']?\s*[:=]\s*[\"']([^\"'\\s]{8,})[\"']", "password assignment", "medium"),
    (r"passwd[\"']?\s*[:=]\s*[\"']([^\"'\\s]{8,})[\"']", "passwd assignment", "medium"),
    (r"pwd[\"']?\s*[:=]\s*[\"']([^\"'\\s]{8,})[\"']", "pwd assignment", "medium"),
    (r"bearer [A-Za-z0-9._~-]{20,}", "bearer token", "high"),
    (r"basic [A-Za-z0-9+/=]{20,}", "basic auth credential", "high"),
    (r"-----BEGIN EC PRIVATE KEY-----", "EC private key", "critical"),
    (r"-----BEGIN DSA PRIVATE KEY-----", "DSA private key", "critical"),
    (r"-----BEGIN OPENSSH PRIVATE KEY-----", "OpenSSH private key", "critical"),
    (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP private key", "critical"),
    (r"stripe[_-]?secret[_-]?key[\"']?\s*[:=]\s*[\"'](sk_[a-z]+_[A-Za-z0-9]{10,})[\"']", "Stripe secret key", "critical"),
    (r"webhook[_-]?secret[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_./+=~-]{12,})[\"']", "webhook secret", "high"),
    (r"signing[_-]?secret[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_./+=~-]{12,})[\"']", "signing secret", "high"),
    (r"encryption[_-]?key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_./+=~-]{16,})[\"']", "encryption key", "high"),
    (r"private[_-]?token[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_./+=~-]{12,})[\"']", "private token", "high"),
    (r"session[_-]?secret[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_./+=~-]{12,})[\"']", "session secret", "high"),
    (r"jwt[_-]?secret[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_./+=~-]{12,})[\"']", "JWT secret", "high"),
    (r"datadog[_-]?api[_-]?key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9]{32})[\"']", "Datadog API key", "high"),
    (r"newrelic[_-]?api[_-]?key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9]{40})[\"']", "New Relic key", "high"),
    (r"sentry[_-]?dsn[\"']?\s*[:=]\s*[\"'](https://[^\"']+)[\"']", "Sentry DSN", "medium"),
    (r"firebase[_-]?api[_-]?key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9_-]{30,})[\"']", "Firebase key", "medium"),
    (r"algolia[_-]?api[_-]?key[\"']?\s*[:=]\s*[\"']([A-Za-z0-9]{32})[\"']", "Algolia key", "medium"),
    (r"cloudinary://[0-9]+:[A-Za-z0-9_-]+@[A-Za-z0-9_-]+", "Cloudinary URL", "high"),
    (r"ftp://[^\"'\\s]{6,}", "FTP URL with creds?", "medium"),
]

# words that mark an obvious placeholder/example, not a real secret
PLACEHOLDER_HINTS = ("example", "placeholder", "changeme", "your-", "xxx",
                     "test123", "abcdef", "123456", "todo", "sample")


class JsSecretsPlugin(Plugin):
    id = "js_secrets"
    label = "JS Secret Miner"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Deep JS/HTML secret mining: 60+ patterns over every JS "
                   "bundle, inline scripts, HTML comments, and source maps.")

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
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                            follow_redirects=True)
            html = r.text[:500000]
            page_url = str(r.url)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        texts: List[Tuple[str, str, str]] = []  # (text, source_url, kind)

        # 1. HTML comments on the homepage
        for cm in re.finditer(r"<!--(.*?)-->", html, re.S):
            c = cm.group(1).strip()
            if 8 < len(c) < 4000:
                texts.append((c, page_url, "HTML comment"))

        # 2. inline scripts
        for sm in re.finditer(
                r"<script(?![^>]+src=)[^>]*>(.*?)</script>", html, re.I | re.S):
            body = sm.group(1).strip()
            if len(body) > 20:
                texts.append((body[:500000], page_url, "inline script"))

        # 3. external scripts (same-domain + crawler bus)
        js_urls: Set[str] = set()
        for sm in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            full = urljoin(page_url, sm.group(1))
            if same_domain(full, domain):
                js_urls.add(full)
        for ju in ctx.consume("js_files"):
            if isinstance(ju, str) and domain in urlparse(ju).netloc:
                js_urls.add(ju)

        # 4. fetch bundles + discover source maps
        map_urls: Set[str] = set()
        for ju in sorted(js_urls)[:15]:
            try:
                jr = await fetch(ctx.http, ctx.limiter, "GET", ju, timeout=15)
                if jr.status_code != 200:
                    continue
                js = jr.text[:1000000]
                texts.append((js, ju, "JS bundle"))
                sm = re.search(r"//# sourceMappingURL=(\S+)", js)
                if sm:
                    map_urls.add(urljoin(ju, sm.group(1).strip()))
                elif ju.endswith(".js"):
                    map_urls.add(ju + ".map")  # guess
            except Exception:
                continue

        # 5. fetch + mine source maps (sourcesContent often has secrets)
        for mu in sorted(map_urls)[:8]:
            try:
                mr = await fetch(ctx.http, ctx.limiter, "GET", mu, timeout=15)
                if mr.status_code != 200:
                    continue
                try:
                    smap = json.loads(mr.text[:3000000])
                except Exception:
                    continue
                blob = mr.text[:1000000]
                texts.append((blob, mu, "source map"))
                for src_content in (smap.get("sourcesContent") or [])[:50]:
                    if isinstance(src_content, str) and len(src_content) > 20:
                        texts.append((src_content[:500000], mu,
                                      "source map original source"))
            except Exception:
                continue

        # 6. pattern scan
        seen: Set[str] = set()
        for text, src_url, kind in texts:
            for pat, label, sev in SECRET_PATTERNS:
                for m in re.finditer(pat, text):
                    raw = m.group(1) if m.lastindex else m.group(0)
                    if not raw or is_placeholder(raw):
                        continue
                    low = raw.lower()
                    if any(h in low for h in PLACEHOLDER_HINTS):
                        continue
                    if len(raw) > 400:
                        continue
                    sig = (label, raw[:24])
                    if sig in seen:
                        continue
                    seen.add(sig)
                    findings.append(self._f(
                        "leak", "js_secret",
                        f"{sev.upper()}: {label} exposed in {kind} "
                        f"({raw})",
                        source=f"JS secret mining ({kind})",
                        source_url=src_url,
                        confidence=80 if sev in ("critical", "high") else 65,
                        passive=passive,
                        evidence={"severity": sev,
                                  "secret_type": label,
                                  "full_value": raw,
                                  "where": kind,
                                  "remediation": ("Rotate this secret immediately "
                                                  "at the provider, then remove "
                                                  "it from client-side code. "
                                                  "Move it server-side."),
                                  "scope_note": "Full value shown. Rotate "
                                                "immediately; never ship "
                                                "secrets client-side."}))
                    if len(findings) >= 40:
                        break
                if len(findings) >= 40:
                    break
            if len(findings) >= 40:
                break

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"mined {len(texts)} texts ({len(js_urls)} JS files), "
                       f"{len(findings)} secrets")
        res.duration_ms = dur
        return res
