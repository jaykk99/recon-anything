"""Exposed API key finder (Milestone: secret findings).

Scans the homepage HTML and every first-party JS bundle for 90+ API key
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
    # Broader patterns: catch more variants
    ("aws_session_token", r"ASIA[0-9A-Z]{16}", 90, "critical"),
    ("gcp_service_account", r"\"type\"\s*:\s*\"service_account\"", 85, "critical"),
    ("azure_client_secret", r"(?i)(?:client[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9~_.\-]{20,}['\"]", 70, "high"),
    ("openai_org", r"org-[A-Za-z0-9]{20,}", 60, "medium"),
    ("algolia_key", r"(?i)algolia.{0,30}['\"][A-Za-z0-9]{20,}['\"]", 60, "medium"),
    ("mapbox_token", r"pk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}", 65, "medium"),
    ("firebase_config", r"\"apiKey\"\s*:\s*\"AIza[A-Za-z0-9\-_]{35}\"", 75, "high"),
    # ===================================================================
    # Expanded provider coverage (2026-10-27). High-signal, prefix-anchored
    # token patterns - more secret TYPES caught means more crown-jewel
    # findings. Bounded quantifiers only (no catastrophic backtracking).
    # ===================================================================
    # -- source control / packages ---
    ("gitlab_pat", r"glpat-[A-Za-z0-9_\-]{20}", 95, "critical"),
    ("gitlab_pipeline_token", r"glptt-[0-9a-f]{40}", 90, "critical"),
    ("gitlab_runner_token", r"GR1348941[A-Za-z0-9_\-]{20}", 90, "critical"),
    ("github_oauth", r"gho_[A-Za-z0-9]{36}", 95, "critical"),
    ("github_app_token", r"(?:ghu|ghs)_[A-Za-z0-9]{36}", 95, "critical"),
    ("docker_hub_pat", r"dckr_pat_[A-Za-z0-9_\-]{27,}", 90, "critical"),
    ("hashicorp_vault", r"hvs\.[A-Za-z0-9_\-]{90,}", 90, "critical"),
    ("hashicorp_vault_batch", r"hvb\.[A-Za-z0-9_\-]{90,}", 85, "critical"),
    # -- cloud / infra ---
    ("gcp_oauth_refresh", r"1//0[A-Za-z0-9_\-]{30,}", 70, "high"),
    ("digitalocean_pat", r"dop_v1_[a-f0-9]{64}", 90, "critical"),
    ("digitalocean_oauth", r"doo_v1_[a-f0-9]{64}", 90, "critical"),
    ("cloudflare_api_token", r"(?i)cloudflare.{0,20}['\"][A-Za-z0-9_\-]{40}['\"]", 70, "high"),
    ("cloudflare_global_key", r"(?i)(?:cf[_-]?api[_-]?key|x-auth-key).{0,10}['\"][0-9a-f]{37}['\"]", 75, "high"),
    ("linode_token", r"(?i)linode.{0,20}['\"][0-9a-f]{64}['\"]", 70, "high"),
    ("fastly_token", r"(?i)fastly.{0,20}['\"][A-Za-z0-9_\-]{32}['\"]", 65, "medium"),
    ("terraform_cloud", r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}", 90, "critical"),
    # -- databases / backends ---
    ("mongodb_srv_uri", r"mongodb(?:\+srv)?://[^\s:@]+:[^\s:@]+@[A-Za-z0-9.\-]+", 90, "critical"),
    ("postgres_uri", r"postgres(?:ql)?://[^\s:@]+:[^\s:@]+@[A-Za-z0-9.\-]+", 90, "critical"),
    ("mysql_uri", r"mysql://[^\s:@]+:[^\s:@]+@[A-Za-z0-9.\-]+", 90, "critical"),
    ("redis_uri", r"redis(?:s)?://[^\s:@]*:[^\s:@]+@[A-Za-z0-9.\-]+", 85, "critical"),
    ("amqp_uri", r"amqps?://[^\s:@]+:[^\s:@]+@[A-Za-z0-9.\-]+", 80, "high"),
    ("supabase_service_key", r"(?i)supabase.{0,30}(eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})", 70, "high"),
    ("planetscale_token", r"pscale_tkn_[A-Za-z0-9_\-]{32,}", 90, "critical"),
    ("planetscale_password", r"pscale_pw_[A-Za-z0-9_\-]{32,}", 90, "critical"),
    # -- deploy / PaaS ---
    ("vercel_token", r"(?i)vercel.{0,20}['\"][A-Za-z0-9]{24}['\"]", 65, "high"),
    ("netlify_token", r"(?i)netlify.{0,20}['\"][A-Za-z0-9_\-]{40,}['\"]", 65, "high"),
    ("railway_token", r"(?i)railway.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", 65, "high"),
    # -- auth / identity ---
    ("okta_token", r"00[A-Za-z0-9_\-]{40}", 55, "medium"),
    ("auth0_client_secret", r"(?i)auth0.{0,30}['\"][A-Za-z0-9_\-]{40,}['\"]", 65, "high"),
    ("jwt_secret_assign", r"(?i)jwt[_-]?secret\s*[:=]\s*['\"]([^'\"]{12,})['\"]", 70, "high"),
    # -- payments ---
    ("braintree_token", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", 90, "critical"),
    ("paypal_client", r"(?i)(?:paypal|client_id).{0,10}['\"]A[A-Za-z0-9_\-]{79}['\"]", 55, "medium"),
    ("razorpay_key", r"rzp_(?:live|test)_[A-Za-z0-9]{14,}", 85, "high"),
    ("paystack_secret", r"sk_(?:live|test)_[0-9a-f]{40}", 85, "critical"),
    ("adyen_key", r"(?i)adyen.{0,20}['\"]AQE[A-Za-z0-9+/]{40,}['\"]", 70, "high"),
    # -- comms / marketing ---
    ("mailchimp_key", r"[0-9a-f]{32}-us[0-9]{1,2}", 85, "high"),
    ("postmark_token", r"(?i)postmark.{0,20}['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]", 70, "high"),
    ("pusher_key", r"(?i)pusher.{0,30}['\"][0-9a-f]{20}['\"]", 60, "medium"),
    ("vonage_secret", r"(?i)(?:nexmo|vonage).{0,20}['\"][A-Za-z0-9]{16}['\"]", 60, "medium"),
    ("intercom_token", r"dG9r[A-Za-z0-9+/=]{50,}", 60, "medium"),
    # -- observability ---
    ("datadog_api_key", r"(?i)datadog.{0,20}['\"][0-9a-f]{32}['\"]", 65, "high"),
    ("newrelic_key", r"NRAK-[A-Z0-9]{27}", 90, "high"),
    ("newrelic_license", r"(?i)(?:newrelic|new_relic).{0,20}['\"][A-Za-z0-9]{40}['\"]", 65, "medium"),
    ("rollbar_token", r"(?i)rollbar.{0,20}['\"][0-9a-f]{32}['\"]", 60, "medium"),
    # -- productivity / SaaS ---
    ("notion_token", r"(?:secret_|ntn_)[A-Za-z0-9]{36,}", 85, "high"),
    ("airtable_key", r"key[A-Za-z0-9]{14}", 55, "medium"),
    ("airtable_pat", r"pat[A-Za-z0-9]{14}\.[0-9a-f]{64}", 90, "high"),
    ("asana_pat", r"(?i)asana.{0,20}['\"][0-9]/[0-9]{16}:[A-Za-z0-9]{32}['\"]", 70, "high"),
    ("figma_token", r"figd_[A-Za-z0-9_\-]{40,}", 85, "high"),
    ("dropbox_token", r"sl\.[A-Za-z0-9_\-]{130,}", 85, "critical"),
    # -- web3 / finance APIs ---
    ("alchemy_key", r"(?i)alchemy.{0,30}['\"][A-Za-z0-9_\-]{32}['\"]", 60, "medium"),
    ("infura_project", r"(?i)infura\.io/v3/[0-9a-f]{32}", 70, "high"),
    ("etherscan_key", r"(?i)etherscan.{0,20}['\"][A-Z0-9]{34}['\"]", 60, "medium"),
    ("coinbase_key", r"(?i)coinbase.{0,20}['\"][A-Za-z0-9]{16,64}['\"]", 55, "medium"),
    # -- generic high-signal connection strings / passwords ---
    ("basic_auth_url", r"https?://[A-Za-z0-9._%\-]+:[^\s:@/]{3,}@[A-Za-z0-9.\-]+", 80, "high"),
    ("password_assign", r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]", 55, "medium"),
    ("db_password_assign", r"(?i)(?:db[_-]?pass(?:word)?|database[_-]?password)\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]", 70, "high"),
    ("smtp_password", r"(?i)smtp[_-]?pass(?:word)?\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]", 70, "high"),
]

REMED_KEY = "api_key"


class SecretsPlugin(Plugin):
    id = "secrets"
    label = "Exposed API Keys"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Mine pages and JS bundles for 90+ API key and token patterns."

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
                # Shared homepage cache: first plugin pays, the rest read from cache.
                page = await ctx.fetch_page(base, timeout=25)
                if page is None:
                    raise RuntimeError("homepage fetch failed")
                return {"html": page["text"][:500000], "url": page["url"]}
            except Exception as e:
                return {"error": str(e)[:200] or type(e).__name__}

        home, _ = await ctx.cache.cached("http", f"secrets:{base}", get_home)
        if "error" in home:
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
                    val = m.group(1) if m.groups() else m.group(0)
                    emit(name, val, "homepage HTML", conf, sev, page_url)
            except re.error:
                continue

        # Inline <script>...</script> blocks: secrets baked into the page's
        # own JS, not just external bundles. Scan every inline block.
        for block in re.findall(r"<script\b[^>]*>(.*?)</script>", html,
                                re.I | re.S):
            if len(block) < 12:
                continue
            for name, pat, conf, sev in PATTERNS:
                try:
                    for m in re.finditer(pat, block):
                        val = m.group(1) if m.groups() else m.group(0)
                        emit(name, val, "inline script", conf, sev, page_url)
                except re.error:
                    continue

        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        # Raised 2026-10-27 (Jay: find ALL of it) from 25 -> 60 bundles.
        srcs = [s for s in srcs if not s.startswith("data:")][:60]
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
                        val = m.group(1) if m.groups() else m.group(0)
                        emit(name, val, f"JS bundle {host or 'inline'}", conf, sev, full)
                except re.error:
                    continue
            # Check for source maps: append .map to JS URLs
            try:
                map_url = full + ".map"
                mr = await fetch(ctx.http, ctx.limiter, "GET", map_url, timeout=10)
                if mr.status_code == 200 and "sourcesContent" in mr.text[:5000]:
                    for name, pat, conf, sev in PATTERNS:
                        try:
                            for m in re.finditer(pat, mr.text[:500000]):
                                val = m.group(1) if m.groups() else m.group(0)
                                emit(name, val, f"source map {host or 'inline'}", conf, sev, map_url)
                        except re.error:
                            continue
                    findings.append(self._f(
                        "leak", "sourcemap_exposed",
                        f"HIGH: source map exposed at {map_url} - contains original source code",
                        source="source map check", source_url=map_url,
                        confidence=85, passive=passive,
                        evidence={"severity": "high",
                                  "remediation": "Remove .map files from production or restrict access."}))
            except Exception:
                pass

        # Scan HTML comments for secrets
        comments = re.findall(r"<!--(.*?)-->", html, re.S)
        for comment in comments[:120]:
            if len(comment.strip()) < 10:
                continue
            for name, pat, conf, sev in PATTERNS:
                try:
                    for m in re.finditer(pat, comment):
                        val = m.group(1) if m.groups() else m.group(0)
                        emit(name, val, "HTML comment", conf, sev, page_url)
                except re.error:
                    continue

        # Scan meta tags for secrets
        metas = re.findall(r'<meta[^>]+content=["\']([^"\']{20,})["\']', html, re.I)
        for meta in metas[:60]:
            for name, pat, conf, sev in PATTERNS:
                try:
                    for m in re.finditer(pat, meta):
                        val = m.group(1) if m.groups() else m.group(0)
                        emit(name, val, "meta tag", conf, sev, page_url)
                except re.error:
                    continue

        dur = int((time.monotonic() - t0) * 1000)
        crit = sum(1 for f in findings if f.evidence and f.evidence.get("severity") == "critical")
        res = self._ok(findings,
                       f"scanned page + {len(srcs)} bundles, {len(findings)} secrets ({crit} critical)")
        res.duration_ms = dur
        return res
