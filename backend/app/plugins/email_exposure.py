"""Exposed credential hunter (defensive OSINT only).

Finds credentials tied to the target that are ALREADY PUBLIC:

- GitHub code search for the domain + credential keywords (needs
  GITHUB_TOKEN in ctx.keys as "github_token"; skipped gracefully when
  missing). Read-only API search, never clones private repos.
- Scylla.sh public compilation search for emails on this domain.
- Live probes for exposed config files on the target itself
  (/.env, wp-config backups, .git/config) via the shared probe cache.
  Only flagged when the content actually contains secret-looking values.

Never attempts logins, never brute-forces, never touches anything that
is not already public. Secrets are redacted in the finding value; the
full match sits in evidence["match"] so the owner can verify and rotate.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .secretutils import evidence_block, is_placeholder, redact

# GitHub code-search queries (quoted). Rate-limited to a few per run.
GH_QUERIES = [
    '"{d}" password',
    '"{d}" db_password',
    '"{d}" api_key',
    'filename:.env "{d}"',
    '"{d}" smtp_password',
]

# Paste / compilation aggregator (public, no key).
SCYLLA_URL = "https://scylla.sh/search?q=email:*@{d}&size=50"

# Config paths probed on the target itself (active mode only). Flagged
# only when the body looks like it holds real secrets.
CONFIG_PATHS = [
    "/.env", "/.env.bak", "/.env.old", "/.env.production",
    "/config.php", "/config.php.bak", "/wp-config.php.bak",
    "/.git/config", "/database.yml", "/settings.py.bak",
]

SECRET_HINT = re.compile(
    r"(?i)(password|passwd|pwd|secret|api[_-]?key|db[_-]?pass|smtp[_-]?pass)"
    r"\s*[:=]\s*['\"]?([^'\"\s&;]{4,80})",
    re.M,
)
# Marker that the probe hit a real .env / config, not a 404 page.
ENV_MARKER = re.compile(r"(?i)(APP_KEY=|DB_HOST=|DATABASE_URL=|SECRET_KEY=)")


class EmailExposurePlugin(Plugin):
    id = "email_exposure"
    label = "Exposed Credentials"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "identity"
    description = ("Hunt publicly exposed credentials for the target: "
                   "GitHub code search, paste compilations, exposed "
                   ".env/config files.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        await self._github_search(domain, ctx, findings)
        await self._scylla(domain, ctx, findings)
        if not passive:
            await self._config_probes(domain, target, ctx, findings)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"{len(findings)} public credential exposures for {domain}")
        res.duration_ms = dur
        return res

    async def _github_search(self, domain: str, ctx: Ctx,
                             findings: List[Finding]) -> None:
        token = ctx.keys.get("github_token")
        if not token:
            findings.append(self._f(
                "leak", "github_note",
                "GitHub code search skipped: no GITHUB_TOKEN configured "
                "(add it in Keys to hunt exposed credentials in public code)",
                source="GitHub", confidence=50, passive=True,
                evidence=evidence_block("", "gh_no_token", "credential", "low")))
            return
        for q in GH_QUERIES:
            url = ("https://api.github.com/search/code?q="
                   + quote(q.format(d=domain)) + "&per_page=10")
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25,
                                headers={"Authorization": f"Bearer {token}",
                                         "Accept": "application/vnd.github+json"})
            except Exception as e:
                findings.append(self._f(
                    "leak", "github_note",
                    f"GitHub search error: {str(e)[:120]}",
                    source="GitHub", confidence=40, passive=True,
                    evidence=evidence_block("", "gh_error", "credential", "low")))
                return
            if r.status_code in (401, 403):
                findings.append(self._f(
                    "leak", "github_note",
                    f"GitHub API rejected the token (HTTP {r.status_code})",
                    source="GitHub", confidence=50, passive=True,
                    evidence=evidence_block("", "gh_auth", "credential", "low")))
                return
            if r.status_code != 200:
                continue
            try:
                items = r.json().get("items", [])
            except Exception:
                continue
            for it in items:
                repo = (it.get("repository") or {}).get("full_name", "?")
                path = it.get("path", "?")
                value = (f"Public code hit for credential query "
                         f"'{q.format(d=domain)}': {repo}/{path}")
                ev = evidence_block(path, "gh_credential_dork", "credential",
                                    "high",
                                    {"repo": repo, "query": q.format(d=domain)})
                findings.append(self._f(
                    "leak", "github_credential_hit", value,
                    source="GitHub code search",
                    source_url=it.get("html_url"), confidence=70,
                    passive=True, evidence=ev))
            # GitHub code search: 10 req/min authenticated. Stop if the
            # bucket is empty so we never burn the whole budget.
            if r.headers.get("x-ratelimit-remaining") == "0":
                findings.append(self._f(
                    "leak", "github_note",
                    "GitHub code-search rate limit reached; "
                    "remaining queries skipped",
                    source="GitHub", confidence=40, passive=True,
                    evidence=evidence_block("", "gh_429", "credential",
                                            "low")))
                break

    async def _scylla(self, domain: str, ctx: Ctx,
                      findings: List[Finding]) -> None:
        url = SCYLLA_URL.format(d=domain)
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25)
        except Exception:
            return
        if r.status_code != 200:
            return
        try:
            hits = r.json().get("hits") or r.json().get("data") or []
        except Exception:
            return
        seen = set()
        for h in hits[:20]:
            email = str(h.get("email") or h.get("_source", {}).get("email") or "")
            if "@" not in email or not email.lower().endswith("@" + domain):
                continue
            if email in seen:
                continue
            seen.add(email)
            fields = h.get("fields") or {}
            value = (f"{redact(email, 6)} appears in a public breach "
                     f"compilation (fields seen: "
                     f"{', '.join(list(fields)[:6]) or 'email only'})")
            ev = evidence_block(email, "scylla_compilation", "credential",
                                "high", {"fields": list(fields)[:10]})
            findings.append(self._f(
                "leak", "compilation_exposure", value,
                source="Scylla public compilations", confidence=75,
                passive=True, evidence=ev))

    async def _config_probes(self, domain: str, target: Target, ctx: Ctx,
                             findings: List[Finding]) -> None:
        base = (await web_base(ctx, target, domain)).rstrip("/")
        for path in CONFIG_PATHS:
            url = base + path
            try:
                data = await ctx.probe(url, timeout=8)
            except Exception:
                continue
            if data.get("status") != 200:
                continue
            body = data.get("text", "")
            if len(body) < 20:
                continue
            if not ENV_MARKER.search(body):
                continue
            secrets: Dict[str, str] = {}
            for m in SECRET_HINT.finditer(body):
                name, val = m.group(1).lower(), m.group(2)
                if is_placeholder(val) or len(val) < 4:
                    continue
                secrets[name] = redact(val)
            if not secrets and "APP_KEY" not in body and "SECRET_KEY" not in body:
                continue
            detail = ", ".join(f"{k}={v}" for k, v in list(secrets.items())[:5])
            value = (f"HIGH: exposed config file {path} on {domain} "
                     f"contains secrets ({detail or 'secret markers'})")
            ev = evidence_block(detail or path, "exposed_config", "credential",
                                "high", {"path": path, "url": url})
            findings.append(self._f(
                "leak", "exposed_config", value, source="config probe",
                source_url=url, confidence=90, passive=False, evidence=ev))
