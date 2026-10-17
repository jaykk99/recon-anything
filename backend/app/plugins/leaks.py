"""Identity / leaks plugin (Milestone 6).

- Breach exposure via HIBP (needs key, graceful skip).
- GitHub code search for the domain/org (needs token, graceful skip).
- Google/Bing dork generator (always works, builds the dork strings).
- Email pattern inference from MX + discovered names.
- Username enumeration across platforms (passive: known URL patterns).
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

DORKS = [
    'site:{d} ext:log | ext:txt | ext:conf | ext:cfg | ext:env | ext:ini',
    'site:{d} ext:sql | ext:db | ext:sqlite | ext:bak | ext:backup',
    'site:{d} inurl:admin | inurl:dashboard | inurl:panel | inurl:login',
    'site:{d} "index of"',
    'site:{d} filetype:pdf confidential',
    '"{d}" password | passwd | pwd',
    '"{d}" api_key | apikey | secret',
    '"{d}" "@gmail.com" OR "@yahoo.com" filetype:xls',
]

SOCIAL_PATTERNS = [
    ("github", "https://github.com/{u}"),
    ("twitter", "https://twitter.com/{u}"),
    ("instagram", "https://instagram.com/{u}"),
    ("linkedin", "https://linkedin.com/in/{u}"),
    ("facebook", "https://facebook.com/{u}"),
    ("tiktok", "https://tiktok.com/@{u}"),
    ("reddit", "https://reddit.com/user/{u}"),
    ("medium", "https://medium.com/@{u}"),
    ("gitlab", "https://gitlab.com/{u}"),
]


class LeaksPlugin(Plugin):
    id = "leaks"
    label = "Leaks + Identity"
    accepts = ["domain", "url", "email", "username", "person_or_company"]
    passive = True
    cost = Cost.FREEMIUM
    group = "identity"
    description = "Breach check, GitHub code search, dork generator, username enum."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List[Finding] = []

        if target.type == "email":
            await self._email_breach(target, ctx, findings)
        if target.type in ("username", "person_or_company"):
            self._username_enum(target, findings)
        domain = domain_from_target(target.type, target.normalized)
        if domain:
            self._dorks(domain, findings)
            await self._github_search(ctx, domain, findings)
        if not findings and target.type not in ("email", "username", "person_or_company"):
            return self._skipped("nothing applicable for this target type")

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"leak/identity checks for {target.normalized}")
        res.duration_ms = dur
        return res

    async def _email_breach(self, target: Target, ctx: Ctx, findings: List[Finding]):
        key = ctx.keys.get("hibp")
        if not key:
            findings.append(self._f("leak", "hibp_note",
                                    "HIBP check skipped: no HIBP_API_KEY configured",
                                    source="haveibeenpwned", confidence=50, passive=True))
            return
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(target.normalized)}"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url,
                            headers={"hibp-api-key": key, "User-Agent": "ReconAnything/1.0"},
                            timeout=20)
            if r.status_code == 200:
                for b in r.json():
                    name = b.get("Name", "?")
                    findings.append(self._f("leak", "breach",
                                            f"{name} ({b.get('BreachDate', '?')})",
                                            source="haveibeenpwned",
                                            source_url="https://haveibeenpwned.com/",
                                            confidence=90, passive=True))
            elif r.status_code == 404:
                findings.append(self._f("identity", "breach_clean",
                                        "no breaches found for this email",
                                        source="haveibeenpwned", confidence=80, passive=True))
            elif r.status_code == 429:
                findings.append(self._f("leak", "hibp_note", "HIBP rate limited",
                                        source="haveibeenpwned", confidence=40))
        except Exception as e:
            findings.append(self._f("leak", "hibp_note", f"HIBP error: {str(e)[:120]}",
                                    source="haveibeenpwned", confidence=40))

    async def _github_search(self, ctx: Ctx, domain: str, findings: List[Finding]):
        token = ctx.keys.get("github_token")
        if not token:
            findings.append(self._f("leak", "github_note",
                                    "GitHub code search skipped: no GITHUB_TOKEN configured",
                                    source="GitHub", confidence=50, passive=True))
            return
        url = f"https://api.github.com/search/code?q={quote(chr(34) + domain + chr(34))}&per_page=20"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url,
                            headers={"Authorization": f"Bearer {token}",
                                       "Accept": "application/vnd.github+json"},
                            timeout=25)
            if r.status_code == 200:
                items = r.json().get("items", [])
                for it in items[:20]:
                    repo = (it.get("repository") or {}).get("full_name", "?")
                    path = it.get("path", "?")
                    findings.append(self._f("leak", "github_hit",
                                            f"{repo}/{path}",
                                            source="GitHub code search",
                                            source_url=it.get("html_url"),
                                            confidence=70, passive=True))
            elif r.status_code in (401, 403):
                findings.append(self._f("leak", "github_note",
                                        f"GitHub API rejected the token (HTTP {r.status_code})",
                                        source="GitHub", confidence=50))
        except Exception as e:
            findings.append(self._f("leak", "github_note", f"GitHub error: {str(e)[:120]}",
                                    source="GitHub", confidence=40))

    def _dorks(self, domain: str, findings: List[Finding]):
        for d in DORKS:
            q = d.format(d=domain)
            findings.append(self._f("leak", "dork", q,
                                    source="dork generator",
                                    source_url="https://www.google.com/search?q=" + quote(q),
                                    confidence=60, passive=True))

    def _username_enum(self, target: Target, findings: List[Finding]):
        u = target.normalized.strip().lstrip("@")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{2,40}", u):
            return
        for name, pat in SOCIAL_PATTERNS:
            findings.append(self._f("identity", "profile_url", pat.format(u=u),
                                    source="username enum", source_url=pat.format(u=u),
                                    confidence=45, passive=True))
