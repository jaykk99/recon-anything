"""Username checker plugin (Sherlock-style).

Checks if a username exists across popular platforms. Custom-built,
no API keys needed.

Works two ways:
- username target: checks that username directly.
- domain/url target: harvests candidate usernames from the site
  (email local-parts, author names, org name) then checks those.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

PLATFORMS = [
    ("github", "https://github.com/{u}", ["Not Found"], 85),
    ("twitter", "https://twitter.com/{u}", ["doesn\u2019t exist", "not found"], 70),
    ("instagram", "https://www.instagram.com/{u}/", ["Sorry, this page"], 70),
    ("reddit", "https://www.reddit.com/user/{u}/", ["nobody on Reddit"], 75),
    ("youtube", "https://www.youtube.com/@{u}", ["404"], 60),
    ("tiktok", "https://www.tiktok.com/@{u}", ["Couldn't find"], 65),
    ("twitch", "https://www.twitch.tv/{u}", ["not available"], 70),
    ("medium", "https://medium.com/@{u}", ["404"], 65),
    ("devto", "https://dev.to/{u}", ["404"], 75),
    ("gitlab", "https://gitlab.com/{u}", ["404"], 80),
    ("bitbucket", "https://bitbucket.org/{u}/", ["404"], 75),
    ("npm", "https://www.npmjs.com/~{u}", ["404"], 80),
    ("pypi", "https://pypi.org/user/{u}/", ["404"], 80),
    ("hackernews", "https://news.ycombinator.com/user?id={u}", ["No such user"], 80),
]

EMAIL_RE = re.compile(r"([a-zA-Z0-9._%+\-]{2,40})@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24})")
AUTHOR_RE = re.compile(
    r"(?i)(?:author|by)[\"'\s:=]+([A-Za-z][A-Za-z0-9_.\-]{2,30})")

GENERIC_LOCALS = {"info", "contact", "support", "admin", "hello", "mail",
                  "sales", "help", "noreply", "no-reply", "webmaster",
                  "postmaster", "abuse", "team"}


class UsernamesPlugin(Plugin):
    id = "usernames"
    label = "Username Checker"
    accepts = ["username", "domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = "Sherlock-style username check; harvests candidates from sites."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List[Finding] = []
        candidates: List[str] = []

        if target.type == "username":
            u = target.normalized.strip().lstrip("@")
            if len(u) >= 2:
                candidates = [u]
        else:
            domain = domain_from_target(target.type, target.normalized)
            if not domain:
                return self._skipped("no domain for this target type")
            base = f"https://{domain}" if target.type == "domain" else target.normalized
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                                follow_redirects=True)
                html = r.text[:400000]
            except Exception as e:
                res = self._error(f"fetch failed: {str(e)[:200]}")
                res.duration_ms = int((time.monotonic() - t0) * 1000)
                return res
            seen = set()
            for m in EMAIL_RE.finditer(html):
                local = m.group(1).lower()
                if local not in GENERIC_LOCALS and len(local) >= 3:
                    seen.add(local)
            for m in AUTHOR_RE.finditer(html[:100000]):
                seen.add(m.group(1).lower())
            # org name as a candidate handle
            seen.add(domain.split(".")[0].lower())
            candidates = sorted(seen)[:8]
            if candidates:
                findings.append(self._f(
                    "identity", "username_candidates",
                    f"Harvested {len(candidates)} username candidates from {domain}: "
                    f"{', '.join(candidates)}",
                    source="site harvesting", confidence=80, passive=True))

        if not candidates:
            res = self._ok(findings, "no username candidates found")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        for username in candidates:
            for plat, template, not_found_markers, conf in PLATFORMS:
                url = template.format(u=username)
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=12)
                    body = r.text[:5000].lower()
                    is_not_found = any(m.lower() in body for m in not_found_markers)
                    if r.status_code == 200 and not is_not_found:
                        findings.append(self._f(
                            "identity", "username_found",
                            f"@{username} exists on {plat}",
                            source="username checker", source_url=url,
                            confidence=conf, passive=True))
                except Exception:
                    continue

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"checked {len(candidates)} username(s) on {len(PLATFORMS)} platforms")
        res.duration_ms = dur
        return res
