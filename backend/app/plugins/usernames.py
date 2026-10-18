"""Username checker plugin (Sherlock-style).

Checks if a username exists across popular platforms.
Custom-built, no API keys needed. Works for username targets.
"""
from __future__ import annotations

import time
from typing import List

from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# Platform -> URL template. We check for 200 + absence of "not found" markers.
PLATFORMS = [
    ("github", "https://github.com/{u}", ["Not Found", "404"], 85),
    ("twitter", "https://twitter.com/{u}", ["doesn\\u2019t exist"], 70),
    ("instagram", "https://www.instagram.com/{u}/", ["Sorry, this page"], 70),
    ("reddit", "https://www.reddit.com/user/{u}/", ["nobody on Reddit"], 75),
    ("youtube", "https://www.youtube.com/@{u}", ["404"], 60),
    ("tiktok", "https://www.tiktok.com/@{u}", ["Couldn't find"], 65),
    ("twitch", "https://www.twitch.tv/{u}", ["not available"], 70),
    ("medium", "https://medium.com/@{u}", ["404"], 65),
    ("devto", "https://dev.to/{u}", ["404"], 75),
    ("stackoverflow", "https://stackoverflow.com/users/", [], 40),
    ("gitlab", "https://gitlab.com/{u}", ["404"], 80),
    ("bitbucket", "https://bitbucket.org/{u}/", ["404"], 75),
    ("npm", "https://www.npmjs.com/~{u}", ["404"], 80),
    ("pypi", "https://pypi.org/user/{u}/", ["404"], 80),
    ("hackernews", "https://news.ycombinator.com/user?id={u}", ["No such user"], 80),
]


class UsernamesPlugin(Plugin):
    id = "usernames"
    label = "Username Checker"
    accepts = ["username"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = "Sherlock-style username existence check across platforms."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        username = target.normalized.strip().lstrip("@")
        if not username or len(username) < 2:
            return self._skipped("no username provided")
        findings: List[Finding] = []
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
                elif r.status_code == 404:
                    findings.append(self._f(
                        "identity", "username_not_found",
                        f"@{username} not on {plat} (404)",
                        source="username checker", source_url=url,
                        confidence=50, passive=True))
            except Exception:
                continue
        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"checked {len(PLATFORMS)} platforms")
        res.duration_ms = dur
        return res
