"""Social media footprint plugin.

Finds social media accounts associated with a domain or username.
Checks common platforms and generates profile URLs.
Custom-built, no API keys needed.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class SocialPlugin(Plugin):
    id = "social"
    label = "Social Footprint"
    accepts = ["domain", "url", "username", "person_or_company"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = "Find associated social media accounts."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List[Finding] = []

        if target.type in ("domain", "url"):
            domain = domain_from_target(target.type, target.normalized)
            if not domain:
                return self._skipped("no domain")
            base = (await web_base(ctx, target, domain)).rstrip("/")

            # Scrape homepage for social links
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=15)
                if r.status_code == 200:
                    import re
                    social_patterns = [
                        (r'https?://(?:www\.)?facebook\.com/([A-Za-z0-9._-]+)',
                         "Facebook", 85),
                        (r'https?://(?:www\.)?instagram\.com/([A-Za-z0-9._-]+)',
                         "Instagram", 85),
                        (r'https?://(?:www\.)?twitter\.com/([A-Za-z0-9_]+)',
                         "Twitter", 85),
                        (r'https?://(?:www\.)?x\.com/([A-Za-z0-9_]+)',
                         "X", 85),
                        (r'https?://(?:www\.)?linkedin\.com/(?:company|in|school)/([A-Za-z0-9-]+)',
                         "LinkedIn", 85),
                        (r'https?://(?:www\.)?youtube\.com/(?:c/|channel/|user/|@)([A-Za-z0-9_-]+)',
                         "YouTube", 80),
                        (r'https?://(?:www\.)?tiktok\.com/@([A-Za-z0-9._-]+)',
                         "TikTok", 80),
                        (r'https?://(?:www\.)?github\.com/([A-Za-z0-9-]+)',
                         "GitHub", 85),
                        (r'https?://(?:www\.)?gitlab\.com/([A-Za-z0-9_.-]+)',
                         "GitLab", 80),
                        (r'https?://(?:www\.)?reddit\.com/(?:user|r)/([A-Za-z0-9_-]+)',
                         "Reddit", 80),
                        (r'https?://(?:www\.)?pinterest\.com/([A-Za-z0-9_]+)',
                         "Pinterest", 75),
                        (r'https?://(?:www\.)?snapchat\.com/add/([A-Za-z0-9._-]+)',
                         "Snapchat", 75),
                        (r'https?://(?:www\.)?t\.me/([A-Za-z0-9_]+)',
                         "Telegram", 80),
                        (r'https?://(?:www\.)?discord\.gg/([A-Za-z0-9]+)',
                         "Discord", 75),
                        (r'https?://(?:www\.)?medium\.com/@?([A-Za-z0-9_-]+)',
                         "Medium", 70),
                        (r'https?://(?:www\.)?twitch\.tv/([A-Za-z0-9_]+)',
                         "Twitch", 75),
                        (r'https?://(?:www\.)?vimeo\.com/([A-Za-z0-9_-]+)',
                         "Vimeo", 70),
                        (r'https?://(?:www\.)?dribbble\.com/([A-Za-z0-9_-]+)',
                         "Dribbble", 70),
                        (r'https?://(?:www\.)?behance\.net/([A-Za-z0-9_-]+)',
                         "Behance", 70),
                        (r'https?://(?:www\.)?stackoverflow\.com/users/\d+/([A-Za-z0-9_-]+)',
                         "StackOverflow", 75),
                        (r'https?://(?:www\.)?dev\.to/([A-Za-z0-9_-]+)',
                         "Dev.to", 70),
                        (r'https?://(?:www\.)?hashnode\.com/@([A-Za-z0-9_-]+)',
                         "Hashnode", 65),
                        (r'https?://(?:www\.)?producthunt\.com/@([A-Za-z0-9_-]+)',
                         "ProductHunt", 65),
                        (r'https?://(?:www\.)?angel\.co/(?:company|l)/([A-Za-z0-9_-]+)',
                         "AngelList", 65),
                        (r'https?://(?:www\.)?crunchbase\.com/organization/([A-Za-z0-9-]+)',
                         "Crunchbase", 70),
                        (r'https?://(?:www\.)?mastodon\.social/@([A-Za-z0-9_]+)',
                         "Mastodon", 65),
                        (r'https?://(?:www\.)?threads\.net/@([A-Za-z0-9._-]+)',
                         "Threads", 75),
                        (r'https?://(?:www\.)?bsky\.app/profile/([A-Za-z0-9._-]+)',
                         "Bluesky", 70),
                        (r'https?://(?:www\.)?linktr\.ee/([A-Za-z0-9_-]+)',
                         "Linktree", 70),
                        (r'https?://(?:www\.)?about\.me/([A-Za-z0-9_-]+)',
                         "About.me", 65),
                        (r'https?://(?:www\.)?keybase\.io/([A-Za-z0-9_]+)',
                         "Keybase", 70),
                        (r'https?://(?:www\.)?open\.spotify\.com/(?:user|artist)/([A-Za-z0-9]+)',
                         "Spotify", 65),
                        (r'https?://(?:www\.)?soundcloud\.com/([A-Za-z0-9_-]+)',
                         "SoundCloud", 65),
                        (r'https?://(?:www\.)?flickr\.com/(?:people|photos)/([A-Za-z0-9@_-]+)',
                         "Flickr", 65),
                        (r'https?://(?:www\.)?500px\.com/([A-Za-z0-9_-]+)',
                         "500px", 60),
                        (r'https?://(?:www\.)?codepen\.io/([A-Za-z0-9_-]+)',
                         "CodePen", 70),
                        (r'https?://(?:www\.)?kaggle\.com/([A-Za-z0-9_-]+)',
                         "Kaggle", 70),
                        (r'https?://hub\.docker\.com/(?:u|r)/([A-Za-z0-9_-]+)',
                         "Docker Hub", 70),
                        (r'https?://(?:www\.)?npmjs\.com/~([A-Za-z0-9_-]+)',
                         "npm", 65),
                        (r'https?://pypi\.org/user/([A-Za-z0-9_-]+)',
                         "PyPI", 65),
                        (r'https?://(?:www\.)?hackerone\.com/([A-Za-z0-9_-]+)',
                         "HackerOne", 70),
                        (r'https?://(?:www\.)?bugcrowd\.com/([A-Za-z0-9_-]+)',
                         "Bugcrowd", 70),
                    ]
                    for pattern, plat, conf in social_patterns:
                        for m in re.finditer(pattern, r.text):
                            handle = m.group(1).rstrip("/")
                            if handle and len(handle) < 50:
                                findings.append(self._f(
                                    "identity", "social_account",
                                    f"{plat}: @{handle}",
                                    source="social footprint",
                                    source_url=m.group(0)[:200],
                                    confidence=conf, passive=True))
            except Exception:
                pass

            # Brand name guess for social search
            brand = domain.split(".")[0]
            if len(brand) >= 3:
                for plat, url_t in [
                    ("Twitter", f"https://twitter.com/{brand}"),
                    ("X", f"https://x.com/{brand}"),
                    ("Instagram", f"https://instagram.com/{brand}"),
                    ("Facebook", f"https://facebook.com/{brand}"),
                    ("LinkedIn", f"https://linkedin.com/company/{brand}"),
                    ("TikTok", f"https://tiktok.com/@{brand}"),
                    ("YouTube", f"https://youtube.com/@{brand}"),
                    ("GitHub", f"https://github.com/{brand}"),
                    ("Reddit", f"https://reddit.com/r/{brand}"),
                    ("Medium", f"https://medium.com/@{brand}"),
                    ("Twitch", f"https://twitch.tv/{brand}"),
                    ("Discord", f"https://discord.gg/{brand}"),
                ]:
                    findings.append(self._f(
                        "identity", "social_guess",
                        f"Possible {plat}: {url_t} (verify manually)",
                        source="social footprint", source_url=url_t,
                        confidence=30, passive=True))
        else:
            # Username / person: use the usernames plugin approach for socials
            name = target.normalized.strip().lstrip("@")
            for plat, url_t in [
                ("Twitter", f"https://twitter.com/{name}"),
                ("X", f"https://x.com/{name}"),
                ("Instagram", f"https://instagram.com/{name}"),
                ("GitHub", f"https://github.com/{name}"),
                ("LinkedIn", f"https://linkedin.com/in/{name}"),
                ("TikTok", f"https://tiktok.com/@{name}"),
                ("Reddit", f"https://reddit.com/user/{name}"),
                ("Medium", f"https://medium.com/@{name}"),
                ("Dev.to", f"https://dev.to/{name}"),
                ("StackOverflow", f"https://stackoverflow.com/users/{name}"),
                ("GitLab", f"https://gitlab.com/{name}"),
                ("CodePen", f"https://codepen.io/{name}"),
                ("Kaggle", f"https://kaggle.com/{name}"),
                ("HackerOne", f"https://hackerone.com/{name}"),
                ("Keybase", f"https://keybase.io/{name}"),
                ("Telegram", f"https://t.me/{name}"),
            ]:
                findings.append(self._f(
                    "identity", "social_guess",
                    f"Check {plat}: {url_t}",
                    source="social footprint", source_url=url_t,
                    confidence=40, passive=True))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"found {len(findings)} social signals")
        res.duration_ms = dur
        return res
