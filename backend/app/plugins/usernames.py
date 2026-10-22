"""Username checker plugin (Sherlock-style).

Checks if a username exists across popular platforms. Custom-built,
no API keys needed.

Works two ways:
- username target: checks that username directly.
- domain/url target: harvests candidate usernames from the site
  (email local-parts, author names, org name) then checks those.
"""
from __future__ import annotations

import asyncio

import re
import time
from typing import List
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
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
    ("stackoverflow", "https://stackoverflow.com/users/{u}", ["Page Not Found"], 70),
    ("codepen", "https://codepen.io/{u}", ["404"], 70),
    ("dribbble", "https://dribbble.com/{u}", ["404"], 65),
    ("behance", "https://www.behance.net/{u}", ["404"], 65),
    ("producthunt", "https://www.producthunt.com/@{u}", ["404"], 65),
    ("kaggle", "https://www.kaggle.com/{u}", ["404"], 70),
    ("dockerhub", "https://hub.docker.com/u/{u}", ["404"], 75),
    ("hackerone", "https://hackerone.com/{u}", ["404"], 75),
    ("bugcrowd", "https://bugcrowd.com/{u}", ["404"], 75),
    ("keybase", "https://keybase.io/{u}", ["404"], 75),
    ("mastodon", "https://mastodon.social/@{u}", ["404"], 60),
    ("crates", "https://crates.io/users/{u}", ["404"], 75),
    ("rubygems", "https://rubygems.org/profiles/{u}", ["404"], 75),
    ("sourceforge", "https://sourceforge.net/u/{u}/profile", ["404"], 70),
    ("vimeo", "https://vimeo.com/{u}", ["404"], 65),
    ("soundcloud", "https://soundcloud.com/{u}", ["404"], 65),
]

EMAIL_RE = re.compile(r"([a-zA-Z0-9._%+\-]{2,40})@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24})")
AUTHOR_RE = re.compile(
    r"(?i)(?:author|by)[\"'\s:=]+([A-Za-z][A-Za-z0-9_.\-]{2,30})")
# Extra harvesting sources: meta author tags, JSON-LD, HTML comments,
# @mentions, profile links to social platforms, author bylines.
META_AUTHOR_RE = re.compile(
    r"(?i)<meta[^>]+(?:name|property)=[\"'](?:author|article:author|"
    r"profile:username|twitter:creator)[\"'][^>]+content=[\"']([^\"']{2,40})")
JSONLD_AUTHOR_RE = re.compile(
    r"(?i)\"author\"[^}]{0,300}?\"name\"\s*:\s*\"([^\"]{2,40})\"")
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
MENTION_RE = re.compile(r"(?<![\w@])@([A-Za-z][A-Za-z0-9_.\-]{2,30})")
PROFILE_LINK_RE = re.compile(
    r"(?i)https?://(?:www\.)?(?:github|twitter|x|linkedin|instagram|"
    r"facebook|medium|dev\.to|gitlab|dribbble|behance)\.com/"
    r"(?:@|in/|users/|u/)?([A-Za-z0-9_.\-]{2,40})")
BYLINE_RE = re.compile(
    r"(?i)(?:written by|posted by|byline|rel=[\"']author[\"'])[^>]{0,120}?"
    r">([^<]{2,40})<")

GENERIC_LOCALS = {"info", "contact", "support", "admin", "hello", "mail",
                  "sales", "help", "noreply", "no-reply", "webmaster",
                  "postmaster", "abuse", "team"}

# Username literals baked into the site's own JS/config ("username": "x",
# login: 'x', user = "x"). Service accounts and deploy bots leak this way.
JS_USERNAME_RE = re.compile(
    r"""(?i)["']?(?:username|user_name|login|service_account|account_name)"""
    r"""["']?\s*[:=]\s*["']([A-Za-z0-9][A-Za-z0-9_.\-]{1,39})["']""")
SCRIPT_SRC_RE = re.compile(r"""(?i)<script[^>]+src=["']([^"']+)["']""")
# Well-known default account names: if a site's own public data says one
# of these accounts exists, that is a finding (attackers try them first).
DEFAULT_ACCOUNTS = {"admin", "administrator", "root", "webmaster",
                    "sysadmin", "system", "manager", "operator"}
_NON_HANDLES = {"true", "false", "null", "none", "user", "username",
                "string", "text", "password", "email", "name", "value"}


def usernames_in_js(text: str) -> List[str]:
    """Handles assigned to username/login fields in JS or config text."""
    out = []
    for m in JS_USERNAME_RE.finditer(text[:600000]):
        v = m.group(1).strip()
        if v.lower() not in _NON_HANDLES and v not in out:
            out.append(v)
    return out[:20]


def parse_wp_users(text: str) -> List[dict]:
    """Parse a /wp-json/wp/v2/users response into [{slug, name}]."""
    import json
    try:
        data = json.loads(text)
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    out = []
    for u in data[:50]:
        if isinstance(u, dict) and u.get("slug"):
            out.append({"slug": str(u["slug"])[:60],
                        "name": str(u.get("name") or "")[:80]})
    return out


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
            base = await web_base(ctx, target, domain)
            try:
                # Shared homepage cache: first plugin pays, the rest read from cache.
                page = await ctx.fetch_page(base, timeout=25)
                if page is None:
                    raise RuntimeError("homepage fetch failed")
                html = page["text"][:400000]
            except Exception as e:
                res = self._degraded(f"fetch failed: {str(e)[:200]}")
                res.duration_ms = int((time.monotonic() - t0) * 1000)
                return res
            seen = set()
            for m in EMAIL_RE.finditer(html):
                local = m.group(1).lower()
                if local not in GENERIC_LOCALS and len(local) >= 3:
                    seen.add(local)
            for m in AUTHOR_RE.finditer(html[:100000]):
                seen.add(m.group(1).lower())
            # NEW: meta author tags
            for m in META_AUTHOR_RE.finditer(html[:200000]):
                seen.add(m.group(1).strip().lower().replace(" ", ""))
            # NEW: JSON-LD author names
            for m in JSONLD_AUTHOR_RE.finditer(html[:200000]):
                seen.add(m.group(1).strip().lower().replace(" ", "")[:30])
            # NEW: @mentions in page text
            for m in MENTION_RE.finditer(html[:200000]):
                seen.add(m.group(1).lower())
            # NEW: social profile links on the page
            for m in PROFILE_LINK_RE.finditer(html[:200000]):
                seen.add(m.group(1).lower())
            # NEW: HTML comments (devs leave handles in comments)
            for cm in COMMENT_RE.finditer(html[:200000]):
                for m in EMAIL_RE.finditer(cm.group(1)):
                    local = m.group(1).lower()
                    if local not in GENERIC_LOCALS and len(local) >= 3:
                        seen.add(local)
                for m in MENTION_RE.finditer(cm.group(1)):
                    seen.add(m.group(1).lower())
            # NEW: author bylines (written by X)
            for m in BYLINE_RE.finditer(html[:200000]):
                name = m.group(1).strip().lower().replace(" ", "")
                if 2 <= len(name) <= 30:
                    seen.add(name)
            # org name as a candidate handle
            seen.add(domain.split(".")[0].lower())
            candidates = sorted(seen)[:15]
            if candidates:
                findings.append(self._f(
                    "identity", "username_candidates",
                    f"Harvested {len(candidates)} username candidates from {domain}: "
                    f"{', '.join(candidates)}",
                    source="site harvesting", confidence=80, passive=True))
            # Accounts the site exposes about ITSELF: username literals
            # in its own JS/config, and its public WP author accounts.
            # In-scope assets only; no logins, no credential data.
            findings.extend(
                await self._exposed_accounts(base, html, ctx))

        if not candidates:
            res = self._ok(findings, "no username candidates found")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # Platform checks concurrently (different hosts; same checks).
        sem = asyncio.Semaphore(8)

        async def _check_platform(username: str, plat: str, template: str,
                                  not_found_markers, conf: int):
            url = template.format(u=username)
            async with sem:
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=12)
                except Exception:
                    return None
            body = r.text[:5000].lower()
            is_not_found = any(m.lower() in body for m in not_found_markers)
            if r.status_code == 200 and not is_not_found:
                return self._f(
                    "identity", "username_found",
                    f"@{username} exists on {plat}",
                    source="username checker", source_url=url,
                    confidence=conf, passive=True)
            return None

        jobs = []
        for username in candidates:
            for plat, template, not_found_markers, conf in PLATFORMS:
                jobs.append((username, plat, template, not_found_markers, conf))
        for f in await asyncio.gather(*[_check_platform(*j) for j in jobs]):
            if f:
                findings.append(f)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"checked {len(candidates)} username(s) on {len(PLATFORMS)} platforms")
        res.duration_ms = dur
        return res

    async def _exposed_accounts(self, base: str, html: str,
                                ctx: Ctx) -> List[Finding]:
        """Usernames the target exposes on its own assets.

        1) username/login literals in the site's JavaScript and config
           objects (service accounts, deploy bots, embedded defaults);
        2) the site's public WordPress author accounts from its own
           REST API, flagging well-known default account names.
        Observation only: nothing is logged into, ever.
        """
        out: List[Finding] = []
        from urllib.parse import urljoin
        js_urls: List[str] = []
        for item in ctx.consume("js_files"):
            if isinstance(item, str):
                js_urls.append(item if item.startswith("http")
                               else urljoin(base, item))
        for m in SCRIPT_SRC_RE.finditer(html[:200000]):
            u = urljoin(base, m.group(1))
            if u not in js_urls:
                js_urls.append(u)
        for js_url in js_urls[:5]:
            try:
                page = await ctx.fetch_page(js_url, timeout=10)
            except Exception:
                page = None
            if not page:
                continue
            handles = usernames_in_js(page.get("text") or "")
            if handles:
                defaults = [h for h in handles
                            if h.lower() in DEFAULT_ACCOUNTS]
                out.append(self._f(
                    "identity", "username_in_code",
                    f"Usernames baked into site code at {js_url}: "
                    f"{', '.join(handles)}",
                    source="JS/config username literals",
                    source_url=js_url, confidence=85, passive=True,
                    evidence={"severity": "medium",
                              "usernames": handles,
                              "default_accounts": defaults,
                              "why": "Service/deploy account names in "
                                     "public code hand attackers valid "
                                     "account names for password spraying "
                                     "and social engineering."}))
        # WordPress author accounts, from the site's own public REST API.
        wp_url = urljoin(base, "/wp-json/wp/v2/users")
        try:
            page = await ctx.fetch_page(wp_url, timeout=10)
        except Exception:
            page = None
        if page and page.get("status_code", page.get("status")) == 200:
            users = parse_wp_users(page.get("text") or "")
            if users:
                slugs = [u["slug"] for u in users]
                defaults = [s for s in slugs
                            if s.lower() in DEFAULT_ACCOUNTS]
                out.append(self._f(
                    "identity", "wp_author_accounts",
                    f"WordPress author accounts exposed by the site's "
                    f"REST API: "
                    f"{', '.join(f'{u['slug']} ({u['name']})' for u in users[:10])}",
                    source="WP REST API (site's own public data)",
                    source_url=wp_url, confidence=90, passive=True,
                    evidence={"severity": "medium",
                              "accounts": users,
                              "default_accounts": defaults,
                              "why": "WP author enumeration gives "
                                     "attackers confirmed account names; "
                                     "a default 'admin' account is the "
                                     "first one tried. Restrict the users "
                                     "endpoint or rename defaults."}))
        return out
