"""FFUF-style content discovery with auto-calibration.

dir_brute.py already probes a fixed wordlist. This plugin is the
FFUF workflow instead, which is a different animal:

- FUZZ-position fuzzing: a curated wordlist is substituted into the
  path, and file stems (backup, db, dump, config...) are additionally
  fuzzed across archive/database extensions.
- Auto-calibration (ffuf's -ac): two random nonexistent paths are
  probed first; any response matching the calibration signature
  (status + size + word count) is filtered as noise. That is what
  makes it usable on catch-all / SPA hosts where every path is a
  200 with the same shell.
- Recursion depth 1: a discovered directory is fuzzed one level
  deeper with a small sub-wordlist.
- Backup/config hits are reported by NAME, status and size only:
  the finding never stores the file's contents.

GET only, rate-limited through ctx.probe's shared limiter/cache,
bounded probe budget. Authorized targets only.
"""
from __future__ import annotations

import asyncio
import re
import time
import uuid
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

WORDS = """admin administrator login dashboard panel console manage management
api api/v1 api/v2 rest graphql swagger openapi.json docs documentation
config settings setup install status health metrics server-status
backup backups db database dump archive old temp tmp private internal
dev test staging beta debug trace uploads upload files file download
downloads export import reports report invoices orders products product
users user account accounts profile profiles register signup signin
auth oauth callback webhooks webhook token session sessions search
forgot-password reset verify confirm activate feed rss sitemap.xml
robots.txt manifest.json .well-known/security.txt wp-admin wp-login.php
administrator phpmyadmin adminer portal secure member members client
clients customer customers billing payments checkout cart shop store
assets static media images image js css fonts lib includes inc core
app server services service v1 v2 public private-api internal-api
hidden secret admin-api debugbar telescope horizon nova logs log
error errors test.php info.php phpinfo.php shell cmd exec system""".split()

# File stems fuzzed across extensions (existence probe only).
STEM_EXTS = {
    "backup": [".zip", ".tar.gz", ".sql", ".bak", ".old"],
    "db": [".sql", ".sqlite", ".bak"],
    "dump": [".sql", ".zip"],
    "database": [".sql", ".bak", ".zip"],
    "config": [".bak", ".old", ".save", ".txt"],
    "site": [".zip", ".tar.gz"],
    "www": [".zip", ".tar.gz"],
}

SUBWORDS = ["index", "login", "config", "users", "list", "home",
            "main", "default", "upload", "settings"]

DIR_WORDS = {"admin", "administrator", "api", "uploads", "files",
             "internal", "dev", "backup", "backups", "private",
             "portal", "console", "panel", "manage", "app", "services"}

SENSITIVE = ("backup", "dump", "database", "db.", "db/", ".sql", "config",
             "debug", "internal", "private", "secret", "phpinfo", ".bak",
             ".old", ".zip", ".tar.gz", "adminer", "phpmyadmin")
PANEL = ("admin", "phpmyadmin", "adminer", "console", "dashboard",
         "wp-admin", "portal", "manage")

MAX_PROBES = 260
KEEP_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403}


def _words_of(text: str) -> int:
    return len(re.findall(r"\S+", text or ""))


def _signature(resp: Dict) -> Tuple[int, int, int]:
    return (int(resp.get("status") or 0), int(resp.get("length") or 0),
            _words_of(resp.get("text") or ""))


def _matches_calibration(sig: Tuple[int, int, int],
                         calib: List[Tuple[int, int, int]]) -> bool:
    for c in calib:
        if sig[0] != c[0]:
            continue
        size_tol = max(24, int(c[1] * 0.02))
        if abs(sig[1] - c[1]) <= size_tol and abs(sig[2] - c[2]) <= 2:
            return True
    return False


class ContentDiscoveryFfufPlugin(Plugin):
    id = "content_discovery_ffuf"
    label = "Content Discovery (FFUF-style)"
    accepts = ["domain", "url"]
    passive = False
    aggressive = True
    cost = Cost.FREE
    group = "web"
    timeout_s = 120
    description = ("FFUF-style path fuzzing with auto-calibration "
                   "against the site's not-found baseline, extension "
                   "fuzzing for backup/db stems, and depth-1 recursion "
                   "into discovered directories. GET only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        start = time.time()
        if self.module_mode(ctx) == "passive":
            return self._ok([], "content discovery sends probes; "
                                "needs active mode")
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._ok([], "not a web target")
        base = (await web_base(ctx, target, domain)).rstrip("/") + "/"
        budget = [MAX_PROBES]

        async def probe(path: str) -> Optional[Dict]:
            if budget[0] <= 0:
                return None
            budget[0] -= 1
            return await ctx.probe(urljoin(base, path.lstrip("/")),
                                   timeout=8)

        # Auto-calibration: signatures of paths that cannot exist.
        calib: List[Tuple[int, int, int]] = []
        for _ in range(2):
            r = await probe(f"ffuf-cal-{uuid.uuid4().hex[:10]}")
            if r and int(r.get("status") or 0):
                calib.append(_signature(r))

        candidates: List[str] = list(dict.fromkeys(WORDS))
        for stem, exts in STEM_EXTS.items():
            for ext in exts:
                candidates.append(stem + ext)

        sem = asyncio.Semaphore(6)

        async def check(path: str) -> Optional[Tuple[str, Dict]]:
            async with sem:
                r = await probe(path)
            if not r:
                return None
            status = int(r.get("status") or 0)
            if status == 0 or status not in KEEP_STATUS:
                return None
            if _matches_calibration(_signature(r), calib):
                return None
            return (path, r)

        results = await asyncio.gather(
            *(check(p) for p in candidates))
        found: Dict[str, Dict] = {p: r for p, r in
                                  (x for x in results if x)}

        # Depth-1 recursion into discovered directories.
        dirs = [p for p in found
                if p.split("/")[0] in DIR_WORDS][:4]
        sub_paths = [f"{d}/{s}" for d in dirs for s in SUBWORDS
                     if f"{d}/{s}" not in found]
        if sub_paths:
            sub_results = await asyncio.gather(
                *(check(p) for p in sub_paths))
            for x in sub_results:
                if x:
                    found[x[0]] = x[1]

        findings: List[Finding] = []
        for path, r in sorted(found.items()):
            url = urljoin(base, path)
            status = int(r.get("status") or 0)
            low = path.lower()
            if any(s in low for s in SENSITIVE) and status == 200:
                severity, conf = "high", 85
                note = "sensitive content reachable"
            elif any(s in low for s in PANEL) and status in (200, 401, 403):
                severity, conf = "medium", 80
                note = "panel/login surface reachable"
            elif status in (401, 403):
                severity, conf = "low", 70
                note = "path exists but is access-controlled"
            else:
                severity, conf = "low", 65
                note = "discovered content"
            ev = {"severity": severity, "status": status,
                  "size": int(r.get("length") or 0),
                  "words": _words_of(r.get("text") or ""),
                  "note": note,
                  "contents_stored": False,
                  "remediation": ("Remove or access-control this path "
                                  "if it is not meant to be public; "
                                  "backups and configs must never sit "
                                  "in the document root.")}
            findings.append(self._f(
                "web", "discovered_path",
                f"{url} ({note}, HTTP {status})",
                source="ffuf-style content discovery", source_url=url,
                confidence=conf, passive=False, evidence=ev))
            ctx.publish("endpoints", url)
        result = self._ok(findings,
                          f"{len(found)} paths survived calibration "
                          f"of {len(candidates) + len(sub_paths)} probed")
        result.duration_ms = int((time.time() - start) * 1000)
        return result
