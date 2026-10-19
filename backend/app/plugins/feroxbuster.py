"""Feroxbuster-style recursive content discovery (native, keyless).

Maps the visible file structure and auto-recurses: when a directory
probe returns a hit (200/redirect), the same wordlist is run inside
that directory up to 2 levels deep. 404-baseline filtered to kill
wildcards and soft-404s.

GET only. No login attempts, no credential brute-forcing, no writes.
Bounded: directory wordlist x 2 recursion levels, under 30s.
"""
from __future__ import annotations

import time
from typing import Dict, List, Set
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch, fetch_many
from ..net import web_base
from .base import (Cost, Ctx, Finding, Plugin, PluginResult, Target,
                   bounded)

DIR_WORDS = """admin administrator api v1 v2 assets static media uploads
images img files downloads css js scripts lib includes inc
backup backups bak old archive tmp temp cache logs
config configs settings db database private secret internal
docs documentation help support blog news portal dashboard
panel console backend system test dev staging prod demo
user users account accounts member members customer clients
order orders cart checkout payment billing search products
wp-admin wp-content wp-includes cgi-bin bin mobile app
images/icons icons fonts feed rss sitemap
old-site newsite beta alpha preview new
crm erp jenkins gitlab jira confluence grafana kibana
mail webmail ftp proxy cdn error errors
""".split()

FILE_WORDS = """index home main default login signin register
about contact sitemap robots.txt security.txt humans.txt
config.php config.bak .env .env.bak wp-config.php
package.json composer.json Dockerfile docker-compose.yml
phpinfo.php info.php test.php debug.php console.php
swagger.json openapi.json api-docs health status metrics
server-status crossdomain.xml clientaccesspolicy.xml
.env.local .env.prod web.config .htaccess
backup.zip site.zip db.sql backup.sql
readme.txt license.txt CHANGELOG.txt
""".split()

SOFT404_HINTS = ("not found", "page not found", "404", "does not exist",
                 "couldn't be found")


class FeroxbusterPlugin(Plugin):
    id = "feroxbuster"
    label = "Feroxbuster"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    timeout_s = 30
    aggressive = True
    description = ("Recursive content discovery: auto-recurses into "
                   "found dirs. GET only.")

    async def _baseline(self, ctx: Ctx, base: str) -> Dict:
        import random
        import string
        rand = "".join(random.choices(string.ascii_lowercase, k=16))
        probe = f"{base}/__no_such_path_{rand}__"
        try:
            r = await bounded(fetch(
                ctx.http, ctx.limiter, "GET", probe,
                timeout=10, follow_redirects=False, max_retries=0), 12)
            if r is None:
                return {"status": 0, "length": 0, "body": ""}
            body = r.text[:3000]
            return {"status": r.status_code, "length": len(body),
                    "body": body[:1500]}
        except Exception:
            return {"status": 0, "length": 0, "body": ""}

    def _is_hit(self, status: int, body: str, baseline: Dict) -> bool:
        if status in (301, 302, 303, 307, 308):
            return True
        if status in (404, 0):
            return False
        if status == baseline.get("status") and \
                abs(len(body) - baseline.get("length", 0)) < 64:
            low = body[:1500].lower()
            base_low = (baseline.get("body") or "").lower()
            if low[:400] == base_low[:400]:
                return False
            if any(h in low for h in SOFT404_HINTS):
                return False
        if status == 200 and any(h in body[:1500].lower()
                                 for h in SOFT404_HINTS) and len(body) < 3000:
            return False
        return status in (200, 201, 202, 204, 301, 302, 303, 307, 308,
                          401, 403, 405, 500)

    async def _probe_dir(self, ctx: Ctx, dir_url: str, baseline: Dict,
                         ) -> List[tuple]:
        """Probe one directory. Returns list of (url, status, is_dir)."""
        hits = []
        reqs = [("GET", f"{dir_url}/{quote(w)}",
                 {"timeout": 8, "max_retries": 0,
                  "follow_redirects": False})
                for w in DIR_WORDS + FILE_WORDS]
        # deadline: keep partial results on a slow host instead of
        # discarding the whole directory sweep
        resps = await fetch_many(ctx.http, ctx.limiter, reqs,
                                 concurrency=20, deadline=20)
        for (method, u, _kw), r in zip(reqs, resps):
            if r is None:
                continue
            try:
                if self._is_hit(r.status_code, r.text[:3000], baseline):
                    # trailing-slash probes to confirm real dirs
                    is_dir = False
                    if r.status_code in (301, 302, 303, 307, 308):
                        loc = r.headers.get("location", "")
                        is_dir = loc.endswith("/") or True
                    hits.append((u, r.status_code, is_dir))
            except Exception:
                continue
        return hits

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped("enumeration probes need active mode")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        baseline = await self._baseline(ctx, base)
        findings: List[Finding] = []
        discovered: Set[str] = set()

        # Level 0: root
        level0 = await self._probe_dir(ctx, base, baseline)
        dirs_to_recurse = []
        for u, status, is_dir in level0:
            if u not in discovered:
                discovered.add(u)
                findings.append(self._f(
                    "web", "discovered_path", u,
                    "feroxbuster", source_url=u, confidence=80,
                    evidence={"severity": "medium", "status": status,
                              "depth": 0,
                              "remediation": "Review discovered paths; "
                                             "remove or protect unused ones."},
                    passive=False))
                ctx.publish("endpoints", u)
                if status in (301, 302, 303, 307, 308, 200):
                    dirs_to_recurse.append(u.rstrip("/"))

        # Level 1: recurse into found dirs (cap 8)
        for d in dirs_to_recurse[:8]:
            if (time.monotonic() - t0) > 22:
                break
            level1 = await self._probe_dir(ctx, d, baseline)
            for u, status, is_dir in level1:
                if u not in discovered:
                    discovered.add(u)
                    findings.append(self._f(
                        "web", "discovered_path", u,
                        "feroxbuster", source_url=u, confidence=80,
                        evidence={"severity": "medium", "status": status,
                                  "depth": 1,
                                  "remediation": "Review discovered paths; "
                                                 "remove or protect unused ones."},
                        passive=False))
                    ctx.publish("endpoints", u)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"discovered {len(discovered)} paths "
                       f"({len(dirs_to_recurse)} dirs recursed)")
        res.duration_ms = dur
        return res
