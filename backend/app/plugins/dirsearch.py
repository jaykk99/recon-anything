"""dirsearch-style path discovery with extension expansion (native).

Probes curated base names and expands each with suffixes (.php,
.bak, .zip, .sql, .tar.gz, .old, .txt ...) - by NAME only: requests
are HEAD (falling back to a ranged-free GET only where HEAD is not
answered), and findings report existence + status + size ONLY.
Backup/archive contents are never downloaded, stored or reported.
Soft-404 / wildcard baselines are fingerprinted first and filtered.
"""
from __future__ import annotations

import time
from typing import Dict, List
from urllib.parse import quote

from ..net import web_base
from ..classifier import domain_from_target
from ..ratelimit import fetch, fetch_many
from .base import Cost, Ctx, Plugin, PluginResult, Target, bounded

BASE_NAMES = [
    "backup", "backups", "site", "www", "web", "db", "database",
    "dump", "data", "config", "configuration", "settings", "admin",
    "old", "temp", "archive", "export", "sql", "index", "main",
    "home", "default", "test", "dev", "staging", "private", "files",
    "uploads", "download", "downloads", "wp-config", "web", "app",
    "src", "source", "code", "release", "deploy", "full", "copy",
]
SUFFIXES = [".zip", ".tar.gz", ".tgz", ".bak", ".old", ".sql",
            ".php.bak", ".php~", ".txt", ".orig", ".save"]
# Standalone sensitive filenames probed as-is.
EXACT_FILES = [
    ".env", ".env.bak", ".env.old", "backup.zip", "backup.sql",
    "site.zip", "www.zip", "db.sql", "dump.sql", "database.sql",
    "config.php.bak", "wp-config.php.bak", "config.bak",
    "archive.zip", "backup.tar.gz",
]
HIT_STATUSES = (200, 201, 204, 301, 302, 307, 308, 401, 403, 405)


def probe_paths() -> List[str]:
    """The full expanded probe list (pure helper, deduped)."""
    out: List[str] = []
    seen = set()
    for name in EXACT_FILES:
        if name not in seen:
            seen.add(name)
            out.append(name)
    for base in BASE_NAMES:
        for suffix in SUFFIXES:
            p = base + suffix
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


class DirsearchPlugin(Plugin):
    id = "dirsearch"
    label = "dirsearch Path Discovery"
    accepts = ["domain", "url"]
    passive = False
    cost = Cost.FREE
    group = "web"
    timeout_s = 90
    aggressive = True
    description = ("Path discovery with extension expansion "
                   "(.php/.bak/.zip style suffixes). Existence and "
                   "status by name only - backup contents are never "
                   "downloaded.")

    async def _baseline(self, ctx: Ctx, base: str) -> Dict:
        import random
        import string
        rand = "".join(random.choices(string.ascii_lowercase, k=16))
        probe = f"{base}/__no_such_{rand}__.zip"
        try:
            r = await bounded(fetch(
                ctx.http, ctx.limiter, "HEAD", probe, timeout=8,
                follow_redirects=False, max_retries=0), 10)
            if r is None:
                return {"status": 0, "length": -1, "ctype": ""}
            try:
                length = int(r.headers.get("content-length", -1))
            except Exception:
                length = -1
            return {"status": r.status_code, "length": length,
                    "ctype": (r.headers.get("content-type", "")
                              .split(";")[0].strip().lower())}
        except Exception:
            return {"status": 0, "length": -1, "ctype": ""}

    def _is_hit(self, status: int, length: int, baseline: Dict,
                ctype: str = "") -> bool:
        if status not in HIT_STATUSES:
            return False
        # wildcard / soft-404 fingerprint: same status AND (same size
        # OR same content-type with no size to compare) as the
        # random-name baseline means the server answers everything
        # the same way (SPA fallback / catch-all) - not a real file.
        # Size alone is not enough: SPA fallbacks serve 200 text/html
        # with no Content-Length for every path.
        if status == baseline.get("status"):
            if length >= 0 and length == baseline.get("length"):
                return False
            if length < 0 and baseline.get("length", -1) < 0 \
                    and ctype and ctype == baseline.get("ctype"):
                return False
        return True

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        if self.module_mode(ctx) == "passive":
            return self._skipped("path discovery needs active mode")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        baseline = await self._baseline(ctx, base)
        paths = probe_paths()
        urls = [f"{base}/{quote(p, safe='.')}" for p in paths]
        reqs = [("HEAD", u, {"timeout": 8, "max_retries": 0,
                             "follow_redirects": False}) for u in urls]
        resps = await fetch_many(ctx.http, ctx.limiter, reqs,
                                 concurrency=20, deadline=45)
        findings = []
        swept = 0
        for path, u, r in zip(paths, urls, resps):
            if r is None:
                continue
            swept += 1
            try:
                length = int(r.headers.get("content-length", -1))
            except Exception:
                length = -1
            ctype = (r.headers.get("content-type", "")
                     .split(";")[0].strip().lower())
            if not self._is_hit(r.status_code, length, baseline, ctype):
                continue
            is_backup = any(path.endswith(s) for s in
                            (".zip", ".tar.gz", ".tgz", ".sql", ".bak",
                             ".old")) or path.startswith(".env")
            findings.append(self._f(
                "web", "dirsearch_path",
                f"{u} exists (HTTP {r.status_code}"
                + (f", {length} bytes" if length >= 0 else "")
                + ") - existence only, contents not fetched",
                source="dirsearch", source_url=u, confidence=82,
                passive=False,
                evidence={"severity": "medium" if is_backup else "low",
                          "status": r.status_code, "size": length,
                          "path": path,
                          "remediation": "Remove backup/archive/config "
                                         "files from the web root, or "
                                         "deny access to them at the "
                                         "server. Their contents were "
                                         "not downloaded by this check."}))
            ctx.publish("endpoints", u)
        res = self._ok(findings,
                       f"probed {swept} expanded paths, "
                       f"{len(findings)} hits")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
