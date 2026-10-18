"""Open directory finder plugin.

Checks common paths for open directory listings (Apache/Nginx autoindex).
Custom-built, works in both passive (Wayback) and active (direct probe) modes.
"""
from __future__ import annotations

import re
import time
from typing import List
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# Common paths where open directories are found
DIR_PATHS = [
    "/", "/backup/", "/backups/", "/old/", "/tmp/", "/files/",
    "/uploads/", "/download/", "/downloads/", "/images/", "/img/",
    "/assets/", "/static/", "/media/", "/data/", "/db/",
    "/admin/", "/private/", "/secret/", "/test/", "/dev/",
    "/wp-content/uploads/", "/sites/default/files/",
]

# Markers of an open directory listing
DIR_MARKERS = [
    "index of /", "directory listing for", "<title>index of",
    "[parent directory]", "[to parent directory]",
]


class OpenDirPlugin(Plugin):
    id = "opendir"
    label = "Open Directories"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Find open directory listings on common paths."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)

        for path in DIR_PATHS:
            url = base + path
            try:
                if mode == "passive":
                    wb = ("https://web.archive.org/cdx/search/cdx?url="
                          + quote(url, safe="") + "&output=json&limit=1")
                    r = await fetch(ctx.http, ctx.limiter, "GET", wb, timeout=10)
                    if r.status_code == 200 and len(r.json()) > 1:
                        findings.append(self._f(
                            "web", "opendir_archived",
                            f"{path} was archived - may have been an open directory",
                            source="Wayback", source_url=url,
                            confidence=45, passive=True))
                else:
                    r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10)
                    body = r.text[:5000].lower()
                    if r.status_code == 200 and any(m in body for m in DIR_MARKERS):
                        # Count files listed
                        links = len(re.findall(r'href="[^"]*"', body))
                        findings.append(self._f(
                            "web", "open_directory",
                            f"OPEN DIRECTORY at {path} ({links} links found)",
                            source="directory check", source_url=url,
                            confidence=90, passive=False))
            except Exception:
                continue

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"checked {len(DIR_PATHS)} paths ({mode})")
        res.duration_ms = dur
        return res
