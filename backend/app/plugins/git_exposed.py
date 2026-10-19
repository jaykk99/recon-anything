"""GitTools-style exposed VCS directory detector.

Probes for publicly readable version-control metadata: /.git/HEAD,
/.git/config, /.git/logs/HEAD, plus Subversion (/.svn/entries),
Mercurial (/.hg/requires), and Bazaar (/.bzr/branch.conf). If exposed,
flags it HIGH - an exposed VCS directory lets anyone reconstruct source
code and history, which almost always leaks secrets.

Detection only: small read-only GETs of metadata files. Never downloads
entire repos or objects. Authorized testing only.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (path, expected marker, label)
GIT_PROBES = [
    ("/.git/HEAD", "ref:", ".git/HEAD"),
    ("/.git/config", "[core]", ".git/config"),
    ("/.gitignore", None, ".gitignore"),
    ("/.git/logs/HEAD", "commit", ".git/logs/HEAD"),
    ("/.git/COMMIT_EDITMSG", None, ".git/COMMIT_EDITMSG"),
    ("/.git/index", None, ".git/index"),
    # Subversion
    ("/.svn/entries", "dir", ".svn/entries"),
    ("/.svn/wc.db", "SQLite", ".svn/wc.db"),
    # Mercurial
    ("/.hg/requires", "revlog", ".hg/requires"),
    ("/.hg/hgrc", "[", ".hg/hgrc"),
    # Bazaar
    ("/.bzr/branch.conf", "parent", ".bzr/branch.conf"),
]


class GitExposedPlugin(Plugin):
    id = "git_exposed"
    label = "Exposed .git Detector"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("GitTools-style: probe for publicly readable VCS "
                   "metadata (.git, .svn, .hg, .bzr).")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        for path, marker, label in GIT_PROBES:
            url = base.rstrip("/") + path
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10)
            except Exception:
                continue
            body = r.text[:2000]
            if r.status_code != 200 or not body.strip():
                continue
            exposed = marker is None or marker in body
            if not exposed:
                continue
            sev = "high" if path in ("/.git/HEAD", "/.git/config",
                                     "/.git/logs/HEAD") else "medium"
            detail = body[:200].replace("\n", " | ")
            findings.append(self._f(
                "leak", "git_exposed",
                f"Exposed {label} publicly readable at {path}",
                source="git exposure probe", source_url=url,
                confidence=95 if marker else 80, passive=passive,
                evidence={"remediation": "Block /.git at the web server or "
                          "CDN immediately. Assume source and history are "
                          "compromised: rotate all secrets that ever lived "
                          "in the repo.",
                          "severity": sev, "risk": sev,
                          "preview": detail}))

        # VCS directory listing checks (some servers index them)
        for vcs_dir, vcs_marker in (("/.git/", "HEAD|config|objects/?"),
                                    ("/.svn/", "entries|wc.db|format"),
                                    ("/.hg/", "requires|store|hgrc")):
            try:
                url = base.rstrip("/") + vcs_dir
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10)
                if (r.status_code == 200
                        and re.search(vcs_marker, r.text)):
                    findings.append(self._f(
                        "leak", "git_exposed",
                        f"Exposed {vcs_dir} directory listing publicly readable",
                        source="git exposure probe", source_url=url,
                        confidence=90, passive=passive,
                        evidence={"remediation": f"Block {vcs_dir} at the web server "
                                  "or CDN immediately.",
                                  "severity": "high", "risk": "high"}))
            except Exception:
                pass

        res = self._ok(findings,
                       f"{len(findings)} .git exposure hits" if findings
                       else "no .git exposure found")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
