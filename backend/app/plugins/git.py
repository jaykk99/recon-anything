"""Exposed .git deep checker (Milestone: critical findings).

Non-destructive, read-only: fetches .git/HEAD first. If the repo
metadata is exposed, it tries config, logs/HEAD, index and packed-refs
to show how much of the repository is recoverable, and flags that the
entire source (including secrets in history) can be reconstructed.
Passive mode checks the Wayback Machine. Authorized testing only.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

GIT_FILES = [
    ("/.git/HEAD", "HEAD ref", 95, "ref:"),
    ("/.git/config", "repo config (may leak origin URLs)", 95, "[core]"),
    ("/.git/logs/HEAD", "reflog (commit history)", 92, None),
    ("/.git/index", "staging index (file list)", 88, "DIRC"),
    ("/.git/packed-refs", "packed refs (branches/tags)", 88, "# pack-refs"),
    ("/.git/COMMIT_EDITMSG", "last commit message", 85, None),
]

REMEDIATION = ("Block /.git at the web server or WAF immediately, redeploy "
               "without the .git directory, and audit git history for "
               "secrets: rotate anything ever committed.")

RECONSTRUCT_GUIDE = ("To reconstruct the repo (authorized testing only): "
                     "1) wget -r --no-parent {base}/.git/ "
                     "2) Use gitdumper: python3 gitdumper.py {base}/.git/ ./out "
                     "3) cd out && git log --all --oneline to browse history. "
                     "Every commit ever made is recoverable, including deleted secrets.")


class GitPlugin(Plugin):
    id = "git"
    aggressive = True  # suppressed on WAF-protected hosts
    label = "Exposed .git Check"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Deep .git exposure check: HEAD, config, logs, index."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (f"https://{domain}" if target.type == "domain"
                else target.normalized.rstrip("/"))
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        async def check(path: str):
            full = base + path
            if passive:
                url = ("https://web.archive.org/cdx/search/cdx?url="
                       + quote(full, safe="") + "&output=json&fl=timestamp&limit=1")
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=15)
                    if r.status_code == 200:
                        data = r.json()
                        if isinstance(data, list) and len(data) > 1:
                            return {"archived": True, "ts": data[1][0] if data[1] else ""}
                except Exception:
                    pass
                return None
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=12)
                if r.status_code == 200 and r.text.strip():
                    return {"body": r.text[:500]}
            except Exception:
                pass
            return None

        head = await check("/.git/HEAD")
        if not head:
            res = self._ok([], "no .git/HEAD exposure")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        if passive:
            findings.append(self._f(
                "leak", "git_exposed_archived",
                f"CRITICAL: .git/HEAD was archived ({head.get('ts', '')}). "
                f"The repository metadata was publicly reachable.",
                source="Wayback CDX", source_url=base + "/.git/HEAD",
                confidence=85, passive=True,
                evidence={"severity": "critical", "remediation": REMEDIATION}))
        else:
            body = head.get("body", "")
            findings.append(self._f(
                "leak", "git_head_exposed",
                f"CRITICAL: .git/HEAD is exposed ({body.strip()[:60]}). "
                f"The full repository can likely be reconstructed.",
                source=".git check", source_url=base + "/.git/HEAD",
                confidence=97, passive=False,
                evidence={"severity": "critical", "remediation": REMEDIATION}))

        recovered = []
        for path, label, conf, marker in GIT_FILES[1:]:
            got = await check(path)
            if not got:
                continue
            if not passive and marker and marker not in got.get("body", ""):
                continue
            recovered.append(label)
            findings.append(self._f(
                "leak", "git_file_exposed",
                f"CRITICAL: {path} exposed ({label}).",
                source=".git check", source_url=base + path,
                confidence=conf if not passive else conf - 12, passive=passive,
                evidence={"severity": "critical", "remediation": REMEDIATION}))
            if len(recovered) >= 6:
                break

        if recovered and not passive:
            findings.append(self._f(
                "leak", "git_full_recon",
                f"CRITICAL: {len(recovered) + 1} git metadata files recoverable "
                f"({', '.join(recovered)}). Entire source history reconstructable. "
                f"{RECONSTRUCT_GUIDE.format(base=base)}",
                source=".git check", source_url=base + "/.git/HEAD",
                confidence=95, passive=False,
                evidence={"severity": "critical",
                          "remediation": REMEDIATION,
                          "reconstruct_guide": RECONSTRUCT_GUIDE.format(base=base),
                          "scope_note": "Authorized testing only. Proving exposure is enough for a bounty report."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f".git exposed: {len(findings)} findings")
        res.duration_ms = dur
        return res
