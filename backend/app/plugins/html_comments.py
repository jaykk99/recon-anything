"""HTML comment analysis plugin.

Extracts HTML comments from the homepage and flags the ones that leak
useful intel: TODO/FIXME notes naming internal systems, commented-out
code with URLs/endpoints/credentials patterns, IE conditional leftovers
pointing at internal hosts, and template debug output. Commented-out
secrets are handed to the secrets pipeline via finding keys.

Passive: parses the already-fetched homepage HTML. No extra requests.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Plugin, PluginResult, PluginStatus, Target

COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
URL_RE = re.compile(r"https?://[^\s\"'<>]+|/[\w\-.~:/?#\[\]@!$&'()*+,;=%]+")
SECRET_RE = re.compile(
    r"(api[_-]?key|secret|password|passwd|pwd|token|aws_access|private[_-]?key)"
    r"\s*[:=]\s*[\"']?([\w\-./+]{8,})[\"']?", re.I)
TODO_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK|BUG|NOTE:?.*internal)\b", re.I)
INTERNAL_HOST_RE = re.compile(
    r"\b([a-z0-9\-]+\.(?:local|internal|corp|lan|intranet|dev|staging|test))\b",
    re.I)


class HtmlCommentsPlugin(Plugin):
    id = "html_comments"
    label = "HTML Comment Intel"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Mine HTML comments for TODOs, commented-out endpoints, "
                   "internal hosts and credential patterns.")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        resp = await ctx.fetch_page(base + "/", timeout=12)
        if resp is None:
            return self._degraded("homepage unreachable")
        comments = COMMENT_RE.findall(resp.text or "")
        findings: List = []
        secret_hits = todo_hits = internal_hits = 0
        endpoints = set()

        for c in comments:
            c = c.strip()
            if not c or len(c) > 2000:
                continue
            m = SECRET_RE.search(c)
            if m:
                secret_hits += 1
                findings.append(self._f(
                    "leak", "comment_credential",
                    f"Credential-like pattern in HTML comment "
                    f"({m.group(1)}=...)",
                    source="HTML comment analysis", source_url=base + "/",
                    confidence=75, passive=True,
                    evidence={"severity": "high",
                              "snippet": c[:160],
                              "remediation": ("Remove the credential from the "
                                              "HTML immediately and rotate "
                                              "it; strip comments from prod "
                                              "builds.")}))
                continue
            if TODO_RE.search(c):
                todo_hits += 1
            ih = INTERNAL_HOST_RE.search(c)
            if ih:
                internal_hits += 1
                findings.append(self._f(
                    "web", "comment_internal_host",
                    f"Internal hostname in HTML comment: {ih.group(1)}",
                    source="HTML comment analysis", source_url=base + "/",
                    confidence=80, passive=True,
                    evidence={"severity": "low", "host": ih.group(1),
                              "snippet": c[:160],
                              "remediation": ("Remove internal hostnames from "
                                              "prod HTML; they aid network "
                                              "mapping.")}))
            for u in URL_RE.findall(c):
                if len(u) > 8 and u not in endpoints and len(endpoints) < 30:
                    endpoints.add(u)
        if todo_hits:
            findings.append(self._f(
                "web", "comment_todos",
                f"{todo_hits} TODO/FIXME-style developer notes in HTML "
                "comments",
                source="HTML comment analysis", source_url=base + "/",
                confidence=70, passive=True,
                evidence={"severity": "low", "count": todo_hits,
                          "remediation": ("Strip dev notes from production "
                                          "HTML; they hint at unfinished "
                                          "security work.")}))
        for ep in sorted(endpoints)[:15]:
            ctx.publish("endpoints", ep)
        if endpoints:
            findings.append(self._f(
                "web", "comment_endpoints",
                f"{len(endpoints)} URLs/endpoints found in HTML comments",
                source="HTML comment analysis", source_url=base + "/",
                confidence=75, passive=True,
                evidence={"severity": "low",
                          "sample": sorted(endpoints)[:5],
                          "remediation": ("Review commented-out endpoints; "
                                          "remove dead code from prod.")}))
        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"mined {len(comments)} HTML comments: {secret_hits} "
                   f"credential patterns, {len(endpoints)} endpoints")
