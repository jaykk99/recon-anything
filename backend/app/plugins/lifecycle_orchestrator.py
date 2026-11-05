"""Full-lifecycle orchestration report (reconFTW / reNgine style).

reconFTW and reNgine earn their keep by chaining: assets feed JS
analysis, JS feeds endpoint discovery, endpoints feed verification,
and the operator gets ONE risk-ranked answer instead of six plugin
dumps. ReconAnything already has the stages as plugins; this
meta-plugin is the chain, run as a phase-2 finisher:

  Stage 1 ASSETS      subdomains / endpoints / JS files / tech from
                      the discovery bus (or a self-serve homepage
                      pass when the bus is empty, so it also works
                      standalone).
  Stage 2 SURFACE     every candidate endpoint scored by shape
                      (admin / backup / config / api / debug /
                      upload / auth / params).
  Stage 3 VERIFY      the top candidates are probed once (read-only
                      GET via the shared probe cache) - a candidate
                      that does not answer is not a priority.
  Stage 4 PRIORITIZE  one risk-ranked report finding plus an
                      individual priority finding per top live
                      target, each with its remediation. This is the
                      post-recon value: what to fix first, and how.

Silent when nothing is live and interesting - a clean target gets
no report noise.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Dict, List, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .injutil import same_domain

SCORE_HINTS = [
    (".env", 9), (".git", 9), ("backup", 7), ("config", 7),
    ("admin", 6), ("debug", 6), ("internal", 6), ("upload", 5),
    ("phpmyadmin", 7), ("setup", 5), ("install", 5), ("api", 3),
    ("login", 3), ("auth", 3), ("graphql", 4), ("swagger", 4),
    ("actuator", 6), ("manager", 4), ("console", 4),
]
REMEDIATION = {
    "backup": "Move backups out of the document root and deny web access to archive/database files.",
    "config": "Remove config files from web reach and serve configuration from outside the document root.",
    ".env": "Remove .env from the document root, deny dotfile access, and rotate the secrets it named.",
    ".git": "Block /.git at the web server or strip repository metadata from the deployment.",
    "admin": "Put the admin surface behind SSO/VPN or IP allowlisting and enforce MFA.",
    "debug": "Disable debug endpoints and verbose errors in production.",
    "internal": "Restrict internal endpoints to trusted networks; they are not public surface.",
    "upload": "Validate upload types server-side and store uploads outside the executable web root.",
    "api": "Enforce authentication and object-level authorization on this API endpoint.",
}
MAX_VERIFY = 10
MAX_PRIORITY = 5


def _score(url: str) -> Tuple[int, str]:
    low = url.lower()
    score, why = 0, ""
    for hint, pts in SCORE_HINTS:
        if hint in low and pts > score:
            score, why = pts, hint
    if "?" in url and "=" in url:
        score += 2
        why = why or "parameterised"
    return score, why


def _remediation_for(why: str) -> str:
    return REMEDIATION.get(
        why, "Review this live endpoint; restrict or remove it if it "
             "is not intentional public surface, then re-scan.")


class LifecycleOrchestratorPlugin(Plugin):
    id = "lifecycle_orchestrator"
    label = "Lifecycle Orchestrator (reconFTW-style)"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "graph"
    phase = 2
    timeout_s = 90
    description = ("Chains the run's discovery bus through surface "
                   "scoring, live verification and risk ranking, and "
                   "emits one prioritized fix-first report with "
                   "per-target remediation.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        start = time.time()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._ok([], "not a web target")
        base = await web_base(ctx, target, domain)

        subdomains = [s for s in ctx.consume("subdomains")
                      if isinstance(s, str)]
        js_files = [s for s in ctx.consume("js_files")
                    if isinstance(s, str)]
        tech = [s for s in ctx.consume("tech") if isinstance(s, str)]
        endpoints: List[str] = []
        seen_ep = set()
        for item in ctx.consume("endpoints"):
            if isinstance(item, str) and same_domain(item, domain) \
                    and item not in seen_ep:
                seen_ep.add(item)
                endpoints.append(item)

        # Standalone fallback: a light homepage pass so the chain has
        # inputs even when no phase-1 plugin populated the bus.
        if not endpoints and not subdomains:
            page = await ctx.fetch_page(base)
            if page:
                html = page.get("text") or ""
                root = urlparse(base)
                for m in re.finditer(
                        r'(?:href|src)=["\']([^"\']+)["\']', html, re.I):
                    u = urljoin(base, m.group(1))
                    if not same_domain(u, domain):
                        continue
                    if u.lower().endswith((".js",)):
                        if u not in js_files:
                            js_files.append(u)
                            ctx.publish("js_files", u)
                    elif not u.lower().endswith(
                            (".css", ".png", ".jpg", ".svg", ".ico",
                             ".woff", ".woff2")):
                        clean = u.split("#")[0]
                        if clean not in seen_ep:
                            seen_ep.add(clean)
                            endpoints.append(clean)
                            ctx.publish("endpoints", clean)

        scored = sorted(
            ((s, w, e) for e in endpoints
             for s, w in [_score(e)] if s > 0),
            key=lambda x: -x[0])[:MAX_VERIFY]
        if not scored:
            return self._ok([], "lifecycle chain found assets but no "
                                "scored live-surface candidates")

        sem = asyncio.Semaphore(5)

        async def verify(item: Tuple[int, str, str]):
            score, why, url = item
            async with sem:
                resp = await ctx.probe(url, timeout=8)
            status = int(resp.get("status") or 0) if resp else 0
            return (score, why, url, status)

        verified = await asyncio.gather(*(verify(s) for s in scored))
        live = [v for v in verified
                if v[3] in (200, 201, 204, 301, 302, 307, 308, 401, 403)]
        if not live:
            return self._ok([], "lifecycle chain: scored candidates "
                                "did not answer live probes")

        findings: List[Finding] = []
        for score, why, url, status in live[:MAX_PRIORITY]:
            severity = "high" if score >= 7 else (
                "medium" if score >= 4 else "low")
            findings.append(self._f(
                "graph", "lifecycle_priority_target",
                f"Priority {score}/10: {url} is live (HTTP {status}) - "
                f"{why} surface",
                source="lifecycle orchestrator", source_url=url,
                confidence=80, passive=False,
                evidence={"severity": severity, "score": score,
                          "signal": why, "status": status,
                          "remediation": _remediation_for(why)}))
        top_score = live[0][0]
        report_sev = "high" if top_score >= 7 else (
            "medium" if top_score >= 4 else "low")
        findings.append(self._f(
            "graph", "lifecycle_risk_report",
            f"Lifecycle scan of {domain}: {len(subdomains)} "
            f"subdomains, {len(endpoints)} endpoints, "
            f"{len(js_files)} JS files, {len(live)} verified live "
            f"priority targets (top score {top_score}/10)",
            source="lifecycle orchestrator", source_url=base,
            confidence=85, passive=False,
            evidence={
                "severity": report_sev,
                "stages": {
                    "assets": {"subdomains": len(subdomains),
                               "endpoints": len(endpoints),
                               "js_files": len(js_files),
                               "tech": tech[:10]},
                    "verified_live": len(live),
                    "top_targets": [
                        {"url": u, "score": s, "signal": w,
                         "status": st}
                        for s, w, u, st in live[:MAX_PRIORITY]],
                },
                "remediation": ("Work the priority targets in score "
                                "order; each carries its own fix. "
                                "Re-run the scan after fixes to "
                                "verify the surface shrank.")}))
        result = self._ok(findings,
                          f"lifecycle chain complete: {len(live)} "
                          f"live priority targets")
        result.duration_ms = int((time.time() - start) * 1000)
        return result
