"""Authenticated-surface detector (passive discovery, read-only).

Finds places where authenticated testing could start: signup/register
pages, trial flows, and exposed collaboration/dev platforms (Jira,
Confluence, GitLab, Jenkins). Detection only - never creates accounts,
never attempts logins.

Each hit is reported as an "authenticated testing opportunity" with the
URL, so Jay knows where to point manual testing.
"""
from __future__ import annotations

import re
import time
from typing import List, Optional, Tuple

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (path, marker_re, key, title, severity, confidence)
AUTH_PROBES = [
    ("/signup", r"sign.?up|create.?account|register",
     "signup_page", "Signup page", "low", 80),
    ("/register", r"register|create.?account",
     "signup_page", "Registration page", "low", 80),
    ("/trial", r"trial|start.?free",
     "trial_flow", "Trial signup flow", "low", 75),
    ("/pricing", r"pricing|plans",
     "pricing_page", "Pricing page (account tiers)", "low", 70),
]

# (path, marker_re, key, title, severity, confidence, remediation)
PLATFORM_PROBES = [
    ("/secure/Dashboard.jspa", r"jira|atlassian",
     "jira_exposed", "Jira exposed", "medium", 85,
     "Restrict Jira to VPN/SSO. Anonymous access leaks project and user data."),
    ("/login.action", r"confluence|atlassian",
     "confluence_exposed", "Confluence exposed", "medium", 85,
     "Restrict Confluence to VPN/SSO. Old versions have RCE CVEs - check the version."),
    ("/users/sign_in", r"gitlab",
     "gitlab_exposed", "GitLab exposed", "medium", 88,
     "Restrict GitLab to VPN/SSO. Check the version against known GitLab RCE CVEs."),
    ("/login", r"jenkins",
     "jenkins_exposed", "Jenkins exposed", "high", 88,
     "Jenkins must never be internet-facing. Restrict to VPN immediately."),
    ("/grafana/login", r"grafana",
     "grafana_exposed", "Grafana exposed", "medium", 85,
     "Put Grafana behind VPN/SSO. Check for default admin/admin."),
]

REMEDIATION_AUTH = ("Review the auth surface: enforce rate limiting and "
                    "CAPTCHA on signup/login, require email verification, "
                    "and test for user enumeration and auth bypass.")


class AuthSurfacePlugin(Plugin):
    id = "auth_surface"
    label = "Auth Surface Map"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Find signup flows and exposed Jira/Confluence/GitLab/Jenkins."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []

        async def probe(path: str, marker: str) -> Optional[Tuple[str, str]]:
            full = base + path
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", full, timeout=10)
            except Exception:
                return None
            if r.status_code == 200 and re.search(marker, r.text[:20000], re.I):
                return full, r.text[:200]
            return None

        for path, marker, key, title, sev, conf in AUTH_PROBES:
            hit = await probe(path, marker)
            if hit:
                full, _ = hit
                findings.append(self._f(
                    "web", key,
                    f"Authenticated testing opportunity: {title} at {full} - "
                    f"test signup for enumeration, rate limits, and verification bypass",
                    source="auth surface", source_url=full,
                    confidence=conf, passive=True,
                    evidence={"severity": sev, "remediation": REMEDIATION_AUTH}))

        for path, marker, key, title, sev, conf, remediation in PLATFORM_PROBES:
            hit = await probe(path, marker)
            if hit:
                full, _ = hit
                findings.append(self._f(
                    "web", key,
                    f"{sev.upper()}: {title} reachable at {full} - authenticated "
                    f"testing opportunity (detection only, no login attempted)",
                    source="auth surface", source_url=full,
                    confidence=conf, passive=True,
                    exploitability="public_poc" if sev in ("high", "medium") else "unknown",
                    evidence={"severity": sev, "remediation": remediation}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(findings)} auth-surface hits")
        res.duration_ms = dur
        return res
