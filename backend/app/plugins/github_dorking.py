"""GitHub secret-dorking plugin (passive, read-only).

Hunts for accidentally committed secrets tied to the target using
secret-dork patterns. Works with ZERO API keys:

- Keyless: Sourcegraph public code search API (no auth needed) runs the
  highest-signal dorks automatically.
- Keyless: clickable GitHub/Sourcegraph/Google dork URLs for manual review.
- Enhanced: GITHUB_TOKEN unlocks the GitHub code search API directly
  (higher limits, richer results).

Never clones repos, never touches code - search APIs only.
"""
from __future__ import annotations

import json
import time
from typing import List
from urllib.parse import quote_plus

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, safe_json_dict

# (dork suffix, label, severity) - full query becomes '"{domain}" ' + suffix
SECRET_DORKS = [
    ("filename:.env", "env files", "high"),
    ("filename:id_rsa", "private SSH keys", "critical"),
    ("extension:pem", "PEM keys/certs", "high"),
    ("filename:.pem", "PEM files", "high"),
    ("filename:credentials.json", "credential files", "high"),
    ("filename:secrets.yaml", "secret configs", "high"),
    ("api_key", "API keys", "high"),
    ("apikey", "API keys", "high"),
    ("password", "passwords", "medium"),
    ("secret", "secrets", "medium"),
    ("aws_access_key_id", "AWS keys", "critical"),
    ("xoxb-", "Slack tokens", "high"),
    ("ghp_", "GitHub tokens", "critical"),
    ("BEGIN RSA PRIVATE KEY", "private keys", "critical"),
]

REMEDIATION = ("Rotate every exposed credential immediately, purge it from "
               "git history (BFG / filter-repo), and add the pattern to "
               "pre-commit secret scanning.")


class GithubDorkingPlugin(Plugin):
    id = "github_dorking"
    label = "GitHub Secret Dorks"
    accepts = ["domain", "url"]
    requires_keys = []  # works keyless; GITHUB_TOKEN only enhances limits
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = ("Secret dorking for committed secrets: keyless Sourcegraph "
                   "code search + clickable dork links. GITHUB_TOKEN (optional) "
                   "adds GitHub API results.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []

        # Manual dork links always work - Jay can click through in the UI.
        dork_links = []
        for suffix, label, _sev in SECRET_DORKS[:6]:
            q = quote_plus(f'"{domain}" {suffix}')
            dork_links.append(f"https://github.com/search?q={q}&type=code")
        findings.append(self._f(
            "identity", "github_dork_links",
            f"Secret-dork links for {domain}: " + " | ".join(
                f"{label}" for _, label, _ in SECRET_DORKS[:6]),
            source="GitHub dorks",
            source_url=dork_links[0],
            confidence=50, passive=True,
            evidence={"severity": "low",
                      "remediation": "Review the linked searches for committed secrets.",
                      "dork_urls": dork_links}))

        token = ctx.keys.get("github_token")
        if not token:
            # Keyless path: Sourcegraph public code search (no auth needed).
            sg_findings = await self._sourcegraph_search(ctx, domain)
            findings.extend(sg_findings)
            note = (f"keyless: Sourcegraph code search ran ({len(sg_findings)} "
                    f"hit(s)); GITHUB_TOKEN would add GitHub API results")
            res = self._ok(findings, note)
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        headers = {"Authorization": f"Bearer {token}",
                   "Accept": "application/vnd.github+json"}
        # Run the highest-signal dorks live (rate-limited, small set).
        for suffix, label, sev in SECRET_DORKS[:8]:
            query = f'"{domain}" {suffix}'
            api_url = ("https://api.github.com/search/code?q=" +
                       quote_plus(query) + "&per_page=5")
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", api_url,
                                timeout=15, headers=headers)
            except Exception:
                continue
            if r.status_code == 403:
                findings.append(self._f(
                    "identity", "github_dork_ratelimited",
                    "GitHub code search rate-limited - use the manual dork links",
                    source="GitHub API", confidence=40, passive=True))
                break
            if r.status_code != 200:
                continue
            try:
                data = r.json()
            except Exception:
                continue
            total = data.get("total_count", 0)
            if total > 0:
                findings.append(self._f(
                    "leak", "github_secret_dork_hit",
                    f"{sev.upper()}: GitHub code search found {total} result(s) for "
                    f'dork "{query}" ({label}) - possible committed secret',
                    source="GitHub code search",
                    source_url="https://github.com/search?q=" + quote_plus(query) + "&type=code",
                    confidence=80, passive=True,
                    exploitability="public_poc",
                    evidence={"severity": sev, "remediation": REMEDIATION,
                              "dork": query, "result_count": total}))
                for item in data.get("items", [])[:5]:
                    repo = item.get("repository", {}).get("full_name", "?")
                    path = item.get("path", "?")
                    findings.append(self._f(
                        "leak", "github_secret_file",
                        f"{sev.upper()}: {repo}: {path} (dork: {suffix})",
                        source="GitHub code search",
                        source_url=item.get("html_url", ""),
                        confidence=75, passive=True,
                        exploitability="public_poc",
                        evidence={"severity": sev, "remediation": REMEDIATION}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"ran {min(8, len(SECRET_DORKS))} secret dorks")
        res.duration_ms = dur
        return res
