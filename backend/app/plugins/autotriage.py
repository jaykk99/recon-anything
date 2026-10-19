"""Auto-triage: route discovered tech to the right scanner.

Consumes technologies from the discovery bus and builds a prioritized
scan plan: for each detected tech, it names the plugins that should
look at it hardest and flags version-specific checks.

Example: "WordPress 6.2" -> cms_probes (plugin slugs), cves (WP CVEs),
backup (wp-config.php.bak), gitleaks (wp secrets).

Also emits a "scan plan" finding: an ordered checklist Jay can follow
for manual testing, ranked by expected value.

Pure logic - no network calls. Keyless.
Phase 2 chain plugin: needs tech on the bus.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Set, Tuple

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


# tech pattern -> (priority plugins, manual checklist, severity)
TRIAGE_RULES: List[Tuple[str, List[str], List[str], str]] = [
    (r"wordpress", ["cms_probes", "cves", "backup", "gitleaks_scan", "jsdeep"],
     ["Check /wp-admin (default creds flag only)", "Enumerate plugins via /wp-content/plugins/",
      "Check for wp-config.php.bak", "Test REST API /wp-json/wp/v2/users"],
     "medium"),
    (r"drupal", ["cms_probes", "cves", "backup"],
     ["Check /user/login", "Test for CVE-2018-7600 (Drupalgeddon2) version",
      "Enumerate modules"],
     "medium"),
    (r"joomla", ["cms_probes", "cves"],
     ["Check /administrator/", "Version fingerprint for known CVEs"],
     "medium"),
    (r"jenkins", ["shadowit", "cves", "auth"],
     ["MUST be behind VPN - verify", "Check version for RCE CVEs",
      "Look for /script console exposure"],
     "high"),
    (r"gitlab", ["shadowit", "cves", "auth_surface"],
     ["Check version for RCE CVEs", "Look for public repos leaking code",
      "Test for user enumeration"],
     "medium"),
    (r"graphql", ["graphql", "apidiscover", "bola", "idor"],
     ["Run introspection query", "Test for BOLA on object queries",
      "Check for depth-limit / complexity bypass"],
     "medium"),
    (r"jwt|jsonwebtoken", ["jwt", "jwt_audit", "auth"],
     ["Check alg=none", "Check weak secrets (offline wordlist only)",
      "Check missing exp / long exp"],
     "medium"),
    (r"api", ["apidiscover", "bola", "idor", "param_fuzzer", "cors"],
     ["Map all endpoints", "Test BOLA with two accounts",
      "Fuzz parameters for behavior changes", "Check CORS misconfig"],
     "medium"),
    (r"nginx|apache|iis", ["cves", "headers", "tls", "infodisclosure"],
     ["Version -> CVE match", "Check server-status / server-info exposure",
      "Verify security headers"],
     "low"),
    (r"php", ["cves", "infodisclosure", "backup"],
     ["Check phpinfo exposure", "Look for .php.bak files",
      "Version -> CVE match"],
     "medium"),
    (r"node|express|next\.?js|nuxt", ["jsdeep", "sourcemap", "cves", "dependency_conf"],
     ["Download source maps", "Check for exposed .env",
      "Audit dependencies for known vulns"],
     "medium"),
    (r"django|laravel|rails|spring", ["misconfig", "cves", "infodisclosure"],
     ["Check for debug mode exposure", "Look for .env / secrets",
      "Version -> CVE match"],
     "medium"),
    (r"docker|kubernetes", ["docker", "k8s", "cloud_enum"],
     ["Check for exposed Docker socket", "Check K8s API exposure",
      "Look for exposed registries"],
     "high"),
    (r"elastic|solr", ["cves", "infodisclosure", "shadowit"],
     ["Check for unauthenticated access", "Version -> CVE match"],
     "high"),
    (r"shopify|squarespace|wix|wordpress.*commerce|magento",
     ["cms_probes", "blogic", "param_fuzzer"],
     ["Test price manipulation", "Check coupon logic",
      "Look for payment flow bypasses"],
     "medium"),
    (r"ethereum|solidity|smart.?contract|defi|bridge",
     ["contract_audit", "defi_risk", "meme_coin", "bridge", "chain_osint"],
     ["Static audit for reentrancy/access control",
      "Check for honeypot/rug-pull patterns", "Review bridge trust assumptions"],
     "medium"),
    (r"mysql|postgres|mongo|redis",
     ["port_audit", "db", "cves"],
     ["Verify not internet-exposed", "Check for default credentials (flag only)",
      "Version -> CVE match"],
     "high"),
]


class AutotriagePlugin(Plugin):
    id = "autotriage"
    label = "Auto Triage Router"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Route discovered tech to the right scanners; build manual test plan."
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        techs = []
        for t in ctx.consume("tech"):
            if isinstance(t, str) and t.strip():
                techs.append(t.strip())
        # dedup case-insensitive
        seen = set()
        uniq = []
        for t in techs:
            k = t.lower()
            if k not in seen:
                seen.add(k)
                uniq.append(t)
        techs = uniq[:30]

        if not techs:
            return self._ok([], "no technologies on bus to triage")

        findings: List[Finding] = []
        plan_lines: List[str] = []
        routed_plugins: Set = set()

        for tech in techs:
            for pat, plugins, checklist, sev in TRIAGE_RULES:
                if re.search(pat, tech, re.I):
                    for p in plugins:
                        routed_plugins.add(p)
                    plan_lines.append(f"## {tech}")
                    for item in checklist:
                        plan_lines.append(f"- [ ] {item}")
                    findings.append(self._f(
                        "web", "triage_route",
                        f"Triage: '{tech}' -> focus scanners: "
                        f"{', '.join(plugins)}",
                        source="Auto-triage", confidence=80,
                        evidence={"severity": sev,
                                  "remediation": "Run the listed scanners "
                                                 "against this technology, "
                                                 "then work the manual "
                                                 "checklist.",
                                  "tech": tech,
                                  "route_to": plugins,
                                  "manual_checklist": checklist}))
                    break  # first matching rule wins per tech

        # Emit the consolidated scan plan
        if plan_lines:
            findings.append(self._f(
                "web", "scan_plan",
                f"Scan plan for {domain}: {len(techs)} technologies triaged, "
                f"{len(routed_plugins)} scanners routed. Follow the checklist.",
                source="Auto-triage", confidence=90,
                evidence={"severity": "low",
                          "remediation": "Work through the checklist top to "
                                         "bottom. Highest-value targets first.",
                          "plan": "\n".join(plan_lines[:60]),
                          "routed_plugins": sorted(routed_plugins)}))
            for p in sorted(routed_plugins):
                ctx.publish("triage_route", p)

        reason = f"triaged {len(techs)} techs -> {len(routed_plugins)} scanners"
        res = self._ok(findings, reason)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
