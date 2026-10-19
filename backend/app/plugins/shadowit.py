"""Shadow IT detector: find unauthorized internal tools exposed publicly.

Scans for collaboration, dev, monitoring, and admin platforms that
should live behind a VPN but are reachable from the internet:
Jira, Confluence, GitLab, Jenkins, Grafana, Kibana, Jenkins,
TeamCity, CircleCI, Travis, SonarQube, Nexus, Artifactory,
phpMyAdmin, Adminer, cPanel, Plesk, Webmin, Splunk, etc.

Detection only: probes well-known paths and checks response markers.
Never attempts logins, never submits credentials, never exploits.
GET only. Respects rate limits.

Keyless. Each probe is a single GET with marker verification to
avoid false positives from generic 200 pages.
"""
from __future__ import annotations

import re
import time
from typing import List, Tuple

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


# (paths, marker_regex, key, title, severity, confidence, remediation)
SHADOW_PROBES: List[Tuple] = [
    # --- Collaboration / project management ---
    (["/secure/Dashboard.jspa", "/browse/"], r"jira|atlassian.*jira",
     "shadow_jira", "Shadow IT: Jira exposed", "medium", 85,
     "Jira should be behind VPN/SSO. Anonymous access leaks project data, "
     "user lists, and internal workflows."),
    (["/dashboard.action", "/display/"], r"confluence|atlassian.*confluence",
     "shadow_confluence", "Shadow IT: Confluence exposed", "medium", 85,
     "Confluence should be behind VPN/SSO. Old versions have critical RCE "
     "CVEs - check the version immediately."),
    (["/users/sign_in", "/explore"], r"gitlab",
     "shadow_gitlab", "Shadow IT: GitLab exposed", "medium", 88,
     "GitLab should be behind VPN/SSO. Check version against known RCE CVEs. "
     "Public repos may leak source code and secrets."),
    # --- CI/CD ---
    (["/login", "/script"], r"jenkins",
     "shadow_jenkins", "Shadow IT: Jenkins exposed", "high", 88,
     "Jenkins must NEVER be internet-facing. It has a long history of RCE. "
     "Restrict to VPN immediately."),
    (["/login.html", "/overview.html"], r"teamcity",
     "shadow_teamcity", "Shadow IT: TeamCity exposed", "high", 85,
     "TeamCity had critical auth-bypass CVEs (CVE-2024-27198). Must be "
     "behind VPN. Patch immediately."),
    (["/login"], r"circleci",
     "shadow_circleci", "Shadow IT: CircleCI exposed", "low", 70,
     "CI dashboard exposed. Verify no build logs or secrets are public."),
    (["/api/", "/ui/"], r"sonarqube|sonar",
     "shadow_sonarqube", "Shadow IT: SonarQube exposed", "medium", 80,
     "SonarQube exposes source code analysis. Restrict to VPN."),
    # --- Monitoring / observability ---
    (["/login", "/d/"], r"grafana",
     "shadow_grafana", "Shadow IT: Grafana exposed", "medium", 85,
     "Grafana behind VPN/SSO. Check for default admin/admin credentials "
     "(flag only - never attempt login)."),
    (["/app/kibana", "/login"], r"kibana|elastic",
     "shadow_kibana", "Shadow IT: Kibana exposed", "medium", 82,
     "Kibana exposes log data. Restrict to VPN."),
    (["/account/login", "/en-US/account/login"], r"splunk",
     "shadow_splunk", "Shadow IT: Splunk exposed", "medium", 80,
     "Splunk exposes log/search data. Restrict to VPN/SSO."),
    (["/login"], r"prometheus",
     "shadow_prometheus", "Shadow IT: Prometheus exposed", "medium", 80,
     "Prometheus /metrics may leak internal infrastructure details."),
    # --- Repo / artifact managers ---
    (["/service/rest/v1/status", "/#browse/browse"], r"nexus",
     "shadow_nexus", "Shadow IT: Nexus Repository exposed", "medium", 78,
     "Artifact repo exposed. May leak internal packages and credentials."),
    (["/ui/login", "/artifactory/"], r"artifactory|jfrog",
     "shadow_artifactory", "Shadow IT: Artifactory exposed", "medium", 78,
     "JFrog Artifactory exposed. Restrict to VPN."),
    # --- Database admin ---
    (["/phpmyadmin/", "/phpMyAdmin/"], r"phpmyadmin",
     "shadow_phpmyadmin", "Shadow IT: phpMyAdmin exposed", "high", 88,
     "phpMyAdmin must never be internet-facing. Restrict to VPN or remove."),
    (["/adminer.php", "/adminer/"], r"adminer",
     "shadow_adminer", "Shadow IT: Adminer exposed", "high", 85,
     "Adminer is a single-file DB admin - extremely dangerous if public. "
     "Remove or restrict to VPN immediately."),
    # --- Hosting control panels ---
    (["/cpanel", ":2083"], r"cpanel",
     "shadow_cpanel", "Shadow IT: cPanel exposed", "medium", 75,
     "cPanel login exposed. Ensure strong passwords and 2FA."),
    (["/login.php", ":8443"], r"plesk",
     "shadow_plesk", "Shadow IT: Plesk exposed", "medium", 75,
     "Plesk panel exposed. Restrict admin access to trusted IPs."),
    (["/", ":10000"], r"webmin|usermin",
     "shadow_webmin", "Shadow IT: Webmin exposed", "high", 80,
     "Webmin had critical RCE CVEs. Must be behind VPN."),
    # --- Misc internal tools ---
    (["/login", "/admin"], r"vault by hashicorp|hashicorp.*vault",
     "shadow_vault", "Shadow IT: HashiCorp Vault exposed", "high", 82,
     "Vault UI exposed. The API should never be internet-facing without "
     "mTLS. Restrict immediately."),
    (["/ui/", "/v1/sys/health"], r"consul by hashicorp|hashicorp.*consul",
     "shadow_consul", "Shadow IT: Consul exposed", "high", 80,
     "Consul exposes service discovery and KV data. Restrict to VPN."),
    (["/", "/_cat/indices"], r"elasticsearch",
     "shadow_elasticsearch", "Shadow IT: Elasticsearch exposed", "high", 85,
     "Elasticsearch with no auth exposes all indexed data. Enable security "
     "or restrict to VPN immediately."),
    (["/nifi/", "/nifi-api/"], r"nifi|apache nifi",
     "shadow_nifi", "Shadow IT: Apache NiFi exposed", "medium", 78,
     "NiFi data flows exposed. Restrict to VPN."),
    (["/login", "/superset/"], r"superset|apache.*superset",
     "shadow_superset", "Shadow IT: Superset exposed", "medium", 75,
     "BI dashboard exposed. May leak business data queries."),
]


class ShadowItPlugin(Plugin):
    id = "shadowit"
    label = "Shadow IT Detector"
    accepts = ["domain", "url"]
    passive = False  # sends light probes, but GET-only and rate-limited
    cost = Cost.FREE
    group = "infra"
    description = "Find unauthorized internal tools exposed to the internet."
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")
        seen_keys = set()

        for paths, marker_re, key, title, severity, confidence, remediation in SHADOW_PROBES:
            if key in seen_keys:
                continue
            marker = re.compile(marker_re, re.I)
            hit_url = None
            for path in paths:
                # Handle port-style paths like ":2083"
                url = f"{base}{path}" if not path.startswith(":") else f"{base}{path}/"
                try:
                    data = await ctx.probe(url, timeout=8)
                except Exception:
                    continue
                status = data.get("status", 0)
                text = data.get("text", "")
                headers = data.get("headers", {})
                if status in (200, 301, 302, 401, 403):
                    # Marker in body, title, or server header = real hit
                    haystack = f"{text[:8000]} {headers.get('server', '')} {headers.get('x-powered-by', '')}"
                    if marker.search(haystack):
                        hit_url = data.get("url", url)
                        break
                    # 401/403 on a known tool path is also a signal
                    if status in (401, 403) and len(text) > 100:
                        hit_url = data.get("url", url)
                        break
            if hit_url:
                seen_keys.add(key)
                findings.append(self._f(
                    "infra", key,
                    f"{title} at {hit_url}. Unauthorized internal tools "
                    f"exposed to the internet are a top breach vector.",
                    source="Shadow IT scan", source_url=hit_url,
                    confidence=confidence, passive=passive,
                    evidence={"severity": severity,
                              "remediation": remediation,
                              "tool": title.replace("Shadow IT: ", ""),
                              "url": hit_url}))

        # Publish to bus for assetgraph
        for f in findings:
            ctx.publish("shadow_it", f.evidence.get("tool", ""))

        reason = f"{len(findings)} shadow IT exposures found"
        res = self._ok(findings, reason)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
