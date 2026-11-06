"""Nuclei CVE pack: curated template-style CVE checks (Tier-4 Vuln/CVE).

Companion to the existing plugins on master:
  * ``cves`` (id "cves") is a broad version-aware CVE matcher covering
    Apache/nginx/IIS/PHP/WordPress/Tomcat/Jenkins/Grafana and ~60 more
    products from Server / X-Powered-By / generator / JS signals.
  * PR #118's beyond-recon batch added a nuclei-style template engine
    (generic YAML template execution).

This plugin is the piece neither covers: a CURATED PACK of
nuclei-style templates (id / severity / matchers / version condition /
CVE) for products the ``cves`` database does NOT carry - Jetty,
lighttpd, vBulletin, Roundcube, Zimbra, Moodle, MediaWiki, phpBB,
WildFly, Exchange OWA - evaluated with the same matcher semantics
(status + header/body regex + version comparison). Detection only:
safe GET of the homepage, version strings matched, never exploited.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def _parse_version(s: str) -> Tuple[int, ...]:
    parts = []
    for chunk in re.split(r"[.\-+_]", s or ""):
        m = re.match(r"(\d+)", chunk)
        if m:
            parts.append(int(m.group(1)))
        else:
            break
    return tuple(parts) or (0,)


def _cmp(v: Tuple[int, ...], ref: Tuple[int, ...]) -> int:
    n = max(len(v), len(ref))
    vv = v + (0,) * (n - len(v))
    rr = ref + (0,) * (n - len(ref))
    return (vv > rr) - (vv < rr)


def _check(op: str, ver: Tuple[int, ...], ref: str) -> bool:
    c = _cmp(ver, _parse_version(ref))
    return {"<": c < 0, "<=": c <= 0, "==": c == 0, ">=": c >= 0}[op]


# Nuclei-style templates. source: "server" | "powered_by" | "body" |
# "header:<lowercase-name>". version_re captures the version in group 1.
# checks: (op, ref_version, cve, severity, title). ANY check may fire.
TEMPLATES: List[Dict] = [
    {"id": "jetty-info-disclosure", "software": "Eclipse Jetty",
     "source": "server", "version_re": r"jetty\((\d+\.\d+\.\d+)",
     "checks": [("<", "9.4.39", "CVE-2021-28164", "high",
                 "Jetty < 9.4.39 WEB-INF information disclosure via "
                 "specially encoded URIs")]},
    {"id": "jetty-cookie-parsing", "software": "Eclipse Jetty",
     "source": "server", "version_re": r"jetty\((\d+\.\d+\.\d+)",
     "checks": [("<", "9.4.51", "CVE-2023-26049", "medium",
                 "Jetty < 9.4.51 nonstandard cookie parsing can "
                 "smuggle session data")]},
    {"id": "lighttpd-mod-alias-traversal", "software": "lighttpd",
     "source": "server", "version_re": r"lighttpd/(\d+\.\d+\.\d+)",
     "checks": [("<", "1.4.52", "CVE-2018-19052", "medium",
                 "lighttpd < 1.4.52 mod_alias path traversal")]},
    {"id": "vbulletin-widget-rce", "software": "vBulletin",
     "source": "body", "version_re": r"vbulletin[^<]{0,40}?(\d+\.\d+\.\d+)",
     "checks": [("<", "5.5.5", "CVE-2019-16759", "high",
                 "vBulletin 5.x < 5.5.5 unauthenticated widget RCE "
                 "(public exploit)")]},
    {"id": "roundcube-stored-xss", "software": "Roundcube Webmail",
     "source": "body", "version_re": r"roundcube[^<]{0,40}?(\d+\.\d+\.\d+)",
     "checks": [("<", "1.4.10", "CVE-2020-35730", "medium",
                 "Roundcube < 1.4.10 stored XSS via malicious email")]},
    {"id": "zimbra-memcache-xxe", "software": "Zimbra",
     "source": "body", "version_re": r"zimbra[^<]{0,40}?(\d+\.\d+\.\d+)",
     "checks": [("<", "8.8.12", "CVE-2019-9670", "high",
                 "Zimbra < 8.8.12 Synacor memcached XXE leading to "
                 "credential exposure")]},
    {"id": "moodle-calculated-question-rce", "software": "Moodle",
     "source": "body", "version_re": r"moodle[^<]{0,40}?(\d+\.\d+\.\d+)",
     "checks": [("<", "3.5.3", "CVE-2018-14630", "high",
                 "Moodle < 3.5.3 calculated-question RCE (teacher role)")]},
    {"id": "mediawiki-eol", "software": "MediaWiki",
     "source": "body",
     "version_re": r'content="mediawiki (\d+\.\d+\.\d+)',
     "checks": [("<", "1.35.0", "EOL", "medium",
                 "MediaWiki < 1.35 is end-of-life (no security "
                 "releases since 2020)")]},
    {"id": "phpbb-eol", "software": "phpBB",
     "source": "body", "version_re": r"phpbb[^<]{0,40}?(\d+\.\d+\.\d+)",
     "checks": [("<", "3.3.0", "EOL", "medium",
                 "phpBB < 3.3 is end-of-life; unpatched XSS/CSRF "
                 "issues accumulate")]},
    {"id": "wildfly-eol", "software": "WildFly / JBoss AS",
     "source": "server", "version_re": r"wildfly(?:/|\s)(\d+\.\d+)",
     "checks": [("<", "11.0.0", "EOL", "medium",
                 "WildFly < 11 is end-of-life (2017-era Undertow/JBoss "
                 "stack, unpatched)")]},
    {"id": "exchange-owa-proxylogon-era", "software": "Exchange OWA",
     "source": "header:x-owa-version",
     "version_re": r"(\d+\.\d+\.\d+\.\d+)",
     "checks": [("<", "15.2.0", "CVE-2021-26855", "high",
                 "Exchange OWA build from the ProxyLogon era "
                 "(< 15.2): verify CU level - SSRF CVE-2021-26855 "
                 "was mass-exploited")]},
]


def evaluate_templates(signals: Dict[str, str]) -> List[Dict]:
    """Pure matcher: signals {server, powered_by, body, header:<n>} ->
    fired template hits. Unit-testable without any network."""
    hits: List[Dict] = []
    for tpl in TEMPLATES:
        raw = signals.get(tpl["source"], "") or ""
        m = re.search(tpl["version_re"], raw, re.I)
        if not m:
            continue
        ver_s = m.group(1)
        ver = _parse_version(ver_s)
        for op, ref, cve, sev, title in tpl["checks"]:
            if _check(op, ver, ref):
                hits.append({"template": tpl["id"], "software":
                             tpl["software"], "version": ver_s,
                             "cve": cve, "severity": sev, "title": title})
    return hits


class NucleiCvePackPlugin(Plugin):
    id = "nuclei_cve_pack"
    label = "Nuclei CVE Pack"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Curated nuclei-style CVE template pack for products "
                   "the main CVE matcher does not carry (Jetty, lighttpd, "
                   "vBulletin, Roundcube, Zimbra, Moodle, MediaWiki, "
                   "phpBB, WildFly, Exchange OWA). Version-match only.")
    timeout_s = 45

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        page = await ctx.fetch_page(base + "/", timeout=12)
        if page is None:
            return self._degraded("homepage unreachable")
        headers = {str(k).lower(): str(v)
                   for k, v in dict(page.get("headers") or {}).items()}
        signals: Dict[str, str] = {
            "server": headers.get("server", ""),
            "powered_by": headers.get("x-powered-by", ""),
            "body": (page.get("text") or "")[:200000],
        }
        for name, val in headers.items():
            signals[f"header:{name}"] = val
        findings: List[Finding] = []
        for hit in evaluate_templates(signals):
            findings.append(self._f(
                "web", "nuclei_cve_match",
                f"{hit['software']} {hit['version']} - {hit['cve']}: "
                f"{hit['title']} (template {hit['template']})",
                source="nuclei cve pack", source_url=base + "/",
                confidence=85, passive=True,
                evidence={"severity": hit["severity"], "cve": hit["cve"],
                          "template": hit["template"],
                          "software": hit["software"],
                          "version": hit["version"],
                          "remediation": (
                              f"Upgrade {hit['software']} past the "
                              f"vulnerable range for {hit['cve']} and "
                              "re-scan to verify the banner changed.")}))
        return PluginResult(
            plugin_id=self.id, status="ok", findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"evaluated {len(TEMPLATES)} pack templates, "
                   f"{len(findings)} CVE matches")
