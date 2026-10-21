"""Threat intel monitor: continuous CVE watch for the target's detected tech stack.

Consumes technologies published to the discovery bus (e.g. "Apache 2.4.49",
"WordPress 6.2", "jQuery 3.6.0") and checks the public NVD API 2.0
(https://services.nvd.nist.gov/rest/json/cves/2.0 - keyless) for CVEs
affecting them. CVEs published in the last 30 days are flagged as NEW
threats; older unpatched CVEs matching the exact version are flagged too.

This is threat INTELLIGENCE, not exploitation: it reads public disclosure
feeds and reports what was published. No payloads, no probes, no logins.

Phase 2 chain plugin: runs after tech discovery so the stack is known.
Keyless. GET only. Respects NVD's keyless rate limit (5 req / 30s) with
built-in pacing. Reported CVE IDs are cached so repeat scans don't
re-report the same CVE.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import re
from typing import Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, safe_json_dict

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# How far back counts as "NEW" (published within this window = fresh threat)
NEW_WINDOW_DAYS = 30

# Tech name -> NVD keyword search terms. NVD keywordSearch is fuzzy, so
# keep terms short and product-specific.
TECH_KEYWORDS: Dict[str, List[str]] = {
    "apache": ["apache http server"],
    "nginx": ["nginx"],
    "wordpress": ["wordpress"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "php": ["php"],
    "jquery": ["jquery"],
    "bootstrap": ["bootstrap"],
    "angular": ["angularjs", "angular"],
    "react": ["react"],
    "vue": ["vue.js"],
    "lodash": ["lodash"],
    "moment": ["moment.js"],
    "django": ["django"],
    "laravel": ["laravel"],
    "rails": ["ruby on rails"],
    "spring": ["spring framework"],
    "express": ["express"],
    "node": ["node.js"],
    "mysql": ["mysql"],
    "postgresql": ["postgresql"],
    "mongodb": ["mongodb"],
    "redis": ["redis"],
    "elasticsearch": ["elasticsearch"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "grafana": ["grafana"],
    "tomcat": ["apache tomcat"],
    "iis": ["internet information services"],
    "openssl": ["openssl"],
    "openresty": ["openresty"],
    "cloudflare": ["cloudflare"],
    "varnish": ["varnish"],
    "haproxy": ["haproxy"],
    "traefik": ["traefik"],
    "caddy": ["caddy"],
    "next.js": ["next.js"],
    "nuxt": ["nuxt.js"],
    "strapi": ["strapi"],
    "ghost": ["ghost"],
    "magento": ["magento"],
    "prestashop": ["prestashop"],
    "woocommerce": ["woocommerce"],
    "phpmyadmin": ["phpmyadmin"],
    "webmin": ["webmin"],
    "cpanel": ["cpanel"],
    "plesk": ["plesk"],
    "exim": ["exim"],
    "postfix": ["postfix"],
    "dovecot": ["dovecot"],
    "bind": ["bind"],
    "samba": ["samba"],
    "docker": ["docker"],
    "kubernetes": ["kubernetes"],
    "etcd": ["etcd"],
    "consul": ["consul"],
    "rabbitmq": ["rabbitmq"],
    "kafka": ["apache kafka"],
    "solr": ["apache solr"],
    "struts": ["apache struts"],
    "log4j": ["log4j"],
    "shiro": ["apache shiro"],
    "weblogic": ["weblogic"],
    "websphere": ["websphere"],
    "jboss": ["jboss"],
    "sharepoint": ["sharepoint"],
    "exchange": ["microsoft exchange"],
}

REMEDIATION = ("A new public CVE affects software on this target. Patch to "
               "the fixed version immediately, or apply the vendor's "
               "mitigation. Verify with a re-scan after patching.")


def _parse_tech(entry: str) -> Tuple[str, str]:
    """'Apache 2.4.49' -> ('apache', '2.4.49'). 'WordPress' -> ('wordpress', '')."""
    entry = (entry or "").strip()
    m = re.match(r"^([A-Za-z][A-Za-z0-9.\-+# ]*?)\s*([\d][\d.\-a-zA-Z]*)\s*$", entry)
    if m:
        return m.group(1).strip().lower(), m.group(2).strip()
    return entry.lower(), ""


def _keywords_for(tech_name: str) -> List[str]:
    name = tech_name.lower()
    for key, kws in TECH_KEYWORDS.items():
        if key in name or name in key:
            return kws
    # Fallback: use the raw name as a keyword
    return [name]


def _cvss_and_severity(cve: Dict) -> Tuple[float, str]:
    """Extract (baseScore, severity) from NVD metrics, preferring v3.1 > v3.0 > v2."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = (entries[0] or {}).get("cvssData") or {}
            score = data.get("baseScore")
            sev = (data.get("baseSeverity") or "").upper()
            try:
                return float(score), sev
            except (TypeError, ValueError):
                continue
    return 0.0, ""


def _description(cve: Dict) -> str:
    for d in cve.get("descriptions") or []:
        if (d or {}).get("lang") == "en":
            return (d.get("value") or "")[:400]
    descs = cve.get("descriptions") or []
    if descs:
        return str((descs[0] or {}).get("value") or "")[:400]
    return ""


def _published_dt(cve: Dict) -> Optional[dt.datetime]:
    pub = cve.get("published") or ""
    try:
        # NVD format: "2024-01-15T14:15:00.000" (may lack timezone)
        d = dt.datetime.fromisoformat(pub.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=dt.timezone.utc)
        return d
    except (ValueError, AttributeError):
        return None


class ThreatMonitorPlugin(Plugin):
    id = "threat_monitor"
    label = "Threat Intel Monitor"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Watches public CVE feeds (NVD) for new vulnerabilities "
                   "affecting the target's detected tech stack.")
    phase = 2  # runs after tech discovery populates the bus
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        findings: List[Finding] = []

        # 1. Collect technologies from the discovery bus + direct header sniff
        techs: List[str] = []
        for t in ctx.consume("tech"):
            if isinstance(t, str) and t.strip():
                techs.append(t.strip())
        # Belt and suspenders: grab Server header ourselves too
        try:
            domain = domain_from_target(target.type, target.normalized)
            resp = await fetch(ctx.http, ctx.limiter, "HEAD",
                               f"https://{domain}/", timeout=10)
            server = resp.headers.get("server", "") or ""
            if server:
                techs.append(server.strip())
        except Exception:
            pass

        # Deduplicate (case-insensitive)
        seen = set()
        uniq_techs = []
        for t in techs:
            k = t.lower()
            if k not in seen:
                seen.add(k)
                uniq_techs.append(t)
        techs = uniq_techs[:8]  # cap: NVD rate limit is 5 req / 30s keyless

        if not techs:
            return self._ok([], "no technologies detected to monitor")

        # 2. Check cache for already-reported CVE IDs (dedup across runs)
        cache_key = f"threat_monitor:reported"
        reported: set = set(ctx.cache.get("threat", cache_key) or [])

        now = dt.datetime.now(dt.timezone.utc)
        new_window = dt.timedelta(days=NEW_WINDOW_DAYS)
        checked = 0
        new_cves = 0

        # Build the NVD query list first, then fetch in parallel chunks of 5
        # (NVD keyless limit is 5 req / 30s). The old code slept 7s between
        # every sequential request, burning ~60s of pure sleep and stalling
        # the whole scan.
        queries: List[Tuple[str, str]] = []
        for tech in techs:
            name, _version = _parse_tech(tech)
            keywords = _keywords_for(name)
            for kw in keywords[:1]:  # one keyword per tech to respect rate limit
                url = (f"{NVD_API}?keywordSearch={kw}"
                       f"&resultsPerPage=20")
                queries.append((tech, url))

        from ..ratelimit import fetch_many
        responses: List[Tuple[str, object]] = []
        for i in range(0, len(queries), 5):
            chunk = queries[i:i + 5]
            if i > 0:
                # NVD keyless: 5 requests per 30s rolling window
                await asyncio.sleep(7)
            resps = await fetch_many(
                ctx.http, ctx.limiter,
                [("GET", url) for _, url in chunk],
                concurrency=5, max_retries=1, timeout=15,
                headers={"User-Agent": "ReconAnything-threat-monitor/1.0"})
            responses.extend(zip([t for t, _ in chunk], resps))

        for tech, resp in responses:
            if resp is None:
                continue
            checked += 1
            try:
                if resp.status_code == 403:
                    return self._rate_limited("NVD rate limited (403) - try again later")
                if resp.status_code != 200:
                    continue
                data = safe_json_dict(resp)
                vulns = data.get("vulnerabilities") or []
                # Sort newest first client-side (NVD default order is oldest)
                vulns.sort(key=lambda v: ((v or {}).get("cve") or {}).get("published", ""),
                           reverse=True)
                vulns = vulns[:10]  # newest 10 only
                for item in vulns:
                    cve = (item or {}).get("cve") or {}
                    cve_id = cve.get("id") or ""
                    if not cve_id or cve_id in reported:
                        continue
                    score, sev = _cvss_and_severity(cve)
                    # Only flag meaningful vulns (CVSS 4.0+)
                    if score < 4.0:
                        continue
                    pub_dt = _published_dt(cve)
                    is_new = bool(pub_dt and (now - pub_dt) <= new_window)
                    desc = _description(cve)
                    refs = [r.get("url", "") for r in (cve.get("references") or [])[:3]]
                    ref_str = refs[0] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    when = pub_dt.strftime("%Y-%m-%d") if pub_dt else "unknown date"
                    tag = "NEW" if is_new else "unpatched"
                    value = (f"[{tag}] {cve_id} (CVSS {score}) affects {tech} "
                             f"- published {when}")
                    if is_new:
                        new_cves += 1
                    severity = "high" if score >= 7.0 else "medium"
                    exploit = "public_poc" if score >= 9.0 else "theoretical"
                    findings.append(self._f(
                        "infra", "new_cve", value,
                        "threat_monitor: NVD public feed",
                        source_url=ref_str,
                        confidence=90 if is_new else 75,
                        evidence={
                            "severity": severity,
                            "exploitability": exploit,
                            "remediation": REMEDIATION,
                            "cve_id": cve_id,
                            "cvss": score,
                            "published": when,
                            "is_new": is_new,
                            "tech": tech,
                            "description": desc,
                        },
                        bounty_value="high" if score >= 7.0 else "medium",
                    ))
                    reported.add(cve_id)
            except Exception:
                continue

        # 3. Persist reported CVE IDs so repeat scans don't re-report
        try:
            ctx.cache.set("threat", cache_key, sorted(reported), ttl=86400 * 7)
        except Exception:
            pass

        # 4. Publish a summary to the bus for other plugins
        for f in findings:
            ctx.publish("cves", f.evidence.get("cve_id", ""))

        reason = (f"checked {checked} tech stack items against NVD, "
                  f"{new_cves} new CVEs in last {NEW_WINDOW_DAYS}d, "
                  f"{len(findings)} total findings")
        return self._ok(findings, reason)
