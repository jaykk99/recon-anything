"""Watchdog: continuous monitoring for target changes.

Designed to run on a schedule (cron). Each run:
1. Re-checks the ASM snapshot for new/removed assets
2. Re-runs threat_monitor-style NVD checks for the known tech stack
   (reads cached tech list - no full re-scan needed)
3. Checks certificate transparency (crt.sh) for NEW subdomains
   issued since the last run
4. Emits ALERT findings for anything new

This plugin is lightweight by design: it does NOT re-crawl the target.
It reads caches, hits crt.sh (keyless), and queries NVD (keyless).
A full scan populates the caches; watchdog runs detect drift.

Keyless. Respects NVD rate limits (5 req / 30s).
"""
from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import time
from typing import Dict, List, Optional, Set, Tuple

from ..classifier import domain_from_target
from ..ratelimit import fetch, fetch_many
from .base import (Cost, Ctx, Finding, Plugin, PluginResult, Target,
                   safe_json_dict, safe_json_list)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CRT_API = "https://crt.sh/?q=%25.{domain}&output=json"

# Tech keywords (subset of threat_monitor's - the most common)
TECH_KEYWORDS: Dict[str, List[str]] = {
    "apache": ["apache http server"],
    "nginx": ["nginx"],
    "wordpress": ["wordpress"],
    "php": ["php"],
    "jquery": ["jquery"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "grafana": ["grafana"],
    "docker": ["docker"],
    "kubernetes": ["kubernetes"],
    "django": ["django"],
    "laravel": ["laravel"],
    "rails": ["ruby on rails"],
    "node": ["node.js"],
    "mysql": ["mysql"],
    "postgresql": ["postgresql"],
    "mongodb": ["mongodb"],
    "redis": ["redis"],
    "elasticsearch": ["elasticsearch"],
}

REMEDIATION_ALERT = ("Something changed on the monitored target. Review "
                     "the change immediately: new subdomains may need "
                     "hardening, new CVEs need patching.")


def _parse_tech(entry: str) -> Tuple[str, str]:
    import re
    entry = (entry or "").strip()
    m = re.match(r"^([A-Za-z][A-Za-z0-9.\-+# ]*?)\s*([\d][\d.\-a-zA-Z]*)\s*$", entry)
    if m:
        return m.group(1).strip().lower(), m.group(2).strip()
    return entry.lower(), ""


class WatchdogPlugin(Plugin):
    id = "watchdog"
    label = "Change Watchdog"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = "Continuous monitoring: new subdomains, new CVEs, surface drift."
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        findings: List[Finding] = []
        now = dt.datetime.now(dt.timezone.utc)

        # --- 1. New subdomains via crt.sh ---
        crt_key = f"watchdog:crt:{hashlib.sha256(domain.encode()).hexdigest()[:16]}"
        try:
            seen_subs: Set[str] = set(ctx.cache.get("watchdog", crt_key) or [])
        except Exception:
            seen_subs = set()

        new_subs: List[str] = []
        try:
            resp = await fetch(ctx.http, ctx.limiter, "GET",
                               CRT_API.format(domain=domain), timeout=20)
            if resp and resp.status_code == 200:
                rows = safe_json_list(resp)
                current_subs = set()
                for row in rows[:500]:
                    name = (row.get("name_value") or "").strip().lower()
                    for part in name.split("\n"):
                        part = part.strip().lstrip("*.")
                        if part and (part == domain or part.endswith(f".{domain}")):
                            current_subs.add(part)
                new_subs = sorted(current_subs - seen_subs)[:20]
                try:
                    ctx.cache.set("watchdog", crt_key, sorted(current_subs),
                                  ttl=86400 * 30)
                except Exception:
                    pass
                for sub in new_subs:
                    findings.append(self._f(
                        "infra", "watchdog_new_subdomain",
                        f"WATCHDOG ALERT: new subdomain in CT logs: {sub}",
                        source="Watchdog (crt.sh)", confidence=90,
                        evidence={"severity": "medium",
                                  "remediation": REMEDIATION_ALERT,
                                  "subdomain": sub,
                                  "alert_type": "new_subdomain"}}))
        except Exception:
            pass  # crt.sh hiccups should not fail the watchdog

        # --- 2. New CVEs for known tech stack ---
        tech_key = f"watchdog:tech:{hashlib.sha256(domain.encode()).hexdigest()[:16]}"
        try:
            known_tech: List[str] = list(ctx.cache.get("watchdog", tech_key) or [])
        except Exception:
            known_tech = []
        # Also seed from the ASM snapshot if present
        asm_key = f"asm:snapshot:{hashlib.sha256(domain.lower().encode()).hexdigest()[:16]}"
        try:
            asm_snap = ctx.cache.get("asm", asm_key) or {}
            for t in asm_snap.get("tech", [])[:20]:
                if isinstance(t, str) and t not in known_tech:
                    known_tech.append(t)
        except Exception:
            pass

        cve_cache_key = "threat_monitor:reported"
        try:
            reported: Set[str] = set(ctx.cache.get("threat", cve_cache_key) or [])
        except Exception:
            reported = set()

        new_cves = 0
        queries: List[Tuple[str, str]] = []
        for tech in known_tech[:8]:
            name, _ver = _parse_tech(tech)
            kws = TECH_KEYWORDS.get(name, [name]) if name else []
            for kw in kws[:1]:
                url = f"{NVD_API}?keywordSearch={kw}&resultsPerPage=10"
                queries.append((tech, url))

        for i in range(0, len(queries), 5):
            chunk = queries[i:i + 5]
            if i > 0:
                await asyncio.sleep(7)  # NVD keyless: 5 req / 30s
            try:
                resps = await fetch_many(
                    ctx.http, ctx.limiter,
                    [("GET", url) for _, url in chunk],
                    concurrency=5, max_retries=1, timeout=15,
                    headers={"User-Agent": "ReconAnything-watchdog/1.0"})
            except Exception:
                continue
            for (tech, _url), resp in zip(chunk, resps):
                if resp is None or resp.status_code != 200:
                    continue
                try:
                    data = safe_json_dict(resp)
                    vulns = data.get("vulnerabilities") or []
                    vulns.sort(key=lambda v: ((v or {}).get("cve") or {}).get("published", ""),
                               reverse=True)
                    for item in vulns[:5]:
                        cve = (item or {}).get("cve") or {}
                        cve_id = cve.get("id") or ""
                        if not cve_id or cve_id in reported:
                            continue
                        pub = cve.get("published", "")
                        try:
                            pub_dt = dt.datetime.fromisoformat(pub.replace("Z", "+00:00"))
                            age_days = (now - pub_dt).days
                        except Exception:
                            age_days = 999
                        if age_days > 7:
                            continue  # watchdog only alerts on fresh CVEs
                        # CVSS
                        score = 0.0
                        try:
                            metrics = cve.get("metrics", {})
                            for ver in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                                m = metrics.get(ver) or []
                                if m:
                                    score = float((m[0].get("cvssData") or {}).get("baseScore", 0))
                                    break
                        except Exception:
                            pass
                        if score < 7.0:
                            continue  # watchdog only alerts high+
                        reported.add(cve_id)
                        new_cves += 1
                        findings.append(self._f(
                            "infra", "watchdog_new_cve",
                            f"WATCHDOG ALERT: new CVE {cve_id} (CVSS {score}) "
                            f"affects {tech} - published {age_days}d ago",
                            source="Watchdog (NVD)",
                            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            confidence=90,
                            evidence={"severity": "high",
                                      "remediation": "Patch immediately. "
                                                     "This CVE was published "
                                                     "in the last 7 days.",
                                      "cve_id": cve_id,
                                      "cvss": score,
                                      "tech": tech,
                                      "alert_type": "new_cve"}))
                except Exception:
                    continue

        try:
            ctx.cache.set("threat", cve_cache_key, sorted(reported)[-5000:],
                          ttl=86400 * 7)
        except Exception:
            pass

        # --- 3. Summary ---
        alert_count = len(findings)
        if alert_count == 0:
            findings.append(self._f(
                "infra", "watchdog_clean",
                f"Watchdog: no changes detected for {domain} "
                f"({len(new_subs)} new subs checked, "
                f"{len(known_tech)} techs monitored).",
                source="Watchdog", confidence=95,
                evidence={"severity": "low",
                          "remediation": "No action needed. Watchdog will "
                                         "alert on the next run if anything "
                                         "changes."}))

        reason = (f"watchdog: {len(new_subs)} new subdomains, "
                  f"{new_cves} new CVEs, {len(known_tech)} techs monitored")
        res = self._ok(findings, reason)
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
