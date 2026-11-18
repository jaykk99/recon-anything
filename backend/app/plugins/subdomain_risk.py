"""Subdomain risk plugin (ported from ARTEX modules/FastAnalyst.py).

Phase-2 chain plugin: consumes the "subdomains" the phase-1 enumerator
published (falls back to a crt.sh fetch when the bus is empty), classifies
each subdomain with ARTEX's 4-tier pattern tables, scores it with
ARTEX's vulnerability-indicator weights, probes its HTTP/HTTPS status,
and flags response-code anomalies.

Ported from ARTEX FastSecurityAnalyst:
- _load_security_patterns: critical/high/medium/info pattern tables.
- _load_vulnerability_indicators: admin panels 50, dev environments 45,
  database interfaces 60, backup systems 55, API endpoints 40.
- analyze_subdomains / _identify_security_targets: high-value targets.
- Response-code anomaly analysis (active HTTP(S) status per subdomain).

ReconAnything already had a 2-tier classifier
(subdomains.py::classify_subdomain, critical/medium); this plugin adds
the 4-tier taxonomy, the indicator scores, the testing priority, and the
response-code anomalies — the parts that were missing.
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target, gather_capped

# ARTEX FastAnalyst._load_security_patterns (verbatim tables).
PATTERNS = {
    "critical": {
        "admin": ["admin", "administrator", "cpanel", "whm", "plesk", "directadmin"],
        "database": ["db", "database", "mysql", "phpmyadmin", "adminer", "mongodb", "redis"],
        "backup": ["backup", "bak", "old", "archive", "dump"],
        "internal": ["internal", "intranet", "private", "corp", "employee"],
    },
    "high": {
        "development": ["dev", "devel", "development", "test", "testing", "qa", "staging", "stage"],
        "api": ["api", "rest", "graphql", "service", "webservice", "ws"],
        "config": ["config", "configuration", "setup", "install"],
        "auth": ["auth", "authentication", "login", "sso", "oauth", "ldap"],
    },
    "medium": {
        "mail": ["mail", "email", "smtp", "imap", "pop", "webmail", "exchange"],
        "monitoring": ["monitor", "nagios", "zabbix", "grafana", "kibana"],
        "file": ["files", "upload", "download", "ftp", "sftp"],
        "vpn": ["vpn", "remote", "access", "gateway"],
    },
    "info": {
        "cdn": ["cdn", "static", "assets", "media", "img", "images"],
        "blog": ["blog", "news", "www", "site"],
        "support": ["help", "support", "docs", "documentation"],
        "social": ["social", "community", "forum"],
    },
}

# ARTEX FastAnalyst._load_vulnerability_indicators (verbatim).
INDICATORS = {
    "admin_panels": {
        "patterns": ["admin", "panel", "control", "manage", "dashboard"],
        "risk_score": 50,
        "description": "Administrative interfaces often have authentication bypasses",
    },
    "dev_environments": {
        "patterns": ["dev", "test", "beta", "demo", "sandbox"],
        "risk_score": 45,
        "description": "Development environments may expose debug information",
    },
    "database_interfaces": {
        "patterns": ["phpmyadmin", "adminer", "mysql", "db"],
        "risk_score": 60,
        "description": "Database management interfaces are high-value targets",
    },
    "backup_systems": {
        "patterns": ["backup", "bak", "dump", "archive"],
        "risk_score": 55,
        "description": "Backup systems may contain sensitive data",
    },
    "api_endpoints": {
        "patterns": ["api", "rest", "graphql", "service"],
        "risk_score": 40,
        "description": "APIs vulnerable to IDOR, injection, and data exposure",
    },
}

# Tier base scores for subdomains that match a tier table but no
# indicator (ARTEX only scores indicators; a bare tier match still needs
# a number for ranking).
_TIER_BASE = {"critical": 60, "high": 40, "medium": 25, "info": 5}
_TIER_ORDER = ("critical", "high", "medium", "info")
_MAX_SUBS = 30


def _first_label(sub: str) -> str:
    """Leftmost label, numeric suffix stripped (admin2 -> admin)."""
    first = (sub or "").split(".")[0].lower()
    return first.rstrip("0123456789")


def classify_subdomain_risk(sub: str) -> Optional[Dict]:
    """Classify one subdomain. Pure helper, unit-tested.

    Returns {"tier", "category", "indicator", "risk_score",
    "description"} or None when the subdomain matches no pattern.
    Highest tier wins; within a tier the first matching category wins.
    The indicator score (when one matches) overrides the tier base.
    """
    label = _first_label(sub)
    if not label:
        return None
    tier = category = None
    for t in _TIER_ORDER:
        for cat, words in PATTERNS[t].items():
            if label in words:
                tier, category = t, cat
                break
        if tier:
            break
    if not tier:
        return None
    indicator = None
    score = _TIER_BASE[tier]
    description = ""
    for name, spec in INDICATORS.items():
        if label in spec["patterns"]:
            indicator = name
            score = spec["risk_score"]
            description = spec["description"]
            break
    return {"tier": tier, "category": category, "indicator": indicator,
            "risk_score": score, "description": description}


def response_anomaly(http_status: int, https_status: int) -> str:
    """Name the anomaly in a subdomain's HTTP/HTTPS statuses, or ''.

    Pure helper, unit-tested. 0 = no answer / probe failed.
    """
    if https_status >= 500:
        return f"HTTPS returns {https_status} (server error on the secure endpoint)"
    if http_status == 200 and not https_status:
        return "HTTP 200 but HTTPS does not answer (plaintext-only surface)"
    if http_status >= 500 and https_status == 200:
        return f"HTTP returns {http_status} while HTTPS is healthy"
    return ""


class SubdomainRiskPlugin(Plugin):
    id = "subdomain_risk"
    label = "Subdomain Risk Ranking"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("4-tier risk ranking of discovered subdomains with "
                   "indicator scores and HTTP/HTTPS anomaly flags.")
    # Phase 2: consumes the "subdomains" bus the enumerator filled.
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")

        subs = [s for s in ctx.consume("subdomains") if isinstance(s, str)]
        if not subs:
            subs = await self._crtsh_subs(ctx, domain)
        subs = sorted(set(subs))[:_MAX_SUBS]
        if not subs:
            return self._ok([], f"no subdomains known for {domain}")

        # Probe HTTP + HTTPS status for every candidate (shared probe
        # cache, capped batch). Info-tier subs are classified too but
        # only critical/high/medium become findings.
        results = await gather_capped(
            [ctx.probe(f"https://{s}/") for s in subs] +
            [ctx.probe(f"http://{s}/") for s in subs], budget_s=45)
        https_status = {s: (results[i].get("status") or 0
                            if isinstance(results[i], dict) else 0)
                        for i, s in enumerate(subs)}
        http_status = {s: (results[len(subs) + i].get("status") or 0
                           if isinstance(results[len(subs) + i], dict) else 0)
                       for i, s in enumerate(subs)}

        findings: List[Finding] = []
        counts = {"critical": 0, "high": 0, "medium": 0, "info": 0}
        for sub in subs:
            cls = classify_subdomain_risk(sub)
            if not cls:
                continue
            counts[cls["tier"]] += 1
            if cls["tier"] == "info":
                continue
            anomaly = response_anomaly(http_status.get(sub, 0),
                                       https_status.get(sub, 0))
            sev = cls["tier"]  # _f normalizes critical -> high
            detail = (f"{sub} — {cls['tier']} {cls['category']} "
                      f"(risk {cls['risk_score']})")
            if cls["indicator"]:
                detail += f", indicator: {cls['indicator']}"
            if cls["description"]:
                detail += f": {cls['description']}"
            if anomaly:
                detail += f". Anomaly: {anomaly}."
            detail += (f" [https {https_status.get(sub, 0)}, "
                       f"http {http_status.get(sub, 0)}]")
            findings.append(self._f(
                "web", "subdomain_risk", detail,
                source="subdomain risk ranking", confidence=75,
                passive=True,
                evidence={"severity": sev, "tier": cls["tier"],
                          "category": cls["category"],
                          "indicator": cls["indicator"],
                          "risk_score": cls["risk_score"],
                          "http_status": http_status.get(sub, 0),
                          "https_status": https_status.get(sub, 0),
                          "anomaly": anomaly,
                          "why": "High-risk subdomains (admin, database, "
                                 "backup, internal, dev, API) are the "
                                 "first places to test: check auth, "
                                 "patch level, and whether staging/dev "
                                 "exposes anything production would not."}))

        findings.sort(
            key=lambda f: (f.evidence or {}).get("risk_score", 0),
            reverse=True)
        res = self._ok(
            findings,
            f"ranked {len(subs)} subdomains for {domain}: "
            f"{counts['critical']} critical, {counts['high']} high, "
            f"{counts['medium']} medium, {counts['info']} info")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def _crtsh_subs(self, ctx: Ctx, domain: str) -> List[str]:
        """Fallback enumeration when the bus is empty (same source as
        subdomains.py: crt.sh via the shared cache)."""
        from urllib.parse import quote
        url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"

        async def _fetch():
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25)
                if resp.status_code != 200:
                    return {"error": f"HTTP {resp.status_code}"}
                return resp.json()
            except Exception as e:
                return {"error": str(e)[:200] or type(e).__name__}

        rows, _ = await ctx.cache.cached("ct", domain, _fetch)
        out: List[str] = []
        if isinstance(rows, list):
            for r in rows:
                name = (r.get("name_value") or "").strip().lower()
                for sub in name.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub and sub.endswith(domain) and sub not in out:
                        out.append(sub)
        return out
