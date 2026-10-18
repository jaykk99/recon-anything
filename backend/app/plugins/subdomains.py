"""Subdomain enumeration plugin (Milestone 2).

Sources: crt.sh certificate transparency (free, no key), plus optional
active-mode DNS brute force with a bundled wordlist.
"""
from __future__ import annotations

import asyncio
import time
from typing import List
from urllib.parse import quote

import dns.asyncresolver
import dns.exception
import dns.resolver

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

WORDLIST = """www mail ftp localhost webmail smtp pop imap blog shop api dev
staging test admin portal vpn remote gitlab jira confluence wiki docs
status monitor grafana kibana elastic db database cache redis mq queue
cdn static assets img images media files download upload backup old
beta alpha demo sandbox qa uat prod production dr backup1 backup2
ns1 ns2 mx1 mx2 autodiscover lync sip teams chat meet webinar
crm erp hr finance billing pay payment checkout cart order
support help helpdesk ticket kb community forum
app mobile m site ampamp
oauth sso login auth idp account profile settings
ci cd jenkins drone travis circle build deploy
k8s kubernetes docker registry harbor nexus artifactory
vpn1 firewall gw proxy socks bastion jump
iot printer scanner camera
test1 test2 dev1 dev2 stage1 prod1
partner partners affiliate reseller
legal privacy terms about contact careers press newsroom
graphql rest v1 v2 v3
webhook hooks events callback
sftp ftps
internal intranet corp extranet
legacy classic new old1
mx mail1 mail2
autoconfig
_dmarc
""".split()


# Interesting-subdomain classifier: turns a subdomain list into
# actionable findings. (label_prefix, severity, why)
CRITICAL_SUBS = {
    "admin": "admin panels are the first target for brute force and auth bypass",
    "administrator": "admin panels are the first target for brute force and auth bypass",
    "backend": "backend hosts often lack the hardening of the main site",
    "panel": "panels often expose management functions with weak auth",
    "dashboard": "dashboards may leak internal data or have weak auth",
    "dev": "dev hosts often run debug mode, verbose errors and test creds",
    "development": "dev hosts often run debug mode, verbose errors and test creds",
    "staging": "staging often mirrors prod data with weaker controls",
    "stage": "staging often mirrors prod data with weaker controls",
    "test": "test hosts often have debug enabled and default creds",
    "qa": "qa hosts often have debug enabled and default creds",
    "uat": "uat hosts often mirror prod with weaker controls",
    "sandbox": "sandboxes may allow file upload or code execution",
    "vpn": "vpn endpoints are high-value for network access",
    "remote": "remote access portals are high-value targets",
    "citrix": "citrix gateways have a history of critical CVEs",
    "rdp": "rdp exposed to the internet gets brute forced constantly",
    "git": "git hosting may expose private repos",
    "svn": "svn hosting may expose private repos",
    "jenkins": "jenkins often has script console RCE with default creds",
    "ci": "ci systems can leak secrets and allow build tampering",
    "cd": "cd systems can leak secrets and allow build tampering",
    "deploy": "deploy hosts may allow code push or expose pipelines",
    "db": "database hosts should never be internet-facing",
    "database": "database hosts should never be internet-facing",
    "sql": "database hosts should never be internet-facing",
    "phpmyadmin": "phpmyadmin is brute forced constantly; check version CVEs",
    "api-dev": "non-prod APIs often skip auth checks present in prod",
    "api-staging": "non-prod APIs often skip auth checks present in prod",
    "dev-api": "non-prod APIs often skip auth checks present in prod",
    "old": "legacy hosts run unpatched software",
    "legacy": "legacy hosts run unpatched software",
    "backup": "backup hosts may expose archives of the whole site",
    "bak": "backup hosts may expose archives of the whole site",
}
MEDIUM_SUBS = {
    "api": "api surface: enumerate endpoints and check auth per route",
    "app": "app host: check for debug endpoints and version disclosure",
    "mobile": "mobile api host: check for weak cert pinning assumptions",
    "beta": "beta hosts may have unfinished auth flows",
    "mail": "mail host: check for open relay and webmail version CVEs",
    "email": "mail host: check for open relay and webmail version CVEs",
    "smtp": "smtp host: check for open relay",
    "cdn": "cdn host: check origin IP disclosure",
    "static": "static host: check for directory listing",
    "assets": "asset host: check for directory listing and source maps",
    "blog": "blog host: check CMS version CVEs",
    "docs": "docs host: may document internal APIs and creds",
    "help": "helpdesk may leak internal info via tickets",
    "support": "support portal may leak internal info",
}


# Staleness signals: old tech versions that indicate unmaintained hosts
STALE_SERVER_PATTERNS = [
    (r"apache/2\.2", "Apache 2.2 (EOL since 2017)"),
    (r"apache/2\.0", "Apache 2.0 (EOL since 2013)"),
    (r"nginx/1\.[0-9]\.", "old nginx 1.x"),
    (r"nginx/0\.", "nginx 0.x (ancient)"),
    (r"iis/6\.0", "IIS 6.0 (EOL since 2015)"),
    (r"iis/7\.0", "IIS 7.0 (EOL)"),
    (r"php/5\.", "PHP 5.x (EOL since 2018)"),
    (r"php/7\.0", "PHP 7.0 (EOL since 2019)"),
    (r"php/7\.1", "PHP 7.1 (EOL since 2019)"),
    (r"python/2\.", "Python 2.x (EOL since 2020)"),
    (r"django/1\.", "Django 1.x (EOL)"),
    (r"wordpress", None),  # version checked separately
]

STALE_TITLE_PATTERNS = [
    (r"under construction", "under construction page"),
    (r"coming soon", "coming soon page"),
    (r"welcome to nginx", "default nginx page (unconfigured)"),
    (r"apache2 debian default", "default Apache page (unconfigured)"),
    (r"it works!", "default Apache test page"),
]


def classify_subdomain(sub: str, domain: str):
    """Return (severity, why) if the subdomain looks interesting."""
    first = sub.split(".")[0].lower()
    # strip common numeric suffixes: admin2, dev01
    base = first.rstrip("0123456789")
    for key in (first, base):
        if key in CRITICAL_SUBS:
            return ("critical", CRITICAL_SUBS[key])
    for key in (first, base):
        if key in MEDIUM_SUBS:
            return ("medium", MEDIUM_SUBS[key])
    return (None, None)


async def check_staleness(sub: str, ctx: Ctx) -> List[str]:
    """Probe a subdomain for staleness signals. Returns list of signals."""
    signals = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{sub}/"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10,
                            follow_redirects=True)
            # Check server header for old tech
            server = r.headers.get("server", "")
            for pat, label in STALE_SERVER_PATTERNS:
                import re as _re
                if _re.search(pat, server, _re.I):
                    if label:
                        signals.append(f"stale server header: {label}")
                    break
            # Check title for default/stale pages
            title_m = _re.search(r"<title[^>]*>([^<]{0,200})</title>", r.text[:50000], _re.I)
            if title_m:
                title = title_m.group(1).lower()
                for pat, label in STALE_TITLE_PATTERNS:
                    if _re.search(pat, title):
                        signals.append(f"stale page: {label}")
                        break
            # Check for old WordPress version
            wp_m = _re.search(r'content=["\']WordPress (\d+\.\d+)', r.text[:50000])
            if wp_m:
                ver = wp_m.group(1)
                try:
                    major = float(ver)
                    if major < 6.0:
                        signals.append(f"old WordPress {ver}")
                except ValueError:
                    pass
            break  # got a response, no need to try http
        except Exception:
            continue
    return signals


class SubdomainsPlugin(Plugin):
    timeout_s = 180  # slow enumerator: needs headroom
    id = "subdomains"
    label = "Subdomain Enum"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = "Certificate-transparency subdomains via crt.sh, plus active DNS brute force."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)

        # --- crt.sh (always passive-safe, free, no key) ---
        async def crtsh():
            url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=30)
                if resp.status_code != 200:
                    return {"error": f"HTTP {resp.status_code}"}
                return resp.json()
            except Exception as e:
                return {"error": str(e)[:200] or type(e).__name__}

        rows, _ = await ctx.cache.cached("ct", domain, crtsh)
        seen = set()
        crt_ok = False
        if isinstance(rows, list):
            crt_ok = True
            for r in rows:
                name = (r.get("name_value") or "").strip().lower()
                for sub in name.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub and sub.endswith(domain) and sub not in seen:
                        seen.add(sub)
        elif isinstance(rows, dict) and "error" in rows:
            findings.append(self._f("dns", "subdomain_enum_note",
                                    f"crt.sh unavailable: {rows['error']}",
                                    source="crt.sh", confidence=40, passive=True))

        # --- fallback: hackertarget hostsearch (free, no key) ---
        if not crt_ok:
            async def htarget():
                url = f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}"
                try:
                    resp = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25)
                    if resp.status_code != 200:
                        return {"error": f"HTTP {resp.status_code}"}
                    return {"text": resp.text}
                except Exception as e:
                    return {"error": str(e)[:200] or type(e).__name__}

            ht, _ = await ctx.cache.cached("ht", domain, htarget)
            if isinstance(ht, dict) and ht.get("text"):
                for line in ht["text"].strip().splitlines():
                    parts = line.split(",")
                    if parts:
                        sub = parts[0].strip().lower()
                        if sub and sub.endswith(domain) and sub not in seen:
                            seen.add(sub)
                if seen:
                    findings.append(self._f("dns", "subdomain_enum_note",
                                            "used hackertarget fallback (crt.sh failed)",
                                            source="api.hackertarget.com",
                                            confidence=50, passive=True))

        # (anubis jldc.me fallback removed 2026-10-17: the service moved to
        # jonlu.ca behind a Cloudflare challenge that server-side calls cannot
        # pass, so it could never return results; hackertarget above covers

        # --- more sources: AlienVault OTX, urlscan, ThreatCrowd (all keyless).
        async def otx():
            url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
                   f"{quote(domain)}/passive_dns")
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25)
                if resp.status_code != 200:
                    return None
                return resp.json()
            except Exception:
                return None

        async def urlscan():
            url = (f"https://urlscan.io/api/v1/search/?q=domain:{quote(domain)}"
                   f"&size=100")
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25)
                if resp.status_code != 200:
                    return None
                return resp.json()
            except Exception:
                return None

        async def threatcrowd():
            url = (f"https://www.threatcrowd.org/searchApi/v2/domain/report/"
                   f"?domain={quote(domain)}")
            try:
                resp = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25)
                if resp.status_code != 200:
                    return None
                return resp.json()
            except Exception:
                return None

        # Fetched concurrently: 3 sequential x 25s timeouts become one window.
        otx_data, us_data, tc_data = await asyncio.gather(
            ctx.cache.cached("otx", domain, otx),
            ctx.cache.cached("urlscan", domain, urlscan),
            ctx.cache.cached("tc", domain, threatcrowd),
        )
        otx_data = otx_data[0]
        us_data = us_data[0]
        tc_data = tc_data[0]
        if isinstance(otx_data, dict):
            n_before = len(seen)
            for rec in otx_data.get("passive_dns", []):
                sub = (rec.get("hostname") or "").strip().lower().lstrip("*.")
                if sub and sub.endswith(domain) and sub not in seen:
                    seen.add(sub)
            if len(seen) > n_before:
                findings.append(self._f("dns", "subdomain_enum_note",
                                        f"OTX passive DNS added "
                                        f"{len(seen) - n_before} subdomains",
                                        source="otx.alienvault.com",
                                        confidence=70, passive=True))

        if isinstance(us_data, dict):
            n_before = len(seen)
            for res in us_data.get("results", []):
                sub = (res.get("page", {}).get("domain") or "").strip().lower()
                if sub and sub.endswith(domain) and sub not in seen:
                    seen.add(sub)
            if len(seen) > n_before:
                findings.append(self._f("dns", "subdomain_enum_note",
                                        f"urlscan.io added "
                                        f"{len(seen) - n_before} subdomains",
                                        source="urlscan.io",
                                        confidence=70, passive=True))

        if isinstance(tc_data, dict):
            n_before = len(seen)
            for sub in tc_data.get("subdomains", []):
                s = str(sub).strip().lower().lstrip("*.")
                if s and s.endswith(domain) and s not in seen:
                    seen.add(s)
            if len(seen) > n_before:
                findings.append(self._f("dns", "subdomain_enum_note",
                                        f"ThreatCrowd added "
                                        f"{len(seen) - n_before} subdomains",
                                        source="threatcrowd.org",
                                        confidence=65, passive=True))

        # --- subdomain permutations: common prefixes on found subs ---
        perm_prefixes = ["www2", "m2", "api2", "old", "new", "beta",
                         "test", "dev", "staging"]
        n_before = len(seen)
        for sub in list(seen)[:50]:
            first = sub.split(".")[0]
            rest = ".".join(sub.split(".")[1:])
            for pre in perm_prefixes:
                cand = f"{pre}.{rest}" if first == "www" else f"{pre}-{first}.{rest}"
                if cand not in seen and cand.endswith(domain):
                    # passive only: just note as candidate, don't resolve
                    seen.add(cand)
        if len(seen) > n_before:
            findings.append(self._f("dns", "subdomain_enum_note",
                                    f"permutation engine added "
                                    f"{len(seen) - n_before} candidates",
                                    source="permutation", confidence=40,
                                    passive=True))
        # the crt.sh-failure case.)

        # Staleness probes for interesting subdomains, run concurrently
        # (sequential 2-request probes per subdomain become one window).
        interesting = []
        for sub in sorted(seen):
            sev, why = classify_subdomain(sub, domain)
            if sev:
                interesting.append((sub, sev, why))
        stale_sem = asyncio.Semaphore(6)

        async def _stale(sub: str):
            async with stale_sem:
                return await check_staleness(sub, ctx)

        stale_results = await asyncio.gather(
            *[_stale(sub) for sub, _, _ in interesting])
        stale_by_sub = {sub: sigs for (sub, _, _), sigs
                        in zip(interesting, stale_results)}

        for sub in sorted(seen):
            ctx.publish("subdomains", sub)
            findings.append(self._f("dns", "subdomain", sub,
                                    source="certificate transparency / hostsearch",
                                    source_url=f"https://crt.sh/?q=%25.{domain}",
                                    confidence=85, passive=True))
            sev, why = classify_subdomain(sub, domain)
            if sev:
                # Check for staleness on interesting subdomains
                stale_signals = stale_by_sub.get(sub, [])
                stale_note = ""
                if stale_signals:
                    stale_note = f" STALENESS: {'; '.join(stale_signals)}. This host looks abandoned."
                findings.append(self._f(
                    "dns", "interesting_subdomain",
                    f"{sev.upper()}: {sub} looks interesting: {why}.{stale_note}",
                    source="subdomain classifier",
                    source_url=f"https://crt.sh/?q=%25.{domain}",
                    confidence=75, passive=True,
                    evidence={"severity": sev, "subdomain": sub, "why": why,
                              "stale_signals": stale_signals,
                              "remediation": "Verify this host is intentional, patched, "
                                             "and not exposing more than the main site."}))

        # --- active DNS brute force (concurrent: ~170 sequential resolves
        # become one paced window; the 100-hit cap still applies in
        # wordlist order when emitting findings) ---
        if mode == "active":
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 6
            dns_sem = asyncio.Semaphore(20)

            async def _resolve(word: str):
                cand = f"{word}.{domain}"
                if cand in seen:
                    return None
                async with dns_sem:
                    try:
                        ans = await resolver.resolve(cand, "A")
                        return (cand, ", ".join(str(r) for r in ans))
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                            dns.resolver.NoNameservers, dns.exception.Timeout):
                        return None
                    except Exception:
                        return None

            dns_results = await asyncio.gather(
                *[_resolve(w) for w in WORDLIST])
            found = 0
            for item in dns_results:
                if not item:
                    continue
                cand, ips = item
                ctx.publish("subdomains", cand)
                findings.append(self._f("dns", "subdomain",
                                        f"{cand} -> {ips}",
                                        source="DNS brute force",
                                        confidence=95, passive=False))
                sev, why = classify_subdomain(cand, domain)
                if sev:
                    findings.append(self._f(
                        "dns", "interesting_subdomain",
                        f"{sev.upper()}: {cand} looks interesting: {why}.",
                        source="subdomain classifier", confidence=75,
                        passive=False,
                        evidence={"severity": sev, "subdomain": cand,
                                  "why": why,
                                  "remediation": "Verify this host is intentional, patched, "
                                                 "and not exposing more than the main site."}))
                found += 1
                if found >= 100:
                    break

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{len(seen)} subdomains from CT"
                       + (" + active brute force" if mode == "active" else ""))
        res.duration_ms = dur
        return res
