"""Fast mode: rapid high-value triage scan.

Runs the ~20 highest-signal checks inline in a single plugin pass,
targeting under 30 seconds total. Built for quickly triaging many
targets: DNS posture, security headers, TLS cert, server banner,
robots/sitemap, WAF presence, top risky ports, crt.sh subdomains,
email auth (SPF/DMARC), and tech fingerprint basics.

Everything runs through fetch_many (parallel) plus a short TCP port
sweep, so the whole pass stays fast. Findings are the same shape as
the full scan's - just fewer of them, focused on what matters most.
"""
from __future__ import annotations

import asyncio
import re
import socket
import ssl
import time
from typing import Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from ..ratelimit import fetch, fetch_many
from .base import Cost, Ctx, Plugin, PluginResult, Target
# Reuse the audit plugins' pure graders so fastmode's inline checks never
# drift from the full-scan verdicts.
from .csp_audit import _grade_csp as _grade_csp_policy, _parse_csp
from .hsts import _parse_hsts

# Top risky ports for the fast TCP sweep (connect-only, short timeout).
FAST_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
               1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
               27017, 9200, 11211]

DANGEROUS = {21: "ftp", 23: "telnet", 445: "smb", 1433: "mssql",
             3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis",
             27017: "mongodb", 9200: "elasticsearch", 11211: "memcached"}

SECURITY_HEADERS = ["strict-transport-security", "content-security-policy",
                    "x-frame-options", "x-content-type-options",
                    "referrer-policy", "permissions-policy"]

REMEDIATION = ("Fast triage finding - run a full scan for complete "
               "coverage, then address per the specific check's guidance.")


def _quick_port_scan(host: str, ports: List[int],
                     timeout: float = 0.8) -> List[Tuple[int, str]]:
    """Blocking fast TCP connect sweep. Runs in a thread."""
    found: List[Tuple[int, str]] = []

    def _probe(port: int) -> Optional[Tuple[int, str]]:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            try:
                s.settimeout(1.0)
                banner = s.recv(256).decode("utf-8", "ignore").strip()
            except Exception:
                banner = ""
            finally:
                s.close()
            return (port, banner[:120])
        except Exception:
            return None

    # Threaded for speed; small port list so this stays quick.
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        for res in ex.map(_probe, ports):
            if res:
                found.append(res)
    return found


class FastmodePlugin(Plugin):
    id = "fastmode"
    label = "Fast Mode Triage"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "network"
    description = ("Rapid triage: top 20 highest-value checks in under "
                   "30 seconds.")
    requires_keys = []
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List = []
        domain = domain_from_target(target.type, target.normalized)
        base = target.normalized
        if not base.startswith("http"):
            base = f"https://{domain}"

        # --- 1. Parallel HTTP fetches: homepage, robots, sitemap,
        # security.txt, well-knowns ------------------------------------
        urls = [
            ("GET", base),
            ("GET", f"https://{domain}/robots.txt"),
            ("GET", f"https://{domain}/sitemap.xml"),
            ("GET", f"https://{domain}/.well-known/security.txt"),
            ("GET", f"http://{domain}/robots.txt"),
        ]
        try:
            resps = await fetch_many(ctx.http, ctx.limiter, urls,
                                     concurrency=5, max_retries=0,
                                     timeout=8)
        except Exception:
            resps = [None] * len(urls)

        home = resps[0] if resps else None
        if home is not None and getattr(home, "status_code", 0) == 200:
            findings.extend(self._check_headers(home, base))
            findings.extend(self._check_banner(home, base))
            findings.extend(self._check_tech(home, base))
            findings.extend(self._check_waf(home, base))
            findings.extend(self._check_cookie_flags(home, base))
            findings.extend(self._check_csp_hsts(home, base))
        else:
            findings.append(self._f(
                "web", "fast_home_unreachable",
                f"Homepage unreachable in fast mode: {base}",
                source="fastmode triage", confidence=60,
                evidence={"severity": "low", "url": base,
                          "remediation": REMEDIATION}))

        robots = resps[1] if len(resps) > 1 else None
        if robots is not None and getattr(robots, "status_code", 0) == 200:
            findings.extend(self._check_robots(robots, domain))

        sitemap = resps[2] if len(resps) > 2 else None
        if sitemap is not None and getattr(sitemap, "status_code", 0) == 200:
            n = len(re.findall(r"<loc>", sitemap.text or ""))
            if n:
                findings.append(self._f(
                    "web", "fast_sitemap",
                    f"sitemap.xml exposes {n} URLs",
                    source="fastmode triage",
                    source_url=f"https://{domain}/sitemap.xml",
                    confidence=85,
                    evidence={"severity": "low", "url_count": n,
                              "remediation": REMEDIATION}))

        # --- 2. TLS cert (fast, direct) --------------------------------
        tls_f = await self._check_tls(domain)
        if tls_f:
            findings.append(tls_f)

        # --- 2b. GraphQL quick probe (one harmless __typename) ------------
        findings.extend(await self._check_graphql(base, ctx))

        # --- 3. crt.sh subdomains (fast, keyless) ----------------------
        findings.extend(await self._check_subdomains(domain, ctx))

        # --- 4. Email auth: SPF/DMARC via DNS-over-HTTPS ---------------
        findings.extend(await self._check_email_auth(domain, ctx))

        # --- 5. Fast TCP port sweep (threaded, ~2-4s) ------------------
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            ip = ""
        if ip:
            loop = asyncio.get_running_loop()
            open_ports = await loop.run_in_executor(
                None, _quick_port_scan, ip, FAST_PORTS)
            for port, banner in open_ports:
                sev = "high" if port in DANGEROUS else "low"
                label = DANGEROUS.get(port, "open")
                findings.append(self._f(
                    "infra", "fast_open_port",
                    f"Port {port} open ({label})"
                    + (f" - banner: {banner[:60]}" if banner else ""),
                    source="fastmode triage", confidence=85,
                    evidence={"severity": sev, "port": port,
                              "service": label, "banner": banner[:120],
                              "ip": ip,
                              "exploitability": "theoretical"
                              if port in DANGEROUS else "unknown",
                              "remediation": REMEDIATION}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(
            findings,
            f"fast triage complete in {dur}ms: {len(findings)} findings")
        res.duration_ms = dur
        return res

    # -- checks --------------------------------------------------------
    def _check_headers(self, resp, url: str) -> List:
        out = []
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        missing = [h for h in SECURITY_HEADERS if h not in hdrs]
        if missing:
            out.append(self._f(
                "web", "fast_missing_headers",
                f"Missing {len(missing)} security headers: "
                f"{', '.join(missing)}",
                source="fastmode triage", source_url=url, confidence=95,
                evidence={"severity": "medium" if len(missing) >= 3 else "low",
                          "missing": missing, "remediation": REMEDIATION}))
        server = resp.headers.get("server", "")
        x_powered = resp.headers.get("x-powered-by", "")
        if server or x_powered:
            out.append(self._f(
                "web", "fast_info_disclosure",
                f"Server info disclosed: "
                f"{'server=' + server if server else ''}"
                f"{' x-powered-by=' + x_powered if x_powered else ''}",
                source="fastmode triage", source_url=url, confidence=90,
                evidence={"severity": "low", "server": server,
                          "x_powered_by": x_powered,
                          "remediation": REMEDIATION}))
        return out

    def _check_banner(self, resp, url: str) -> List:
        return []

    def _check_tech(self, resp, url: str) -> List:
        out = []
        text = (resp.text or "")[:50000].lower()
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        techs = []
        if "wp-content" in text or "wp-includes" in text:
            techs.append("WordPress")
        if "drupal" in text:
            techs.append("Drupal")
        if "/_next/" in text or "__next" in text:
            techs.append("Next.js")
        if "shopify" in text or "myshopify" in text:
            techs.append("Shopify")
        srv = hdrs.get("server", "")
        if srv:
            techs.append(f"server:{srv[:40]}")
        if techs:
            out.append(self._f(
                "web", "fast_tech",
                f"Tech detected: {', '.join(techs)}",
                source="fastmode triage", source_url=url, confidence=80,
                evidence={"severity": "low", "tech": techs,
                          "remediation": REMEDIATION}))
        return out

    def _check_waf(self, resp, url: str) -> List:
        out = []
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        waf = ""
        server = hdrs.get("server", "").lower()
        if "cloudflare" in server or "cf-ray" in hdrs:
            waf = "Cloudflare"
        elif "akamai" in server or "akamai" in str(hdrs.get("set-cookie", "")).lower():
            waf = "Akamai"
        elif "sucuri" in server:
            waf = "Sucuri"
        if waf:
            out.append(self._f(
                "web", "fast_waf",
                f"WAF detected: {waf}",
                source="fastmode triage", source_url=url, confidence=90,
                evidence={"severity": "low", "waf": waf,
                          "remediation": REMEDIATION}))
        return out

    def _check_cookie_flags(self, resp, url: str) -> List:
        # Fast inline version of the cookie_security audit: only the
        # highest-signal misses, summarized in one finding.
        out = []
        raw = resp.headers.get_list("set-cookie") \
            if hasattr(resp.headers, "get_list") else []
        if not raw:
            single = resp.headers.get("set-cookie")
            raw = [single] if single else []
        bad = 0
        for c in raw:
            parts = [p.strip() for p in c.split(";")]
            if not parts or "=" not in parts[0]:
                continue
            attrs = {}
            for p in parts[1:]:
                if "=" in p:
                    k, v = p.split("=", 1)
                    attrs[k.strip().lower()] = v.strip()
                else:
                    attrs[p.strip().lower()] = True
            name = parts[0].split("=", 1)[0].strip().lower()
            sess = any(k in name for k in ("sess", "auth", "token", "sid"))
            if sess and ("httponly" not in attrs or "secure" not in attrs):
                bad += 1
        if bad:
            out.append(self._f(
                "web", "fast_cookie_flags",
                f"{bad} session-ish cookie(s) missing Secure/HttpOnly",
                source="fastmode triage", source_url=url, confidence=85,
                evidence={"severity": "medium", "count": bad,
                          "remediation": REMEDIATION}))
        return out

    def _check_csp_hsts(self, resp, url: str) -> List:
        # Fast inline grading via the shared audit helpers: only the
        # bypass-grade weaknesses, one finding each.
        out = []
        is_https = url.startswith("https://")
        csp = resp.headers.get("content-security-policy", "")
        if csp:
            policy = _parse_csp(csp)
            for w in _grade_csp_policy(policy, is_https):
                if w["key"] in ("csp_unsafe_inline", "csp_unsafe_eval",
                                "csp_wildcard_script_src",
                                "csp_data_script_src"):
                    out.append(self._f(
                        "web", "fast_" + w["key"], w["message"],
                        source="fastmode triage", source_url=url,
                        confidence=85,
                        evidence={"severity": w["severity"],
                                  "directive": w["directive"],
                                  "remediation": REMEDIATION}))
        hsts = resp.headers.get("strict-transport-security", "")
        if hsts:
            h = _parse_hsts(hsts)
            try:
                age = int(str(h.get("max-age", "0")).strip('"'))
            except (ValueError, TypeError):
                age = 0
            if age < 31536000 or "includesubdomains" not in h:
                out.append(self._f(
                    "web", "fast_hsts_weak",
                    f"HSTS weak: max-age={age}, "
                    f"includeSubDomains={'includesubdomains' in h}",
                    source="fastmode triage", source_url=url, confidence=85,
                    evidence={"severity": "low", "max_age": age,
                              "remediation": REMEDIATION}))
        return out

    async def _check_graphql(self, base: str, ctx: Ctx) -> List:
        # One harmless __typename probe; introspection stays in the full scan.
        out = []
        try:
            r = await fetch(ctx.http, ctx.limiter, "POST", base + "/graphql",
                            json={"query": "{__typename}"}, timeout=8,
                            max_retries=0)
            data = r.json() if r is not None else {}
            if isinstance(data.get("data"), dict) and \
                    "__typename" in data["data"]:
                out.append(self._f(
                    "api", "fast_graphql",
                    "GraphQL endpoint detected at /graphql",
                    source="fastmode triage",
                    source_url=base + "/graphql", confidence=80,
                    evidence={"severity": "low",
                              "remediation": REMEDIATION}))
        except Exception:
            pass
        return out

    def _check_robots(self, resp, domain: str) -> List:
        out = []
        text = resp.text or ""
        disallows = re.findall(r"(?im)^disallow:\s*(\S+)", text)
        interesting = [d for d in disallows
                       if d != "/" and len(d) > 1][:10]
        if interesting:
            out.append(self._f(
                "web", "fast_robots",
                f"robots.txt discloses {len(interesting)} paths: "
                f"{', '.join(interesting[:5])}",
                source="fastmode triage",
                source_url=f"https://{domain}/robots.txt", confidence=85,
                evidence={"severity": "low", "paths": interesting,
                          "remediation": REMEDIATION}))
        return out

    async def _check_tls(self, domain: str):
        try:
            loop = asyncio.get_running_loop()

            def _grab():
                ctx_ = ssl.create_default_context()
                with socket.create_connection((domain, 443),
                                              timeout=6) as s:
                    with ctx_.wrap_socket(s, server_hostname=domain) as ss:
                        cert = ss.getpeercert()
                        ver = ss.version()
                        return cert, ver

            cert, ver = await loop.run_in_executor(None, _grab)
            if not cert:
                return None
            import datetime as dt
            not_after = cert.get("notAfter", "")
            sev = "low"
            try:
                exp = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                exp = exp.replace(tzinfo=dt.timezone.utc)
                days = (exp - dt.datetime.now(dt.timezone.utc)).days
                if days < 0:
                    sev = "high"
                elif days < 14:
                    sev = "medium"
            except Exception:
                days = -1
            cn = ""
            for rdn in cert.get("subject", ()):
                for k, v in rdn:
                    if k == "commonName":
                        cn = v
            return self._f(
                "infra", "fast_tls",
                f"TLS {ver}, CN={cn}, expires {not_after}"
                + (f" ({days}d left)" if days >= 0 else ""),
                source="fastmode triage", confidence=95,
                evidence={"severity": sev, "tls_version": ver,
                          "common_name": cn, "not_after": not_after,
                          "days_left": days, "remediation": REMEDIATION})
        except Exception:
            return None

    async def _check_subdomains(self, domain: str, ctx: Ctx) -> List:
        out = []
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            f"https://crt.sh/?q=%25.{domain}&output=json",
                            timeout=10, max_retries=0)
            if r.status_code != 200:
                return out
            import json as _json
            try:
                data = _json.loads(r.text)
            except Exception:
                return out
            subs = set()
            for row in data if isinstance(data, list) else []:
                name = str(row.get("name_value", ""))
                for part in name.split("\n"):
                    part = part.strip().lower()
                    if part.endswith(domain) and "*" not in part:
                        subs.add(part)
            subs.discard(domain)
            if subs:
                sample = sorted(subs)[:10]
                out.append(self._f(
                    "web", "fast_subdomains",
                    f"{len(subs)} subdomains in CT logs "
                    f"(e.g. {', '.join(sample[:3])})",
                    source="fastmode triage: crt.sh", confidence=90,
                    evidence={"severity": "low", "count": len(subs),
                              "sample": sample, "remediation": REMEDIATION}))
        except Exception:
            pass
        return out

    async def _check_email_auth(self, domain: str, ctx: Ctx) -> List:
        out = []
        try:
            reqs = [
                ("GET", f"https://cloudflare-dns.com/dns-query?"
                        f"name={domain}&type=TXT",
                 {"headers": {"accept": "application/dns-json"}}),
                ("GET", f"https://cloudflare-dns.com/dns-query?"
                        f"name=_dmarc.{domain}&type=TXT",
                 {"headers": {"accept": "application/dns-json"}}),
            ]
            resps = await fetch_many(ctx.http, ctx.limiter, reqs,
                                     concurrency=2, max_retries=0,
                                     timeout=8)
            spf = dmarc = False
            for r in resps:
                if r is None or r.status_code != 200:
                    continue
                try:
                    txt = r.text or ""
                except Exception:
                    continue
                if "v=spf1" in txt:
                    spf = True
                if "v=DMARC1" in txt:
                    dmarc = True
            if not spf or not dmarc:
                missing = []
                if not spf:
                    missing.append("SPF")
                if not dmarc:
                    missing.append("DMARC")
                out.append(self._f(
                    "identity", "fast_email_auth",
                    f"Email spoofing risk: missing {'+'.join(missing)} "
                    f"for {domain}",
                    source="fastmode triage", confidence=85,
                    evidence={"severity": "medium" if not dmarc else "low",
                              "spf": spf, "dmarc": dmarc,
                              "remediation": REMEDIATION}))
        except Exception:
            pass
        return out
