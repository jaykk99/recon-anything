"""Bank infrastructure detection plugin.

Detection-only recon: core banking platform fingerprints, online banking
portal discovery, exposed admin panels, banking API surface, security
header audit, public CVE matching, PCI DSS indicators. Read-only GETs,
connect-only checks. Never attempts logins, never cracks credentials,
never accesses accounts.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import re
import time
from typing import List

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

TIMEOUT = 15

PLATFORMS = [  # (label, regex, confidence), case-insensitive
    ("Fiserv", r"fiserv", 85), ("FIS", r"\bfis\b|fidelity\s*national", 75),
    ("Jack Henry", r"jack\s*henry|symitar|profitstars", 85),
    ("Temenos", r"temenos|\bt24\b|transact", 75),
    ("Finastra", r"finastra|fusion\s*essence", 80),
    ("Q2", r"q2ebanking|\bq2\b", 75), ("Alkami", r"alkami", 90),
    ("NCR", r"\bncr\b|digital\s*insight", 75),
    ("Diebold Nixdorf", r"diebold", 85),
    ("nCino", r"ncino", 85),
    ("MeridianLink", r"meridian\s*link|meridianlink", 80),
    ("Corelation", r"corelation|keystone", 80),
    ("Finacle (Infosys)", r"finacle", 80),
    ("Mambu", r"mambu", 80),
    ("Backbase", r"backbase", 80),
    ("Bottomline", r"bottomline\s*(technologies)?|paymode", 70),
]
MFA_HINTS = [r"two[-\s]?factor", r"one[-\s]?time\s*(passcode|password|code)",
             r"authenticator", r"multi[-\s]?factor", r"verification\s*code"]
MOBILE_HINTS = [r"mobile[_\-]?banking", r"user[_\-]?agent", r"android",
                r"\bios\b", r"app[_\-]?token"]

# Online-banking / portal paths probed with GET only. A 200 means the
# portal exists and is reachable; we never submit credentials.
BANKING_PORTAL_PATHS = (
    "/online-banking", "/onlinebanking", "/ebanking", "/e-banking",
    "/internet-banking", "/digital-banking", "/login", "/signon",
    "/sign-in", "/myaccount", "/my-account", "/retail", "/personal",
    "/personal-banking", "/business-banking", "/business",
)

# Admin-panel paths probed with GET only (existence check, no login).
ADMIN_PATHS = (
    "/admin", "/administrator", "/admin-panel", "/admin/login",
    "/manager", "/console", "/wp-admin", "/phpmyadmin", "/admincp",
)

# API endpoint patterns extracted from page HTML.
API_PATTERNS = (
    r"/api/[a-z0-9_\-/]+", r"/v1/[a-z0-9_\-/]+", r"/v2/[a-z0-9_\-/]+",
    r"/rest/[a-z0-9_\-/]+",
)
API_FILES = ("/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
             "/api-docs", "/api/docs", "/graphql", "/graphiql")

# Security headers audited on financial sites: missing = finding.
SEC_HEADERS = (
    ("strict-transport-security",
     "HSTS missing - HTTPS not enforced at the header level", 80,
     "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("content-security-policy",
     "CSP missing - XSS/clickjacking mitigations absent", 75,
     "Add a Content-Security-Policy header"),
    ("x-frame-options",
     "X-Frame-Options missing - clickjacking possible", 75,
     "Add X-Frame-Options: DENY or SAMEORIGIN"),
    ("x-content-type-options",
     "X-Content-Type-Options missing - MIME sniffing possible", 70,
     "Add X-Content-Type-Options: nosniff"),
    ("referrer-policy",
     "Referrer-Policy missing - referrer leakage possible", 60,
     "Add Referrer-Policy: strict-origin-when-cross-origin"),
)

# tech marker -> verified public CVE, emitted only when marker is found.
TECH_CVES = [
    ("log4j", "CVE-2021-44228", "Log4Shell RCE in Apache Log4j 2"),
    ("citrix", "CVE-2023-4966", "CitrixBleed session theft in NetScaler"),
    ("f5", "CVE-2022-1388", "F5 BIG-IP iControl REST auth bypass"),
    ("moveit", "CVE-2023-34362", "MOVEit Transfer SQL injection"),
    ("ivanti", "CVE-2024-21887", "Ivanti Connect Secure command injection"),
    ("fortinet", "CVE-2023-27997", "FortiOS heap buffer overflow"),
]
CARD_INPUT = re.compile(r"<input[^>]*(?:card[_-]?number|cardnumber|cc[_-]?num|credit[_-]?card)[^>]*>", re.IGNORECASE)
RL_HEADERS = ("x-ratelimit-limit", "x-rate-limit-limit", "x-ratelimit-remaining", "x-requests-remaining", "x-request-limit", "retry-after")


class BankPlugin(Plugin):
    id = "bank"
    label = "Bank Infrastructure Detection"
    accepts = ["domain", "url", "poi"]
    passive = True
    cost = Cost.FREE
    group = "financial"
    description = ("Banking portals, admin panels, API surface, header "
                   "audit, platform fingerprints. Detection only.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        mode = ctx.mode
        findings: List[Finding] = []
        # Authorization gate (defense in depth), same pattern as the ATM
        # module: bank assessment only runs when the run carries the
        # module authorization - set by main.py when the operator picks
        # the bank source type. Website runs never enqueue this plugin;
        # invoked without the gate, it skips instead of probing.
        authorized = (ctx.module_overrides or {}).get("bank") == "authorized" \
            or getattr(ctx, "source_type", "") == "bank"
        if not authorized:
            return self._skipped(
                "bank module not authorized for this run "
                "(module_overrides bank=authorized required)")
        # Audit claim: the authorization basis for this assessment,
        # recorded inside the run.
        findings.append(self._f(
            "financial", "bank_authorization",
            "Bank assessment authorized for this run (operator selected "
            "the bank source type; module_overrides bank=authorized). "
            "Read-only assessment only: no account access, no "
            "transactions, no credential use.",
            source="authorization audit", confidence=100, passive=True,
            evidence={"severity": "info",
                      "note": "Audit claim finding: the authorization "
                              "basis for every other bank finding in "
                              "this run."}))
        domain = domain_from_target(target.type, target.normalized)
        # POI targets: use the operator website if present, else record
        # the location and stop (no host to assess).
        poi = getattr(target, "poi", None)
        base = None
        if target.type == "poi":
            if poi:
                findings.append(self._f(
                    "financial", "bank_poi",
                    f"Bank location: {poi.get('name', 'unknown')} - "
                    f"{poi.get('address', 'no address')} "
                    f"({poi.get('lat')},{poi.get('lon')})",
                    source="OpenStreetMap", confidence=100,
                    passive=True,
                    evidence={"severity": "low", "lat": poi.get("lat"),
                              "lon": poi.get("lon"),
                              "operator": poi.get("operator", ""),
                              "website": poi.get("website", ""),
                              "phone": poi.get("phone", "")}))
                website = (poi.get("website") or "").strip()
                if website:
                    domain = domain_from_target("url", website) or \
                        domain_from_target("domain", website)
                    if domain:
                        base = website if website.startswith("http") \
                            else f"https://{website}"
                    else:
                        res = self._ok(
                            findings, "bank POI recorded, no website to assess")
                        res.duration_ms = int((time.monotonic() - t0) * 1000)
                        return res
                else:
                    res = self._ok(
                        findings, "bank POI recorded, no website to assess")
                    res.duration_ms = int((time.monotonic() - t0) * 1000)
                    return res
            else:
                return self._skipped("no host for this target type")
        if not domain:
            return self._skipped("no host for this target type")
        if base is None:
            base = (target.normalized if target.type == "url"
                    else f"https://{domain}/")
        ts = dt.datetime.now(dt.timezone.utc).isoformat()
        page = await ctx.fetch_page(base, timeout=TIMEOUT)
        if page is None:
            findings.append(self._f("financial", "bank_fetch_failed",
                                    f"Could not fetch {base}",
                                    source="bank plugin", confidence=100,
                                    passive=True,
                                    evidence={"severity": "low"}))
            res = self._ok(findings, "fetch failed, audit kept")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        html = page.get("text", "") or ""
        headers = page.get("headers", {}) or {}
        final = page.get("url", base) or base
        blob = html + "\n" + "\n".join(f"{k}:{v}"
                                       for k, v in headers.items())
        low = blob.lower()
        # 1) core banking platform fingerprints
        platforms = []
        for label, pat, conf in PLATFORMS:
            if re.search(pat, blob, re.IGNORECASE):
                platforms.append(label)
                findings.append(self._f("financial", "bank_platform",
                                        f"Banking platform fingerprint: "
                                        f"{label}", source="bank plugin",
                                        source_url=final, confidence=conf,
                                        passive=True,
                                        evidence={"severity": "medium"}))
        # 2) online banking portal discovery (GET existence checks)
        findings.extend(
            await self._portal_discovery(base, domain, mode, ctx))
        # 3) exposed admin panels (GET existence checks, no login)
        findings.extend(
            await self._admin_panels(base, domain, mode, ctx))
        # 4) banking API surface: HTML patterns + well-known API files
        findings.extend(
            await self._api_surface(base, domain, html, final, mode, ctx))
        # 5) security header audit (financial-site bar)
        findings.extend(self._header_audit(headers, final))
        # 6) online banking login posture
        forms = re.findall(r"<form[^>]*>.*?</form>", html,
                           re.IGNORECASE | re.DOTALL)
        logins = [f for f in forms if re.search(
            r'type\s*=\s*["\']?password', f, re.IGNORECASE)]
        notes = []
        posture_ev = {"severity": "medium", "login_forms": len(logins),
                      "mfa_hints": 0, "rate_limit_headers": [],
                      "cookies_seen": 0}
        if logins:
            lf = "\n".join(logins)
            notes.append(f"{len(logins)} login form(s) found")
            notes.append("password autocomplete=off" if re.search(
                r'autocomplete\s*=\s*["\']?off', lf, re.IGNORECASE) else
                "MISSING: password autocomplete=off")
            posture_ev["password_autocomplete_off"] = bool(re.search(
                r'autocomplete\s*=\s*["\']?off', lf, re.IGNORECASE))
            mfa = sum(bool(re.search(h, html, re.IGNORECASE))
                      for h in MFA_HINTS)
            posture_ev["mfa_hints"] = mfa
            notes.append(f"MFA hints present ({mfa})" if mfa else
                         "MISSING: no MFA hints in page text")
        else:
            notes.append("no login form with password field found")
        rl = [h for h in RL_HEADERS if h in {k.lower() for k in headers}]
        posture_ev["rate_limit_headers"] = rl
        notes.append(f"rate-limit headers: {', '.join(rl)}" if rl else
                     "MISSING: no rate-limit headers seen")
        cookies = [v for k, v in headers.items()
                   if k.lower() == "set-cookie"]
        posture_ev["cookies_seen"] = len(cookies)
        for flag in ("secure", "httponly", "samesite"):
            if cookies:
                n = sum(flag in c.lower() for c in cookies)
                posture_ev[f"cookie_{flag}"] = f"{n}/{len(cookies)}"
                notes.append(f"cookie {flag}: {n}/{len(cookies)}" if n else
                             f"MISSING: cookie {flag} flag not seen")
        if not cookies:
            notes.append("no Set-Cookie headers captured")
        findings.append(self._f("financial", "bank_login_posture",
                                "Login posture: " + "; ".join(notes),
                                source="bank plugin", source_url=final,
                                confidence=80, passive=True,
                                evidence=posture_ev))
        # 7) CVE matching on detected tech. Word boundaries: bare
        # substring matching made short markers like "f5" fire inside
        # random hex strings in page markup - a CVE claim needs the
        # marker as an actual token in the page evidence.
        for marker, cve, title in TECH_CVES:
            hit = re.search(rf"\b{re.escape(marker)}\b", low) is not None
            inferred = False
            if not hit and marker == "log4j" and \
                    any(p in ("Temenos", "Finastra") for p in platforms):
                hit = True  # Java-based core banking stacks
                inferred = True
            if hit:
                findings.append(self._f(
                    "financial", "bank_cve",
                    f"{cve}: {title}. Verify patched "
                    f"version on {domain}.",
                    source="bank plugin",
                    source_url=final,
                    confidence=50 if inferred else 70,
                    passive=True,
                    evidence={"severity": "high",
                              "cve": cve,
                              "marker": marker,
                              "inferred": inferred,
                              "note": ("Inferred from the detected "
                                       "Java-based platform, not from a "
                                       "Log4j marker in page data."
                                       if inferred else
                                       "Marker detected in the site's "
                                       "own page data."),
                              "remediation": "Patch to "
                              "the vendor-fixed version "
                              "immediately."}))
        # 8) PCI DSS indicators
        pci = []
        for m in CARD_INPUT.finditer(html):
            if "mask" not in m.group(0).lower():
                pci.append("card number input without visible masking")
                break
        query = final.split("?", 1)[-1] if "?" in final else ""
        if re.search(r"(card[_-]?number|cardnumber|cc[_-]?num|\bpan=)",
                     query, re.IGNORECASE):
            pci.append("card data present in URL")
        for fm in forms:
            act = re.search(r'action\s*=\s*["\']([^"\']+)', fm, re.IGNORECASE)
            if act and act.group(1).lower().startswith("http:"):
                pci.append("form action over non-HTTPS URL")
                break
        if pci:
            findings.append(self._f("financial", "bank_pci_flag",
                                    "PCI indicators: " + "; ".join(pci),
                                    source="bank plugin", source_url=final,
                                    confidence=85, passive=True,
                                    evidence={"severity": "high",
                                              "remediation": "Never put "
                                              "card data in URLs; mask "
                                              "card inputs; serve all "
                                              "forms over HTTPS."}))
        if len(findings) <= 1:
            # Only the audit claim: assessment ran, nothing found.
            findings.append(self._f(
                "financial", "bank_no_footprint",
                f"No banking infrastructure footprint on {domain} at {ts}: "
                f"no platform fingerprints, portals, admin panels, API "
                f"surface, or CVEs detected",
                source="bank plugin", confidence=70, passive=True,
                evidence={"severity": "low",
                          "note": "Clean result is still a result."}))
        res = self._ok(findings,
                       f"bank assessment done ({len(findings)} findings)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    async def _portal_discovery(self, base: str, domain: str, mode: str,
                                ctx: Ctx) -> List[Finding]:
        out = []
        passive = (mode == "passive")
        root = base.rstrip("/")
        probes = await asyncio.gather(
            *[ctx.probe(root + p) for p in BANKING_PORTAL_PATHS])
        for path, pr in zip(BANKING_PORTAL_PATHS, probes):
            if pr.get("status") == 200:
                url = root + path
                ctx.publish("endpoints", url)
                title = self._title(pr.get("text", ""))
                out.append(self._f(
                    "financial", "bank_portal",
                    f"Online banking portal reachable on {domain}: {path}"
                    + (f" ({title})" if title else ""),
                    source="bank portal discovery", source_url=url,
                    confidence=85, passive=passive,
                    evidence={"severity": "medium", "path": path,
                              "remediation": "Confirm the portal enforces "
                              "MFA, rate limiting, and account lockout. "
                              "Detection only: no credentials submitted."}))
        return out

    async def _admin_panels(self, base: str, domain: str, mode: str,
                            ctx: Ctx) -> List[Finding]:
        out = []
        passive = (mode == "passive")
        root = base.rstrip("/")
        probes = await asyncio.gather(
            *[ctx.probe(root + p) for p in ADMIN_PATHS])
        for path, pr in zip(ADMIN_PATHS, probes):
            if pr.get("status") == 200:
                url = root + path
                title = self._title(pr.get("text", ""))
                out.append(self._f(
                    "financial", "bank_admin_panel",
                    f"Admin panel reachable on {domain}: {path}"
                    + (f" ({title})" if title else ""),
                    source="bank admin probe", source_url=url,
                    confidence=80, passive=passive,
                    evidence={"severity": "high",
                              "remediation": "Admin panels on financial "
                              "sites must be IP-restricted / VPN-only. "
                              "Detection only: existence check, no login "
                              "attempted."}))
        return out

    async def _api_surface(self, base: str, domain: str, html: str,
                           final: str, mode: str, ctx: Ctx) -> List[Finding]:
        out = []
        passive = (mode == "passive")
        api = set()
        for pat in API_PATTERNS:
            api.update(m.group(0) for m in
                       re.finditer(pat, html, re.IGNORECASE))
        api = sorted(api)[:20]
        mob = [h for h in MOBILE_HINTS
               if re.search(h, html, re.IGNORECASE)]
        if api or mob:
            for p in api[:10]:
                ctx.publish("endpoints", p)
            out.append(self._f("financial", "bank_api_surface",
                               f"API hints: {len(api)} API paths, "
                               f"mobile hints: "
                               f"{', '.join(mob) if mob else 'none'}",
                               source="bank plugin", source_url=final,
                               confidence=70, passive=True,
                               evidence={"severity": "medium",
                                         "api_paths": api[:10],
                                         "mobile_hints": mob}))
        # Distinct API / mobile-banking hosts the page itself points
        # at (absolute URLs in markup): the mobile channel usually
        # lives on its own host and is half the attack surface.
        from urllib.parse import urlparse as _up
        hosts = set()
        for m in re.finditer(r"https?://([a-z0-9.\-]+)", html or "",
                             re.IGNORECASE):
            h = m.group(1).lower()
            if h != domain and any(t in h for t in
                                   ("api", "mobile", "olb", "digital",
                                    "mib", "ebanking")):
                hosts.add(h)
        for h in sorted(hosts)[:10]:
            ctx.publish("subdomains", h)
            out.append(self._f(
                "financial", "bank_mobile_api_host",
                f"Banking API/mobile host referenced by {domain}: {h}",
                source="bank API surface", source_url=final,
                confidence=75, passive=passive,
                evidence={"severity": "medium", "host": h,
                          "remediation": "Inventory the mobile/API "
                          "channel with the same rigor as the web "
                          "channel: auth, rate limits, cert pinning on "
                          "the client side."}))
        root = base.rstrip("/")
        probes = await asyncio.gather(
            *[ctx.probe(root + p) for p in API_FILES])
        for path, pr in zip(API_FILES, probes):
            if pr.get("status") == 200:
                url = root + path
                ctx.publish("endpoints", url)
                out.append(self._f(
                    "financial", "bank_api_doc",
                    f"API definition/schema exposed on {domain}: {path}",
                    source="bank API probe", source_url=url,
                    confidence=90, passive=passive,
                    evidence={"severity": "medium", "path": path,
                              "remediation": "API schemas expose your "
                              "full attack surface; restrict to "
                              "authenticated developers."}))
        return out

    def _header_audit(self, headers: dict, final: str) -> List[Finding]:
        out = []
        lowered = {k.lower(): v for k, v in headers.items()}
        for hdr, msg, conf, fix in SEC_HEADERS:
            if hdr not in lowered:
                out.append(self._f(
                    "financial", "bank_missing_header",
                    f"Banking site missing security header: {msg}",
                    source="bank header audit", source_url=final,
                    confidence=conf, passive=True,
                    evidence={"severity": "medium", "header": hdr,
                              "remediation": fix}))
        return out

    @staticmethod
    def _title(html: str) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", html,
                      re.IGNORECASE | re.DOTALL)
        return (m.group(1).strip()[:80] if m else "")
