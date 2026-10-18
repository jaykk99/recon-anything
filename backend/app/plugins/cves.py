"""Version-aware CVE matcher plugin.

Detects software VERSIONS (not just software names) from Server headers,
X-Powered-By, HTML meta generators, and JS library filenames, then matches
them against known CVEs. "Apache 2.4.49 = CVE-2021-41773 path traversal to
RCE" is a real finding, not noise.

All CVEs below are real, public, and version-bounded. Exploitability is
rated so Jay sees weaponized RCEs above theoretical issues.
No API keys needed. GET only, read-only.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


def _parse_version(s: str) -> Tuple[int, ...]:
    """'2.4.49' -> (2, 4, 49). Non-numeric tails are dropped."""
    parts = []
    for chunk in re.split(r"[.\-+_]", s or ""):
        m = re.match(r"(\d+)", chunk)
        if m:
            parts.append(int(m.group(1)))
        else:
            break
    return tuple(parts) or (0,)


def _ver_lt(v: Tuple[int, ...], ref: Tuple[int, ...]) -> bool:
    n = max(len(v), len(ref))
    vv = v + (0,) * (n - len(v))
    rr = ref + (0,) * (n - len(ref))
    return vv < rr


def _ver_eq(v: Tuple[int, ...], ref: Tuple[int, ...]) -> bool:
    n = max(len(v), len(ref))
    vv = v + (0,) * (n - len(v))
    rr = ref + (0,) * (n - len(ref))
    return vv == rr


def _check(op: str, ver: Tuple[int, ...], ref: str) -> bool:
    r = _parse_version(ref)
    if op == "<":
        return _ver_lt(ver, r)
    if op == "<=":
        return _ver_lt(ver, r) or _ver_eq(ver, r)
    if op == "==":
        return _ver_eq(ver, r)
    if op == ">=":
        return not _ver_lt(ver, r)
    return False


# ---------------------------------------------------------------------------
# Version-specific CVE database. Each entry:
#   where: "server" | "powered_by" | "html" | "js" | "wp_generator"
#   version_re: regex with one capture group for the version string
#   vuln: list of (op, version) - ANY match means vulnerable
#   cve / severity / exploitability / title / remediation
# ---------------------------------------------------------------------------
VERSION_CVES: List[Dict] = [
    # -- Apache httpd -------------------------------------------------------
    {"software": "Apache httpd", "where": "server",
     "version_re": r"apache/(\d+\.\d+\.\d+)",
     "vuln": [("==", "2.4.49")],
     "cve": "CVE-2021-41773", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Apache 2.4.49 path traversal to RCE (public exploit)",
     "remediation": "Upgrade Apache to 2.4.51+ immediately. This version has a public RCE exploit."},
    {"software": "Apache httpd", "where": "server",
     "version_re": r"apache/(\d+\.\d+\.\d+)",
     "vuln": [("==", "2.4.50")],
     "cve": "CVE-2021-42013", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Apache 2.4.50 path traversal to RCE - 2.4.49 fix bypassed (public exploit)",
     "remediation": "Upgrade Apache to 2.4.51+ immediately. The 2.4.50 fix was incomplete."},
    {"software": "Apache httpd", "where": "server",
     "version_re": r"apache/(\d+\.\d+\.\d+)",
     "vuln": [("<", "2.4.59")],
     "cve": "CVE-2024-38476", "severity": "high",
     "exploitability": "public_poc",
     "title": "Apache < 2.4.59 mod_proxy SSRF via malicious backend URL",
     "remediation": "Upgrade Apache to 2.4.59+. Review mod_proxy configs for attacker-controlled backend URLs."},
    {"software": "Apache httpd", "where": "server",
     "version_re": r"apache/2\.2(\.\d+)?",
     "vuln": [(">=", "0")],
     "cve": "EOL", "severity": "high",
     "exploitability": "public_poc",
     "title": "Apache 2.2 is end-of-life (no security patches since 2017)",
     "remediation": "Migrate to Apache 2.4.x. 2.2 has unpatched CVEs with public exploits."},
    # -- nginx --------------------------------------------------------------
    {"software": "nginx", "where": "server",
     "version_re": r"nginx/(\d+\.\d+\.\d+)",
     "vuln": [("<", "1.21.6")],
     "cve": "CVE-2021-23017", "severity": "medium",
     "exploitability": "public_poc",
     "title": "nginx < 1.21.6 resolver 1-byte memory overwrite (DNS response)",
     "remediation": "Upgrade nginx to 1.21.6+. Only exploitable when the resolver is used with attacker-influenced DNS."},
    # -- Microsoft IIS -------------------------------------------------------
    {"software": "Microsoft IIS", "where": "server",
     "version_re": r"microsoft-iis/(\d+\.\d+)",
     "vuln": [("==", "6.0")],
     "cve": "CVE-2017-7269", "severity": "critical",
     "exploitability": "weaponized",
     "title": "IIS 6.0 WebDAV buffer overflow RCE (public Metasploit module)",
     "remediation": "IIS 6.0 is end-of-life. Migrate off Windows Server 2003 immediately."},
    {"software": "Microsoft IIS", "where": "server",
     "version_re": r"microsoft-iis/7\.5",
     "vuln": [(">=", "0")],
     "cve": "EOL", "severity": "medium",
     "exploitability": "theoretical",
     "title": "IIS 7.5 is end-of-life (Server 2008 R2, no patches)",
     "remediation": "Migrate to a supported IIS version."},
    # -- OpenSSL (often inside the Server header) -----------------------------
    {"software": "OpenSSL", "where": "server",
     "version_re": r"openssl/(1\.0\.1[a-f])",
     "vuln": [(">=", "0")],
     "cve": "CVE-2014-0160", "severity": "critical",
     "exploitability": "weaponized",
     "title": "OpenSSL 1.0.1 Heartbleed - reads server memory incl. private keys (public exploit)",
     "remediation": "Upgrade OpenSSL to 1.0.1g+ immediately and rotate all certificates and keys."},
    # -- PHP (X-Powered-By) ----------------------------------------------------
    {"software": "PHP", "where": "powered_by",
     "version_re": r"php/(\d+\.\d+\.\d+)",
     "vuln": [("<", "8.3.8"), ("<", "8.2.21"), ("<", "8.1.29")],
     "cve": "CVE-2024-4577", "severity": "critical",
     "exploitability": "weaponized",
     "title": "PHP-CGI argument injection to RCE on Windows (public exploit)",
     "remediation": "Upgrade PHP to 8.3.8 / 8.2.21 / 8.1.29+. Move off PHP-CGI; use mod_php or php-fpm."},
    {"software": "PHP", "where": "powered_by",
     "version_re": r"php/8\.1\.0-dev",
     "vuln": [(">=", "0")],
     "cve": "BACKDOOR", "severity": "critical",
     "exploitability": "weaponized",
     "title": "PHP 8.1.0-dev backdoor - RCE via User-Agentt header (no CVE, real backdoor)",
     "remediation": "This is a backdoored dev build. Rebuild from a clean release immediately."},
    {"software": "PHP", "where": "powered_by",
     "version_re": r"php/([45]\.\d+\.\d+)",
     "vuln": [(">=", "0")],
     "cve": "EOL", "severity": "high",
     "exploitability": "public_poc",
     "title": "PHP 5.x/4.x is end-of-life with unpatched RCE CVEs",
     "remediation": "Upgrade to a supported PHP 8.x release."},
    # -- Express.js ------------------------------------------------------------
    {"software": "Express.js", "where": "powered_by",
     "version_re": r"express",
     "vuln": [],
     "cve": "CVE-2022-24999", "severity": "medium",
     "exploitability": "public_poc",
     "title": "Express < 4.17.3 qs prototype pollution - verify version",
     "remediation": "Upgrade Express to 4.17.3+. Confirm the qs version bundled.",
     "version_optional": True},
    # -- Next.js ---------------------------------------------------------------
    {"software": "Next.js", "where": "powered_by",
     "version_re": r"next\.js",
     "vuln": [],
     "cve": "CVE-2025-29927", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Next.js middleware authorization bypass < 15.2.3 / < 14.2.25 - verify version (public exploit)",
     "remediation": "Upgrade Next.js to 15.2.3+ / 14.2.25+. Check x-powered-by or build manifests for the version.",
     "version_optional": True},
    # -- WordPress (meta generator) ---------------------------------------------
    {"software": "WordPress", "where": "wp_generator",
     "version_re": r"wordpress (\d+\.\d+(?:\.\d+)?)",
     "vuln": [("<", "5.8.3")],
     "cve": "CVE-2022-21661", "severity": "high",
     "exploitability": "public_poc",
     "title": "WordPress < 5.8.3 WP_Query SQL injection",
     "remediation": "Upgrade WordPress core immediately."},
    # -- JS libraries (filenames / CDN URLs in HTML) ------------------------------
    {"software": "jQuery", "where": "js",
     "version_re": r"jquery[/-](\d+\.\d+\.\d+)",
     "vuln": [("<", "3.5.0")],
     "cve": "CVE-2020-11022 / CVE-2020-11023", "severity": "medium",
     "exploitability": "public_poc",
     "title": "jQuery < 3.5.0 XSS via html()/DOM manipulation",
     "remediation": "Upgrade jQuery to 3.5.0+."},
    {"software": "Bootstrap", "where": "js",
     "version_re": r"bootstrap[/-](\d+\.\d+\.\d+)",
     "vuln": [("<", "4.6.1")],
     "cve": "CVE-2018-14041", "severity": "medium",
     "exploitability": "public_poc",
     "title": "Bootstrap < 4.6.1 XSS in collapse plugin",
     "remediation": "Upgrade Bootstrap to 4.6.1+ (or 5.x)."},
    {"software": "AngularJS", "where": "js",
     "version_re": r"angular(?:\.min)?\.js|angular/(\d+\.\d+\.\d+)",
     "vuln": [("<", "1.8.0")],
     "cve": "CVE-2021-4231", "severity": "medium",
     "exploitability": "public_poc",
     "title": "AngularJS < 1.8.0 XSS (EOL framework, multiple known XSS CVEs)",
     "remediation": "Migrate off AngularJS (EOL). At minimum upgrade to 1.8.3+."},
    {"software": "Moment.js", "where": "js",
     "version_re": r"moment[/-](\d+\.\d+\.\d+)",
     "vuln": [("<", "2.29.4")],
     "cve": "CVE-2022-24785", "severity": "medium",
     "exploitability": "theoretical",
     "title": "Moment.js < 2.29.4 path traversal / ReDoS",
     "remediation": "Upgrade Moment.js to 2.29.4+ or migrate to a maintained date library."},
    {"software": "Lodash", "where": "js",
     "version_re": r"lodash[/-](\d+\.\d+\.\d+)",
     "vuln": [("<", "4.17.21")],
     "cve": "CVE-2021-23337 / CVE-2020-28500", "severity": "medium",
     "exploitability": "public_poc",
     "title": "Lodash < 4.17.21 prototype pollution",
     "remediation": "Upgrade Lodash to 4.17.21+."},
    # -- CMS / framework generic signatures (kept from before, tightened) -----------
    {"software": "Joomla", "where": "html",
     "version_re": r"joomla",
     "vuln": [],
     "cve": "CVE-2023-23752", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Joomla < 4.2.8 improper API access - check version (public exploit)",
     "remediation": "Upgrade Joomla to 4.2.8+.",
     "version_optional": True},
    {"software": "Drupal", "where": "html",
     "version_re": r"drupal",
     "vuln": [],
     "cve": "CVE-2018-7600", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Drupalgeddon2 RCE - check version < 7.58 / < 8.5.1 (public exploit)",
     "remediation": "Upgrade Drupal immediately if below 7.58 / 8.5.1.",
     "version_optional": True},
    {"software": "Laravel", "where": "html",
     "version_re": r"laravel",
     "vuln": [],
     "cve": "CVE-2021-3129", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Laravel debug mode RCE via /_ignition/execute-solution - check if debug is on",
     "remediation": "Disable APP_DEBUG in production. Upgrade Laravel.",
     "version_optional": True},
    {"software": "Apache Struts", "where": "html",
     "version_re": r"struts",
     "vuln": [],
     "cve": "CVE-2017-5638", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Struts2 Jakarta RCE - check version (public exploit)",
     "remediation": "Upgrade Struts to a patched release.",
     "version_optional": True},
    {"software": "Spring Framework", "where": "html",
     "version_re": r"spring",
     "vuln": [],
     "cve": "CVE-2022-22965", "severity": "critical",
     "exploitability": "weaponized",
     "title": "Spring4Shell RCE - verify Spring >= 5.3.18 / 5.2.20 (public exploit)",
     "remediation": "Upgrade Spring Framework to 5.3.18+ / 5.2.20+. Check /actuator for version leaks.",
     "version_optional": True},
]

POC_HINT = ("Verify: curl -sI {url} | grep -iE '^(server|x-powered-by):' "
            "then match the version against the CVE.")


class CvesPlugin(Plugin):
    id = "cves"
    label = "CVE Matcher"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Detect software versions, match against known CVEs with exploitability."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        url = f"https://{domain}" if target.type == "domain" else target.normalized
        findings: List[Finding] = []

        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=15)
        except Exception as e:
            return self._degraded(f"could not fetch: {str(e)[:150]}")

        body = r.text[:200000]
        body_low = body.lower()
        server_h = r.headers.get("server", "")
        powered = r.headers.get("x-powered-by", "")
        headers_low = (server_h + " " + powered).lower()

        # WordPress generator version
        wp_ver: Optional[str] = None
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress (\d+\.\d+(?:\.\d+)?)',
                      body, re.I)
        if m:
            wp_ver = m.group(1)

        seen_cves = set()

        for entry in VERSION_CVES:
            where = entry["where"]
            if where == "server":
                hay = headers_low
            elif where == "powered_by":
                hay = headers_low
            elif where == "wp_generator":
                hay = f"wordpress {wp_ver}" if wp_ver else ""
                if not wp_ver:
                    continue
            elif where in ("html", "js"):
                hay = body_low
            else:
                continue

            m = re.search(entry["version_re"], hay, re.I)
            if not m:
                continue
            ver_str = None
            try:
                ver_str = m.group(1)
            except IndexError:
                ver_str = None

            vulnerable = False
            if entry.get("version_optional"):
                # Software detected, version unknown: advisory finding.
                vulnerable = True
            elif ver_str:
                ver = _parse_version(ver_str)
                for op, ref in entry["vuln"]:
                    if _check(op, ver, ref):
                        vulnerable = True
                        break
            if not vulnerable:
                continue

            dedupe = (entry["cve"], entry["software"])
            if dedupe in seen_cves:
                continue
            seen_cves.add(dedupe)

            ver_note = f"detected version {ver_str}" if ver_str else "version not disclosed - verify manually"
            findings.append(self._f(
                "web", "cve_match",
                f"{entry['severity'].upper()}: {entry['software']} - {entry['title']} "
                f"[{entry['cve']}] ({ver_note})",
                source="CVE matcher", source_url=url,
                confidence=88 if ver_str else 65, passive=True,
                exploitability=entry["exploitability"],
                evidence={
                    "severity": entry["severity"],
                    "cve": entry["cve"],
                    "software": entry["software"],
                    "detected_version": ver_str or "unknown",
                    "remediation": entry["remediation"],
                    "poc_hint": POC_HINT.format(url=url),
                }))

        # WordPress REST API exposure (version enum fuel)
        if "wp-content" in body_low or "wp-includes" in body_low:
            try:
                r2 = await fetch(ctx.http, ctx.limiter, "GET",
                                 url.rstrip("/") + "/wp-json/wp/v2/users",
                                 timeout=10)
                if r2.status_code == 200 and "slug" in r2.text[:2000]:
                    findings.append(self._f(
                        "web", "wp_user_enum",
                        "HIGH: WordPress REST user enumeration at /wp-json/wp/v2/users - usernames disclosed",
                        source="CVE matcher",
                        source_url=url.rstrip("/") + "/wp-json/wp/v2/users",
                        confidence=85, passive=True,
                        exploitability="public_poc",
                        evidence={"severity": "high",
                                  "remediation": "Restrict /wp-json/wp/v2/users to authenticated users."}))
            except Exception:
                pass

        dur = int((time.monotonic() - t0) * 1000)
        # No "nothing found" noise finding: silence is fine, Jay hates noise.
        res = self._ok(findings, f"matched {len(findings)} version CVEs")
        res.duration_ms = dur
        return res
