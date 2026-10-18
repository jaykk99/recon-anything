"""CMS deep probes: WordPress / Drupal / Joomla version detection + known-vuln checks.

Detects the CMS and its exact version via generator meta tags, readme /
changelog files, and API endpoints. Then runs CMS-specific known-vuln
checks (all GET-only, read-only):
  - WordPress: readme.html version, wp-json/wp/v2/users user enumeration,
    xmlrpc.php enabled, wp-cron, sensitive paths (wp-config.php.bak)
  - Drupal: CHANGELOG.txt version, /user/login, node info
  - Joomla: administrator/manifests version, README.txt

Outdated/EOL CMS versions are flagged high. No login attempts, no writes.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# minimum supported major.minor per CMS (below = EOL/flag high)
CMS_EOL = {
    "wordpress": (6, 0),
    "drupal": (10, 0),
    "joomla": (4, 0),
}


def _ver_tuple(v: str) -> Optional[tuple]:
    try:
        return tuple(int(x) for x in v.split(".")[:2])
    except Exception:
        return None


class CmsProbesPlugin(Plugin):
    id = "cms_probes"
    label = "CMS Probes"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("WordPress/Drupal/Joomla version detection + known-vuln "
                   "checks. GET only, no login attempts.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        async def get(path: str, timeout: int = 12):
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base + path,
                                timeout=timeout, max_retries=1,
                                follow_redirects=True)
                return r.status_code, r.text[:200000], dict(r.headers)
            except Exception:
                return 0, "", {}

        def add(key, value, conf, sev, remediation, url=None):
            findings.append(self._f(
                "web", key, value, source="CMS probes",
                source_url=url or base, confidence=conf, passive=passive,
                evidence={"severity": sev, "remediation": remediation}))

        # ---- homepage: generator meta + fingerprints ----
        status, html, _ = await get("/", timeout=20)
        if status == 0:
            res = self._degraded("could not fetch homepage")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        cms: Optional[str] = None
        version: Optional[str] = None

        m = re.search(r'<meta[^>]+name="generator"[^>]+content="WordPress\s*([\d.]+)"',
                      html, re.I)
        if m or "wp-content" in html or "wp-includes" in html:
            cms = "wordpress"
            version = m.group(1) if m else None
        elif re.search(r'Drupal\s*(\d+)', html) or "drupal.js" in html \
                or "sites/default/files" in html:
            m2 = re.search(
                r'<meta[^>]+name="Generator"[^>]+content="Drupal\s*(\d+)',
                html, re.I)
            cms = "drupal"
            version = m2.group(1) if m2 else None
        elif re.search(r'Joomla!?\s*([\d.]+)', html, re.I) or \
                "/media/jui/" in html or "com_content" in html:
            m3 = re.search(
                r'<meta[^>]+name="generator"[^>]+content="Joomla!?\s*([\d.]+)"',
                html, re.I)
            cms = "joomla"
            version = m3.group(1) if m3 else None

        if not cms:
            res = self._ok([], "no supported CMS fingerprinted")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        add("cms_detected", f"CMS detected: {cms.title()}"
            + (f" {version}" if version else " (version unknown)"),
            85, "medium",
            "Inventory this CMS install; keep core + plugins patched.")

        # ---- version disclosure files ----
        if cms == "wordpress":
            st, body, _ = await get("/readme.html")
            if st == 200:
                mv = re.search(r"Version\s*([\d.]+)", body, re.I)
                if mv and not version:
                    version = mv.group(1)
                add("cms_version_disclosure",
                    f"HIGH: WordPress readme.html exposes version "
                    f"{mv.group(1) if mv else '(unparsed)'}",
                    85, "high",
                    "Delete readme.html from the web root; it aids targeting.",
                    base + "/readme.html")
            # REST API user enumeration (info disclosure)
            st, body, _ = await get("/wp-json/wp/v2/users")
            if st == 200 and '"slug"' in body:
                users = re.findall(r'"slug"\s*:\s*"([^"]+)"', body)[:10]
                add("cms_user_enum",
                    f"HIGH: WordPress REST API enumerates users: "
                    f"{', '.join(users) if users else 'user list exposed'}",
                    85, "high",
                    "Restrict /wp-json/wp/v2/users to authenticated users.",
                    base + "/wp-json/wp/v2/users")
            # xmlrpc enabled (brute-force/SSRF vector)
            st, body, _ = await get("/xmlrpc.php")
            if st == 200 and "XML-RPC" in body:
                add("cms_xmlrpc",
                    "MEDIUM: xmlrpc.php enabled - credential brute-force + "
                    "pingback SSRF vector",
                    75, "medium",
                    "Disable XML-RPC if unused (remove or block at WAF).",
                    base + "/xmlrpc.php")
            # wp-cron exposed
            st, body, _ = await get("/wp-cron.php")
            if st == 200:
                add("cms_wpcron",
                    "LOW: wp-cron.php directly reachable (DoS amplification)",
                    60, "low",
                    "Disable default wp-cron and run via system cron.",
                    base + "/wp-cron.php")
            # sensitive leftovers
            for p in ("/wp-config.php.bak", "/wp-config.php.old",
                      "/wp-config.php.save", "/.git/HEAD"):
                st, body, _ = await get(p)
                if st == 200 and len(body.strip()) > 20:
                    add("cms_config_leak",
                        f"CRITICAL: sensitive file {p} is web-reachable "
                        f"({len(body)} bytes)",
                        90, "critical",
                        f"Remove {p} from the web root immediately and "
                        f"rotate any credentials it contained.",
                        base + p)
        elif cms == "drupal":
            st, body, _ = await get("/CHANGELOG.txt")
            if st == 200:
                mv = re.search(r"Drupal\s*([\d.]+)", body, re.I)
                if mv and not version:
                    version = mv.group(1)
                add("cms_version_disclosure",
                    f"HIGH: Drupal CHANGELOG.txt exposes version "
                    f"{mv.group(1) if mv else '(unparsed)'}",
                    85, "high",
                    "Block CHANGELOG.txt (and INSTALL.txt) at the web server.",
                    base + "/CHANGELOG.txt")
            st, body, _ = await get("/user/login")
            if st == 200 and "user-login" in body.lower():
                add("cms_login_exposed",
                    "LOW: Drupal /user/login reachable (expected; ensure "
                    "brute-force protection)",
                    55, "low",
                    "Rate-limit logins; enforce MFA for admins.",
                    base + "/user/login")
        elif cms == "joomla":
            st, body, _ = await get("/administrator/manifests/files/joomla.xml")
            mv = re.search(r"<version>([\d.]+)</version>", body) if st == 200 else None
            if mv:
                version = mv.group(1)
                add("cms_version_disclosure",
                    f"HIGH: Joomla version manifest exposes {version}",
                    85, "high",
                    "Block administrator/manifests at the web server.",
                    base + "/administrator/manifests/files/joomla.xml")
            st, body, _ = await get("/README.txt")
            if st == 200 and "Joomla" in body:
                add("cms_readme",
                    "LOW: Joomla README.txt reachable",
                    60, "low", "Remove README.txt from the web root.",
                    base + "/README.txt")

        # ---- EOL / outdated check ----
        if version:
            eol_min = CMS_EOL.get(cms)
            vt = _ver_tuple(version)
            if eol_min and vt and vt < eol_min:
                add("cms_eol",
                    f"HIGH: {cms.title()} {version} is END OF LIFE "
                    f"(supported >= {eol_min[0]}.{eol_min[1]}) - unpatched "
                    f"CVEs almost certain",
                    85, "high",
                    f"Upgrade {cms.title()} to a supported release "
                    f"immediately; audit plugins/modules too.")

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"{cms.title()} probed, {len(findings)} findings")
        res.duration_ms = dur
        return res
