"""CMS deep probes: version detection + known-vuln checks.

Covers WordPress, Drupal, Joomla, Shopify, Squarespace, and Wix.
Detects the platform and its exact version via generator meta tags,
readme / changelog files, headers, and API endpoints. Then runs
platform-specific known-vuln checks (all GET-only, read-only):
  - WordPress: readme.html version, wp-json/wp/v2/users user enumeration,
    /wp-json/ root listing, xmlrpc.php enabled, wp-cron, sensitive
    paths (wp-config.php.bak), vulnerable-plugin slug detection
  - Drupal: CHANGELOG.txt version, /user/login
  - Joomla: administrator/manifests version, README.txt
  - Shopify: /.well-known/change-password, /admin login wall,
    /products.json + /collections.json inventory disclosure, theme/app
    leaks in HTML, third-party app scripts
  - Squarespace: /config auth wall, ?format=json API exposure,
    /api/open/* endpoints, version disclosure
  - Wix: /_api/ endpoints, version disclosure

Outdated/EOL platform versions are flagged high. No login attempts,
no writes.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple

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


# (plugin slug, version fixed in, public CVE note) - top 20 commonly
# vulnerable WordPress plugins. Kept small (20) for time budget.
WP_VULN_PLUGINS: List[Tuple[str, str, str]] = [
    ("revslider", "6.6.8", "Revolution Slider - multiple unauth RCE CVEs"),
    ("wp-file-manager", "6.9", "File Manager - CVE-2020-25213 unauth RCE"),
    ("contact-form-7", "5.8.4", "Contact Form 7 - CVE-2023-2982 file upload"),
    ("woocommerce", "8.6.0", "WooCommerce - order attribution data leak"),
    ("elementor", "3.18.0", "Elementor - auth-bypass file upload CVEs"),
    ("elementor-pro", "3.18.0", "Elementor Pro - privilege escalation CVEs"),
    ("wordpress-seo", "21.2", "Yoast SEO - stored XSS CVEs"),
    ("all-in-one-seo-pack", "4.2.9", "AIOSEO - privilege escalation CVEs"),
    ("updraftplus", "1.23.4", "UpdraftPlus - CVE-2022-0633 auth bypass"),
    ("wpforms-lite", "1.8.6", "WPForms - Stripe key leak CVEs"),
    ("duplicator", "1.5.8", "Duplicator - unauth data exposure"),
    ("litespeed-cache", "6.5.2", "LiteSpeed Cache - CVE-2024-28000 priv esc"),
    ("better-wp-security", "8.1.7", "iThemes Security - path traversal"),
    ("wp-super-cache", "1.10.4", "WP Super Cache - auth RCE CVEs"),
    ("advanced-custom-fields", "6.2.5", "ACF - unauth XSS/auth bypass"),
    ("jetpack", "12.1.4", "Jetpack - contact form info leak"),
    ("akismet", "5.3", "Akismet - stored XSS CVEs"),
    ("really-simple-ssl", "7.0.16", "Really Simple SSL - auth bypass CVE"),
    ("wordfence", "7.11.0", "Wordfence - outdated scanning core"),
    ("classic-editor", "1.6.3", "Classic Editor - unpatched edge cases"),
]

# Shopify third-party app script markers that are known-vuln prone
# (best effort - flag presence, let owner review CVE status).
SHOPIFY_APP_HINTS = [
    "loox", "judge.me", "judgeme", "yotpo", "klaviyo", "privy",
    "omnisend", "mailchimp", "gorgias", "recharge", "bold", "shogun",
    "pagefly", "gem-pages", "loyalty", "smile.io",
]

WP_DEBUG_MARKERS = re.compile(
    r"WP_DEBUG|Notice:\s+Undefined|Warning:\s+(require|include)|"
    r"Fatal error:|Call to undefined function", re.I)

SHOPIFY_SCRIPT_RE = re.compile(
    r'src="([^"]*(?:cdn\.shopify\.com|myshopify\.com)[^"]*)"', re.I)

SHOPIFY_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)


class CmsProbesPlugin(Plugin):
    id = "cms_probes"
    label = "CMS Probes"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    # Phase 2: runs after tech_fingerprint/fingerprint (phase 1) so the
    # cms_chain can hand it a confirmed CMS to probe deeply.
    phase = 2
    description = ("WordPress/Drupal/Joomla + Shopify/Squarespace/Wix "
                   "version detection + known-vuln checks. "
                   "GET only, no login attempts.")

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
            # Chain confirmation boost: when the cms_chain hinted this CMS
            # (fingerprint already saw it) and our probes confirm it,
            # the finding is corroborated - bump confidence, cap 95.
            if chained and conf < 95:
                conf = min(conf + 5, 95)
            findings.append(self._f(
                "web", key, value, source="CMS probes",
                source_url=url or base, confidence=conf, passive=passive,
                evidence={"severity": sev, "remediation": remediation}))

        # ---- homepage: generator meta + fingerprints ----
        status, html, hdrs = await get("/", timeout=20)
        if status == 0:
            res = self._degraded("could not fetch homepage")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        hdr_text = " ".join(f"{k}: {v}" for k, v in hdrs.items()).lower()
        html_l = html.lower()

        cms: Optional[str] = None
        version: Optional[str] = None

        m = re.search(r'<meta[^>]+name="generator"[^>]+content="WordPress\s*([\d.]+)"',
                      html, re.I)
        if m or "wp-content" in html or "wp-includes" in html:
            cms = "wordpress"
            version = m.group(1) if m else None
        elif ("cdn.shopify.com" in html_l or "myshopify.com" in html_l
                or "x-shopify" in hdr_text):
            cms = "shopify"
            m2 = re.search(r"Shopify\.theme[^}]*version[^0-9]*([0-9.]+)",
                           html, re.I)
            version = m2.group(1) if m2 else None
        elif "squarespace.com" in html_l or "static1.squarespace.com" in html_l:
            cms = "squarespace"
            m2 = re.search(r'"templateVersion"\s*:\s*"([^"]+)"', html)
            if not m2:
                m2 = re.search(r'squarespace[^0-9]*([0-9]{1,2}\.[0-9.]+)',
                               html, re.I)
            version = m2.group(1) if m2 else None
        elif ("wixstatic.com" in html_l or "parastorage.com" in html_l
                or "wix.com" in html_l):
            cms = "wix"
            m2 = re.search(r'viewerModel[^}]*"version"\s*:\s*"([^"]+)"', html)
            version = m2.group(1) if m2 else None
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

        # ---- chain: tech_fingerprint / fingerprint (phase 1) may have
        # already confirmed a CMS via headers, scripts, or cookies that the
        # homepage HTML above missed. A chain hint either corroborates our
        # own detection (confidence boost in add()) or becomes the
        # candidate CMS so the deep checks still run (cms_chain in
        # backend/app/chains.py). Detection only, GET requests.
        chained = False
        try:
            from ..chains import chain_signals
            hints = [h for h in chain_signals(ctx, "cms")
                     if h in ("wordpress", "drupal", "joomla", "shopify",
                              "squarespace", "wix")]
        except Exception:
            hints = []
        if cms and cms in hints:
            chained = True  # fingerprint corroborates homepage detection
        elif not cms and hints:
            cms = hints[0]
            chained = True
            add("cms_chain_triggered",
                f"Chain: tech fingerprinting flagged {cms.title()} - "
                f"running {cms.title()} deep checks on the chain hint.",
                80, "low",
                "No action needed - this records why the CMS checks ran.")

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
            # /wp-json/ root listing exposure
            st, body, _ = await get("/wp-json/")
            if st == 200 and '"routes"' in body:
                routes = re.findall(r'"(/wp-json/[^"]*)"', body)[:8]
                add("cms_api_listing",
                    "MEDIUM: /wp-json/ root listing exposes the full REST "
                    f"API route map ({len(routes)} routes sampled: "
                    f"{', '.join(routes) if routes else 'routes visible'})",
                    80, "medium",
                    "Restrict REST API index exposure; disable unused routes.",
                    base + "/wp-json/")
            # vulnerable plugin slug detection (readme.txt per plugin)
            for slug, fixed, note in WP_VULN_PLUGINS:
                st, body, _ = await get(f"/wp-content/plugins/{slug}/readme.txt",
                                        timeout=8)
                if st != 200:
                    continue
                mv = re.search(r"Stable tag:\s*([\d.]+)", body, re.I)
                installed = mv.group(1) if mv else "unknown"
                ivt, fvt = _ver_tuple(installed), _ver_tuple(fixed)
                if ivt and fvt and ivt < fvt:
                    add("cms_vuln_plugin",
                        f"HIGH: vulnerable WP plugin '{slug}' {installed} "
                        f"installed (fixed in {fixed}) - {note}",
                        85, "high",
                        f"Update plugin '{slug}' to >= {fixed} immediately; "
                        f"audit for signs of compromise.",
                        base + f"/wp-content/plugins/{slug}/readme.txt")
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
        elif cms == "shopify":
            # /.well-known/change-password (Shopify stores have this)
            st, body, _ = await get("/.well-known/change-password")
            if st != 200:
                add("cms_shopify_changepw",
                    "LOW: /.well-known/change-password not reachable "
                    f"(HTTP {st})",
                    60, "low",
                    "Ensure the standard password-change endpoint is in "
                    "place for account recovery flows.",
                    base + "/.well-known/change-password")
            # /admin should redirect to a login wall, never 200 raw
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", base + "/admin",
                                timeout=12, max_retries=1,
                                follow_redirects=False)
                loc = r.headers.get("location", "")
                if r.status_code == 200:
                    txt = r.text[:5000].lower()
                    if "password" not in txt and "login" not in txt:
                        add("cms_shopify_admin",
                            "MEDIUM: /admin returned 200 without redirecting "
                            "to a login page - admin surface may be exposed",
                            75, "medium",
                            "Confirm /admin redirects to Shopify auth; "
                            "enable MFA and restrict staff accounts.",
                            base + "/admin")
            except Exception:
                pass
            # inventory JSON disclosure
            for p in ("/products.json", "/collections.json"):
                st, body, _ = await get(p)
                if st == 200 and ('"products"' in body or '"collections"' in body):
                    n = body.count('"handle"')
                    add("cms_shopify_json",
                        f"MEDIUM: {p} exposes inventory data "
                        f"(~{n} handles) - competitor scraping / price "
                        f"monitoring surface",
                        80, "medium",
                        f"Restrict {p} (disable if unused); monitor for "
                        f"scraping abuse.",
                        base + p)
            # version/app leaks in HTML comments
            for cm in SHOPIFY_COMMENT_RE.findall(html)[:30]:
                if "shopify" in cm.lower() and re.search(r"\d+\.\d+", cm):
                    add("cms_shopify_comment_leak",
                        f"LOW: HTML comment leaks Shopify build info: "
                        f"{cm.strip()[:120]}",
                        65, "low",
                        "Strip build/version info from public HTML comments.",
                        base)
                    break
            # third-party app scripts (best-effort vuln-app review)
            scripts = SHOPIFY_SCRIPT_RE.findall(html)
            app_hits = sorted({s for s in scripts
                               for h in SHOPIFY_APP_HINTS
                               if h in s.lower()})
            if app_hits:
                names = ", ".join(s.split("/")[2][:40] for s in app_hits[:8])
                add("cms_shopify_apps",
                    f"LOW: {len(app_hits)} third-party Shopify app scripts "
                    f"detected ({names}) - review each for known CVEs",
                    60, "low",
                    "Audit installed Shopify apps; remove unused ones and "
                    "check for published CVEs.",
                    base)
        elif cms == "squarespace":
            # /config should require auth
            st, body, _ = await get("/config")
            if st == 200 and re.search(r"squarespace.*config|config.*squarespace",
                                       body, re.I) \
                    and "login" not in body[:5000].lower():
                add("cms_squarespace_config",
                    "HIGH: /config returned config UI content without an "
                    "obvious login wall",
                    70, "high",
                    "Confirm /config requires auth; audit admin sessions.",
                    base + "/config")
            elif st == 200:
                add("cms_squarespace_config",
                    "LOW: /config reachable (check it gates behind login)",
                    55, "low",
                    "Confirm /config requires auth; audit admin sessions.",
                    base + "/config")
            # ?format=json API exposure
            st, body, _ = await get("/?format=json", timeout=8)
            if st == 200 and ('"website"' in body or '"items"' in body):
                add("cms_squarespace_json",
                    "MEDIUM: ?format=json exposes the site's JSON API "
                    "(content structure enumerable)",
                    80, "medium",
                    "Disable JSON format exposure if unused; review content "
                    "leakage.",
                    base + "/?format=json")
            # /api/open/* endpoints
            for p in ("/api/open/GetSections", "/api/open/GetCart"):
                st, body, _ = await get(p, timeout=8)
                if st == 200 and len(body.strip()) > 10:
                    add("cms_squarespace_api",
                        f"MEDIUM: Squarespace API endpoint {p} returns data "
                        f"without auth ({len(body)} bytes)",
                        75, "medium",
                        f"Audit {p}; restrict unauthenticated API access.",
                        base + p)
            # version disclosure
            if version:
                add("cms_version_disclosure",
                    f"LOW: Squarespace template/build version {version} "
                    f"disclosed in page source",
                    60, "low",
                    "Version disclosure is minor; keep the template updated.",
                    base)
        elif cms == "wix":
            # /_api/ endpoints exposure
            for p in ("/_api/communities-blog-node/_api/posts",
                      "/_api/wix-data/v1"):
                st, body, _ = await get(p, timeout=8)
                if st == 200 and len(body.strip()) > 10:
                    add("cms_wix_api",
                        f"MEDIUM: Wix API endpoint {p} returns data without "
                        f"auth ({len(body)} bytes)",
                        75, "medium",
                        f"Audit {p}; restrict unauthenticated API access.",
                        base + p)
            # version disclosure via parastorage service URLs
            svc = re.findall(
                r"https://static\.parastorage\.com/services/([^\"'\s]{1,60})",
                html)
            if svc:
                add("cms_version_disclosure",
                    f"LOW: Wix service bundle versions disclosed "
                    f"({svc[0][:60]})",
                    60, "low",
                    "Version disclosure is minor; keep the site builder "
                    "updated.",
                    base)
            if version:
                add("cms_version_disclosure",
                    f"LOW: Wix viewer version {version} disclosed",
                    60, "low",
                    "Version disclosure is minor; keep the site builder "
                    "updated.",
                    base)
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

        # ---- debug markers for WP ----
        if cms == "wordpress" and WP_DEBUG_MARKERS.search(html):
            add("cms_debug",
                "MEDIUM: PHP debug/notice output visible - WP_DEBUG or "
                "display_errors likely on",
                70, "medium",
                "Disable WP_DEBUG and display_errors in production.",
                base)

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
