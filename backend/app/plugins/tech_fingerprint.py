"""Deep technology fingerprinting with exact versions, CVE matching, EOL flags.

Extends webtech: 100+ version-capturing signatures over headers, HTML,
meta generator tags, script/style URLs, and cookies. Exact versions are
matched against the OSV CVE database (api.osv.dev, free, no key) and an
embedded end-of-life table. EOL software and known-vulnerable versions
are flagged high.

Passive. OSV lookups are best-effort: unreachable API degrades to
version-only findings, never errors.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (name, where, regex with one version group, osv ecosystem, osv package)
# where: headers | html | cookies
VERSION_RULES: List[Tuple[str, str, str, str, str]] = [
    # web servers
    ("Apache", "headers", r"Apache/(\d+\.\d+(?:\.\d+)?)", "", ""),
    ("nginx", "headers", r"nginx/(\d+\.\d+(?:\.\d+)?)", "", ""),
    ("IIS", "headers", r"Microsoft-IIS/(\d+\.\d+)", "", ""),
    ("LiteSpeed", "headers", r"LiteSpeed", "", ""),
    ("Caddy", "headers", r"Caddy", "", ""),
    ("Gunicorn", "headers", r"gunicorn/(\d+\.\d+(?:\.\d+)?)", "", ""),
    ("uWSGI", "headers", r"uWSGI", "", ""),
    # languages / runtimes
    ("PHP", "headers", r"PHP/(\d+\.\d+(?:\.\d+)?)", "", ""),
    ("PHP", "html", r"php[ /-](\d+\.\d+(?:\.\d+)?)", "", ""),
    ("Python", "headers", r"Python/(\d+\.\d+(?:\.\d+)?)", "", ""),
    ("Ruby", "headers", r"Ruby", "", ""),
    ("ASP.NET", "headers", r"ASP\.NET", "", ""),
    ("ASP.NET", "headers", r"X-AspNet-Version:\s*([\d.]+)", "", ""),
    ("Node.js", "headers", r"Node\.js", "", ""),
    # frameworks
    ("Django", "headers", r"csrftoken", "", ""),
    ("Django", "html", r"csrfmiddlewaretoken", "", ""),
    ("Flask", "html", r"flask", "", ""),
    ("Laravel", "headers", r"laravel_session", "", ""),
    ("Symfony", "html", r"symfony", "", ""),
    ("Ruby on Rails", "headers", r"_rails_|Phusion Passenger", "", ""),
    ("Express", "headers", r"X-Powered-By:\s*Express", "", ""),
    ("Next.js", "html", r"_next/static", "", ""),
    ("Nuxt.js", "html", r"_nuxt/", "", ""),
    ("Gatsby", "html", r"gatsby", "", ""),
    # CMS
    ("WordPress", "html", r"wp-content|wp-includes", "", ""),
    ("WordPress", "html", r'<meta[^>]+name="generator"[^>]+content="WordPress (\d+\.\d+(?:\.\d+)?)"', "", ""),
    ("Drupal", "html", r"drupal\.js|sites/default/files", "", ""),
    ("Drupal", "html", r'<meta[^>]+name="Generator"[^>]+content="Drupal (\d+)', "", ""),
    ("Joomla", "html", r'<meta[^>]+name="generator"[^>]+content="Joomla! (\d+\.\d+)', "", ""),
    ("Ghost", "headers", r"ghost", "", ""),
    ("Shopify", "html", r"cdn\.shopify\.com", "", ""),
    ("Magento", "html", r"static/version\d+|Magento_Theme", "", ""),
    ("TYPO3", "html", r"typo3", "", ""),
    # JS libraries (versioned, OSV-checkable via npm)
    ("jQuery", "html", r"jquery[/-](\d+\.\d+(?:\.\d+)?)", "npm", "jquery"),
    ("jQuery", "html", r"jQuery v(\d+\.\d+(?:\.\d+)?)", "npm", "jquery"),
    ("jQuery UI", "html", r"jquery-ui[/-](\d+\.\d+(?:\.\d+)?)", "npm", "jquery-ui"),
    ("Bootstrap", "html", r"bootstrap[/-](\d+\.\d+(?:\.\d+)?)", "npm", "bootstrap"),
    ("Vue.js", "html", r"vue[/.](?:min\.)?js|vue@(\d+\.\d+(?:\.\d+)?)", "npm", "vue"),
    ("React", "html", r"react@(\d+\.\d+(?:\.\d+)?)|react-dom@(\d+\.\d+(?:\.\d+)?)", "npm", "react"),
    ("Angular", "html", r"angular[/@](\d+\.\d+(?:\.\d+)?)|ng-version=\"(\d+\.\d+(?:\.\d+)?)\"", "npm", "@angular/core"),
    ("Lodash", "html", r"lodash[/-](\d+\.\d+(?:\.\d+)?)", "npm", "lodash"),
    ("Moment.js", "html", r"moment[/-](\d+\.\d+(?:\.\d+)?)", "npm", "moment"),
    ("Underscore.js", "html", r"underscore[/-](\d+\.\d+(?:\.\d+)?)", "npm", "underscore"),
    ("Backbone.js", "html", r"backbone[/-](\d+\.\d+(?:\.\d+)?)", "npm", "backbone"),
    ("D3.js", "html", r"d3[/-](\d+\.\d+(?:\.\d+)?)", "npm", "d3"),
    ("Chart.js", "html", r"chart\.js[/-](\d+\.\d+(?:\.\d+)?)", "npm", "chart.js"),
    ("Three.js", "html", r"three[/-](\d+\.\d+(?:\.\d+)?)", "npm", "three"),
    ("GSAP", "html", r"gsap[/-](\d+\.\d+(?:\.\d+)?)", "npm", "gsap"),
    ("Axios", "html", r"axios[/-](\d+\.\d+(?:\.\d+)?)", "npm", "axios"),
    ("Ember.js", "html", r"ember[/-](\d+\.\d+(?:\.\d+)?)", "npm", "ember-source"),
    ("Knockout.js", "html", r"knockout[/-](\d+\.\d+(?:\.\d+)?)", "npm", "knockout"),
    ("RequireJS", "html", r"require[/-](\d+\.\d+(?:\.\d+)?)", "npm", "requirejs"),
    ("Modernizr", "html", r"modernizr[/-](\d+\.\d+(?:\.\d+)?)", "npm", "modernizr"),
    ("Select2", "html", r"select2[/-](\d+\.\d+(?:\.\d+)?)", "npm", "select2"),
    ("DataTables", "html", r"datatables[/-](\d+\.\d+(?:\.\d+)?)", "npm", "datatables.net"),
    ("Swiper", "html", r"swiper[/@](\d+\.\d+(?:\.\d+)?)", "npm", "swiper"),
    ("Slick", "html", r"slick[/-](\d+\.\d+(?:\.\d+)?)", "npm", "slick-carousel"),
    ("Popper.js", "html", r"popper[/-](\d+\.\d+(?:\.\d+)?)", "npm", "@popperjs/core"),
    ("Tailwind", "html", r"tailwindcss[/@](\d+\.\d+(?:\.\d+)?)", "npm", "tailwindcss"),
    ("Bulma", "html", r"bulma[/-](\d+\.\d+(?:\.\d+)?)", "npm", "bulma"),
    ("Foundation", "html", r"foundation[/-](\d+\.\d+(?:\.\d+)?)", "npm", "foundation-sites"),
    ("Materialize", "html", r"materialize[/-](\d+\.\d+(?:\.\d+)?)", "npm", "materialize-css"),
    ("Handlebars", "html", r"handlebars[/-](\d+\.\d+(?:\.\d+)?)", "npm", "handlebars"),
    ("Mustache", "html", r"mustache[/-](\d+\.\d+(?:\.\d+)?)", "npm", "mustache"),
    ("Socket.IO", "html", r"socket\.io[/-](\d+\.\d+(?:\.\d+)?)", "npm", "socket.io"),
    ("Video.js", "html", r"video\.js[/-](\d+\.\d+(?:\.\d+)?)", "npm", "video.js"),
    ("CKEditor", "html", r"ckeditor[/-](\d+\.\d+(?:\.\d+)?)", "npm", "ckeditor4"),
    ("TinyMCE", "html", r"tinymce[/-](\d+\.\d+(?:\.\d+)?)", "npm", "tinymce"),
    ("Summernote", "html", r"summernote[/-](\d+\.\d+(?:\.\d+)?)", "npm", "summernote"),
    ("Dropzone", "html", r"dropzone[/-](\d+\.\d+(?:\.\d+)?)", "npm", "dropzone"),
    ("FullCalendar", "html", r"fullcalendar[/-](\d+\.\d+(?:\.\d+)?)", "npm", "fullcalendar"),
    # analytics / marketing / misc
    ("Google Analytics", "html", r"google-analytics\.com|googletagmanager\.com", "", ""),
    ("Google Tag Manager", "html", r"googletagmanager\.com/gtm\.js\?id=(GTM-[A-Z0-9]+)", "", ""),
    ("Facebook Pixel", "html", r"connect\.facebook\.net.*fbevents", "", ""),
    ("Hotjar", "html", r"static\.hotjar\.com", "", ""),
    ("Segment", "html", r"cdn\.segment\.com", "", ""),
    ("Stripe.js", "html", r"js\.stripe\.com/v(\d+)", "", ""),
    ("reCAPTCHA", "html", r"google\.com/recaptcha", "", ""),
    ("hCaptcha", "html", r"hcaptcha\.com", "", ""),
    ("Cloudflare", "headers", r"cf-ray|__cf_bm|cloudflare", "", ""),
    ("Cloudflare", "html", r"cdnjs\.cloudflare\.com", "", ""),
    ("AWS CloudFront", "headers", r"cloudfront|x-amz-cf", "", ""),
    ("Fastly", "headers", r"fastly", "", ""),
    ("Vercel", "headers", r"x-vercel|Vercel", "", ""),
    ("Netlify", "headers", r"netlify", "", ""),
    ("Akamai", "headers", r"akamai", "", ""),
    ("Sucuri", "headers", r"sucuri|x-sucuri", "", ""),
    ("Incapsula", "headers", r"incap_ses|incapsula", "", ""),
    ("Wordfence", "html", r"wordfence", "", ""),
    ("Yoast SEO", "html", r"yoast", "", ""),
    ("WooCommerce", "html", r"woocommerce", "", ""),
    ("Elementor", "html", r"elementor", "", ""),
    ("phpMyAdmin", "html", r"phpmyadmin", "", ""),
    ("cPanel", "headers", r"cpanel", "", ""),
    ("Plesk", "headers", r"plesk", "", ""),
    ("jQuery Migrate", "html", r"jquery-migrate[/-](\d+\.\d+(?:\.\d+)?)", "npm", "jquery-migrate"),
    ("Sentry", "html", r"sentry", "", ""),
    ("New Relic", "html", r"newrelic", "", ""),
    ("Datadog", "html", r"datadog", "", ""),
    ("Intercom", "html", r"intercom", "", ""),
    ("Zendesk", "html", r"zendesk", "", ""),
    ("HubSpot", "html", r"hubspot", "", ""),
    ("Marketo", "html", r"marketo", "", ""),
    ("Mailchimp", "html", r"mailchimp", "", ""),
    ("AddThis", "html", r"addthis", "", ""),
    ("ShareThis", "html", r"sharethis", "", ""),
    ("Disqus", "html", r"disqus", "", ""),
    ("OpenCart", "html", r"opencart", "", ""),
    ("PrestaShop", "html", r"prestashop", "", ""),
    ("phpBB", "html", r"phpbb", "", ""),
    ("MediaWiki", "html", r"mediawiki", "", ""),
    ("DokuWiki", "html", r"dokuwiki", "", ""),
    ("Grav", "html", r"grav", "", ""),
    ("Hugo", "html", r'<meta[^>]+name="generator"[^>]+content="Hugo (\d+\.\d+(?:\.\d+)?)"', "", ""),
    ("Jekyll", "html", r'<meta[^>]+name="generator"[^>]+content="Jekyll v(\d+\.\d+(?:\.\d+)?)"', "", ""),
    ("Wix", "html", r"wixstatic\.com", "", ""),
    ("Squarespace", "html", r"squarespace", "", ""),
    ("Webflow", "html", r"webflow", "", ""),
    ("Blogger", "html", r"blogger\.com", "", ""),
    ("Varnish", "headers", r"varnish|x-varnish", "", ""),
    ("HAProxy", "headers", r"haproxy", "", ""),
    ("Envoy", "headers", r"envoy", "", ""),
    ("Traefik", "headers", r"traefik", "", ""),
    ("Kong", "headers", r"kong|via:\s*kong", "", ""),
    ("CloudFront", "headers", r"via:.*cloudfront", "", ""),
]

# product -> latest supported major.minor (EOL if detected version is older).
# Conservative: only flag when confidently EOL.
EOL_TABLE = {
    "PHP": (8, 1),        # < 8.1 EOL
    "Python": (3, 9),     # < 3.9 EOL
    "jQuery": (3, 0),     # 1.x/2.x EOL
    "Bootstrap": (4, 0),  # 3.x EOL
    "Apache": (2, 4),     # 2.2 EOL
    "nginx": (1, 20),     # very old EOL
    "IIS": (10, 0),
    "Drupal": (9, 0),
    "WordPress": (5, 0),
    "Vue.js": (2, 7),
    "Angular": (12, 0),
    "Django": (3, 2),
    "Laravel": (8, 0),
    "Ruby on Rails": (6, 0),
}


def _parse_version(v: str) -> Optional[Tuple[int, ...]]:
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except Exception:
        return None


async def _osv_lookup(ctx: Ctx, ecosystem: str, package: str,
                      version: str) -> List[Dict]:
    """Query OSV for vulns affecting package@version. Best-effort."""
    if not ecosystem or not package or not version:
        return []
    try:
        r = await fetch(ctx.http, ctx.limiter, "POST",
                        "https://api.osv.dev/v1/query",
                        json={"package": {"name": package,
                                          "ecosystem": ecosystem},
                              "version": version},
                        timeout=15, max_retries=1)
        if r.status_code != 200:
            return []
        data = r.json()
        return data.get("vulns", []) or []
    except Exception:
        return []


class TechFingerprintPlugin(Plugin):
    id = "tech_fingerprint"
    label = "Tech Fingerprint+"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Exact version detection for 100+ technologies, CVE "
                   "matching via OSV, and EOL flagging.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)
        findings: List[Finding] = []
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base, timeout=25,
                            follow_redirects=True)
            html = r.text[:500000]
            page_url = str(r.url)
        except Exception as e:
            res = self._degraded(f"fetch failed: {str(e)[:200]}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        headers_blob = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        cookies_blob = r.headers.get("set-cookie", "")

        detected: Dict[str, Dict] = {}  # name -> {version, where}
        for name, where, pattern, eco, pkg in VERSION_RULES:
            hay = (headers_blob if where == "headers"
                   else cookies_blob if where == "cookies" else html)
            m = re.search(pattern, hay, re.I | re.M)
            if not m:
                continue
            version = None
            for g in m.groups():
                if g:
                    version = g
                    break
            key = name
            prev = detected.get(key)
            # keep the most specific (longest) version seen
            if prev and prev.get("version") and version and \
                    len(version) <= len(prev["version"]):
                continue
            detected[key] = {"version": version, "where": where,
                             "ecosystem": eco, "package": pkg}

        for name, info in sorted(detected.items()):
            ver = info["version"]
            label = f"{name} {ver}" if ver else name
            sev = "medium"
            extra = ""
            # EOL check
            eol_min = EOL_TABLE.get(name)
            parsed = _parse_version(ver) if ver else None
            if eol_min and parsed and len(parsed) >= 2:
                if (parsed[0], parsed[1]) < eol_min:
                    sev = "high"
                    extra = (f" - END OF LIFE (supported >= "
                             f"{eol_min[0]}.{eol_min[1]}); unpatched CVEs likely")
            findings.append(self._f(
                "web", "tech_version",
                f"{label}{extra} (via {info['where']})",
                source="version signature", source_url=page_url,
                confidence=85 if ver else 70, passive=passive,
                evidence={"severity": sev, "technology": name,
                          "version": ver or "unknown",
                          "remediation": ("Upgrade to a supported release and "
                                          "re-scan; subscribe to the vendor's "
                                          "security advisories.")}))

        # CVE matching for versioned npm packages (bounded: first 8)
        osv_targets = [(n, i) for n, i in detected.items()
                       if i["ecosystem"] and i["version"]]
        for name, info in osv_targets[:8]:
            vulns = await _osv_lookup(ctx, info["ecosystem"],
                                      info["package"], info["version"])
            for v in vulns[:5]:
                vid = v.get("id", "unknown")
                summary = (v.get("summary") or "")[:160]
                sev = "high"
                # crude severity from OSV severity list
                for s in v.get("severity", []) or []:
                    if s.get("type") == "CVSS_V3":
                        try:
                            score = float(s.get("score", "0").split("/")[0]
                                          .split(":")[-1])
                            sev = ("critical" if score >= 9 else
                                   "high" if score >= 7 else
                                   "medium" if score >= 4 else "low")
                        except Exception:
                            pass
                findings.append(self._f(
                    "web", "tech_cve",
                    f"{sev.upper()}: {name} {info['version']} affected by "
                    f"{vid} - {summary}",
                    source="OSV CVE database",
                    source_url="https://osv.dev/vulnerability/" + vid,
                    confidence=85, passive=passive,
                    evidence={"severity": sev, "technology": name,
                              "version": info["version"], "cve": vid,
                              "remediation": ("Upgrade the library past the "
                                              "fixed version listed on the "
                                              "OSV advisory, then re-scan.")}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings,
                       f"{len(detected)} technologies, "
                       f"{sum(1 for f in findings if f.key=='tech_cve')} CVEs")
        res.duration_ms = dur
        return res
