"""Extended technology fingerprinting plugin.

Identifies EVERYTHING: frameworks, versions, plugins, themes, server
software, CDNs, analytics, WAFs, and more. Deeper than webtech.py.
"""
from __future__ import annotations

import re
import time
from typing import List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (tech, where, regex, version_regex)
RULES = [
    # Frameworks with versions
    ("WordPress", "html", r"wp-content", r"WordPress\s*([\d.]+)"),
    ("Joomla", "html", r"joomla", r"Joomla!?[\s_]*([\d.]+)"),
    ("Drupal", "html", r"drupal", r"Drupal\s*([\d.]+)"),
    ("Ghost", "html", r"ghost", None),
    ("Strapi", "html", r"strapi", None),
    ("Next.js", "html", r"_next/static", r"_next/static/[^/]*"),
    ("Nuxt.js", "html", r"_nuxt/", None),
    ("Gatsby", "html", r"gatsby", None),
    ("Remix", "html", r"remix", None),
    ("SvelteKit", "html", r"svelte", None),
    ("Astro", "html", r"astro", None),
    # Backend
    ("Django", "headers", r"csrftoken", r"Django"),
    ("Flask", "headers", r"flask", None),
    ("FastAPI", "headers", r"fastapi", None),
    ("Express.js", "headers", r"x-powered-by:\s*express", r"Express"),
    ("Ruby on Rails", "html", r"rails", r"Rails\s*([\d.]+)"),
    ("Laravel", "html", r"laravel", r"Laravel\s*v?([\d.]+)"),
    ("Symfony", "html", r"symfony", None),
    ("Spring Boot", "headers", r"spring", None),
    ("ASP.NET Core", "headers", r"aspnet", r"ASP.NET Core"),
    ("PHP", "headers", r"x-powered-by:\s*php", r"PHP/([\d.]+)"),
    # Servers
    ("Nginx", "headers", r"server:\s*nginx", r"nginx/([\d.]+)"),
    ("Apache", "headers", r"server:\s*apache", r"Apache/([\d.]+)"),
    ("IIS", "headers", r"server:.*iis", r"IIS/([\d.]+)"),
    ("Caddy", "headers", r"server:\s*caddy", None),
    ("LiteSpeed", "headers", r"litespeed", r"LiteSpeed"),
    ("OpenResty", "headers", r"openresty", None),
    # CDN / WAF
    ("Cloudflare", "headers", r"cf-ray|__cf_bm", None),
    ("AWS CloudFront", "headers", r"x-amz-cf-id", None),
    ("Fastly", "headers", r"fastly", None),
    ("Akamai", "headers", r"akamai", None),
    ("Sucuri", "headers", r"sucuri", None),
    ("Imperva", "headers", r"imperva|incapsula", None),
    ("Cloudflare WAF", "headers", r"cf-mitigated", None),
    # Analytics / tracking
    ("Google Analytics 4", "html", r"gtag.*G-[A-Z0-9]+", None),
    ("Hotjar", "html", r"hotjar", None),
    ("Mixpanel", "html", r"mixpanel", None),
    ("Segment", "html", r"segment", None),
    ("Intercom", "html", r"intercom", None),
    # E-commerce
    ("Shopify", "html", r"cdn.shopify.com", None),
    ("WooCommerce", "html", r"woocommerce", r"WooCommerce\s*([\d.]+)"),
    ("Magento", "html", r"magento", r"Magento\s*([\d.]+)"),
    ("BigCommerce", "html", r"bigcommerce", None),
    # CMS plugins/themes (WordPress)
    ("Elementor", "html", r"elementor", None),
    ("WooCommerce", "html", r"woocommerce", None),
    ("Yoast SEO", "html", r"yoast", None),
    ("Contact Form 7", "html", r"contact-form-7", None),
    ("WP Rocket", "html", r"wp-rocket", None),
]


class FingerprintPlugin(Plugin):
    id = "fingerprint"
    label = "Deep Tech Fingerprinter"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = "Identify every framework, version, plugin, server, CDN."

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")
        findings: List[Finding] = []
        try:
            resp = await fetch(ctx.http, ctx.limiter, "GET", base + "/")
        except Exception as e:
            return self._degraded(f"fetch failed: {e}")
        if not resp or resp.status_code != 200:
            return self._skipped(f"HTTP {resp.status_code if resp else 'no response'}")
        html = resp.text[:500000]
        headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        found = set()
        for tech, where, pattern, ver_pattern in RULES:
            haystack = html if where == "html" else headers_str
            if re.search(pattern, haystack, re.I):
                version = ""
                if ver_pattern:
                    vm = re.search(ver_pattern, haystack, re.I)
                    if vm and vm.groups():
                        version = f" {vm.group(1)}"
                key = f"{tech}{version}"
                if key not in found:
                    found.add(key)
                    findings.append(self._f(
                        "web", "tech_deep", key,
                        f"fingerprint: {tech}{version} detected",
                        confidence=85,
                        evidence={"severity": "info", "why": f"{tech} identified via {where} signature"}))
                    ctx.publish("tech", key)
        # Cookie analysis
        cookies = resp.headers.get("set-cookie", "")
        if cookies:
            for c in ["sessionid", "phpsessid", "jsessionid", "aspsessionid", "_session"]:
                if c.lower() in cookies.lower():
                    findings.append(self._f("web", "session_cookie", c,
                                            "fingerprint: session cookie reveals stack",
                                            confidence=70))
        findings.append(self._f("web", "fingerprint_summary",
                                f"{len(found)} technologies identified",
                                "fingerprint", confidence=90))
        return self._ok(findings, f"identified {len(found)} technologies")
