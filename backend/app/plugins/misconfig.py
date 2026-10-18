"""Framework exposure / misconfiguration detection plugin.

Non-destructive checks for common framework dev-mode exposures:
Django debug mode, Laravel .env, Rails indicators, Spring Boot actuator
endpoints, PHP phpinfo pages, and Apache server-status. GET/HEAD only.
"""
from __future__ import annotations

import time
from typing import Dict, List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target


class MisconfigPlugin(Plugin):
    id = "misconfig"
    label = "Framework Misconfig Detector"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Detects framework dev-mode exposures: Django debug, "
                   "Laravel .env, Rails keys, Spring Boot actuator, "
                   "phpinfo, Apache server-status.")
    phase = 1

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")

        findings: List[Finding] = []

        async def get(path: str):
            url = base + path
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10,
                                max_retries=1, follow_redirects=True)
                return r, url
            except Exception:
                return None, url

        def body(r) -> str:
            try:
                return r.text[:20000]
            except Exception:
                return ""

        def headers(r) -> Dict[str, str]:
            try:
                return {k.lower(): v for k, v in r.headers.items()}
            except Exception:
                return {}

        # --- 1. Homepage: dev-mode indicators in body/headers -----------------
        r, url = await get("/")
        if r is not None:
            txt = body(r)
            h = headers(r)
            low = txt.lower()

            # Django debug toolbar / debug traceback
            if "djdt" in low or "django-debug-toolbar" in low or "debug-toolbar" in low:
                findings.append(self._f(
                    "web", "django_debug",
                    "Django DEBUG mode enabled: debug toolbar HTML present on the homepage",
                    source="Framework misconfig detector", source_url=url,
                    confidence=90, passive=True,
                    evidence={"severity": "high", "exploitability": "public_poc",
                              "remediation": "Set DEBUG=False in the Django settings "
                              "for production, remove the debug toolbar from "
                              "INSTALLED_APPS/MIDDLEWARE, and re-scan to verify."}))
            if "traceback" in low and ("django" in low or "was raised" in low):
                findings.append(self._f(
                    "web", "django_traceback",
                    "Django debug traceback page exposed (full stack traces and "
                    "settings visible to visitors)",
                    source="Framework misconfig detector", source_url=url,
                    confidence=80, passive=True,
                    evidence={"severity": "high", "exploitability": "public_poc",
                              "remediation": "Set DEBUG=False and define "
                              "ALLOWED_HOSTS in Django settings; never serve "
                              "traceback pages publicly."}))
            # Laravel .env leaked inline (some misconfigs dump it in errors)
            if "app_key=base64:" in txt or ("db_password=" in txt and "laravel" in low):
                findings.append(self._f(
                    "web", "laravel_env_inline",
                    "Laravel environment values (APP_KEY / DB credentials) visible "
                    "in a served page",
                    source="Framework misconfig detector", source_url=url,
                    confidence=85, passive=True,
                    evidence={"severity": "high", "exploitability": "weaponized",
                              "remediation": "Rotate every credential in the leaked "
                              ".env immediately (APP_KEY, DB, mail, API keys), "
                              "block .env from the web root, and re-scan."}))
            # Rails secret_key_base exposure (rare but critical)
            if "secret_key_base" in txt:
                findings.append(self._f(
                    "web", "rails_secret",
                    "Rails secret_key_base value appears in served content - "
                    "session forgery possible",
                    source="Framework misconfig detector", source_url=url,
                    confidence=85, passive=True,
                    evidence={"severity": "high", "exploitability": "weaponized",
                              "remediation": "Rotate secret_key_base and all "
                              "encrypted credentials, purge the exposed value "
                              "from served content, and re-scan."}))
            # PHP phpinfo linked inline
            if "phpinfo()" in txt and "php version" in low:
                findings.append(self._f(
                    "web", "phpinfo_inline",
                    "phpinfo() output embedded in a served page (exposes PHP "
                    "version, modules, paths)",
                    source="Framework misconfig detector", source_url=url,
                    confidence=80, passive=True,
                    evidence={"severity": "medium", "exploitability": "theoretical",
                              "remediation": "Remove the phpinfo() page from "
                              "production; keep it only on locked-down dev hosts."}))
            # Dev-mode server headers
            powered = h.get("x-powered-by", "")
            if "php/" in powered.lower():
                findings.append(self._f(
                    "web", "php_version_header",
                    f"PHP version disclosed in X-Powered-By header: {powered}",
                    source="Framework misconfig detector", source_url=url,
                    confidence=90, passive=True,
                    evidence={"severity": "low", "exploitability": "theoretical",
                              "remediation": "Set expose_php=Off in php.ini so "
                              "version headers are not sent."}))
            server = h.get("server", "")
            if "apache/" in server.lower() and any(c.isdigit() for c in server):
                findings.append(self._f(
                    "web", "apache_version_header",
                    f"Apache version disclosed in Server header: {server}",
                    source="Framework misconfig detector", source_url=url,
                    confidence=85, passive=True,
                    evidence={"severity": "low", "exploitability": "theoretical",
                              "remediation": "Set ServerTokens Prod and "
                              "ServerSignature Off in the Apache config."}))

        # --- 2. Laravel .env direct ------------------------------------------
        r, url = await get("/.env")
        if r is not None and r.status_code == 200:
            txt = body(r)
            if "APP_KEY" in txt or "DB_PASSWORD" in txt or "APP_NAME" in txt:
                findings.append(self._f(
                    "leak", "laravel_env",
                    "Laravel .env file publicly downloadable - contains APP_KEY, "
                    "database and mail credentials",
                    source="Framework misconfig detector", source_url=url,
                    confidence=95, passive=True,
                    evidence={"severity": "high", "exploitability": "weaponized",
                              "remediation": "Block .env from the web root "
                              "immediately, rotate ALL credentials in it, and "
                              "check access logs for prior downloads."}))

        # --- 3. Spring Boot actuator ------------------------------------------
        for path in ("/actuator/env", "/actuator/health", "/actuator"):
            r, url = await get(path)
            if r is None or r.status_code != 200:
                continue
            txt = body(r)
            low = txt.lower()
            ctype = r.headers.get("content-type", "").lower()
            if "json" in ctype or txt.strip().startswith("{"):
                kind = "env" if path.endswith("/env") else ("health" if path.endswith("/health") else "index")
                sev = "high" if kind == "env" else "medium"
                findings.append(self._f(
                    "web", f"spring_actuator_{kind}",
                    f"Spring Boot actuator endpoint exposed: {path} returns 200 "
                    f"JSON (kind={kind})",
                    source="Framework misconfig detector", source_url=url,
                    confidence=90, passive=True,
                    evidence={"severity": sev, "exploitability": "public_poc",
                              "remediation": "Restrict actuator endpoints to "
                              "localhost/management port via "
                              "management.endpoints.web.exposure.include, and "
                              "require auth on /actuator/* in production."}))

        # --- 4. phpinfo page ---------------------------------------------------
        for path in ("/phpinfo.php", "/info.php", "/phpinfo"):
            r, url = await get(path)
            if r is None or r.status_code != 200:
                continue
            low = body(r).lower()
            if "php version" in low and "phpinfo" in low:
                findings.append(self._f(
                    "web", "phpinfo_page",
                    f"phpinfo() page publicly accessible at {path} (full PHP "
                    "config disclosure)",
                    source="Framework misconfig detector", source_url=url,
                    confidence=92, passive=True,
                    evidence={"severity": "medium", "exploitability": "theoretical",
                              "remediation": "Delete the phpinfo page from the "
                              "production web root; restrict to local dev only."}))
                break

        # --- 5. Apache server-status ------------------------------------------
        r, url = await get("/server-status")
        if r is not None and r.status_code == 200:
            low = body(r).lower()
            if "apache status" in low or "server version" in low:
                findings.append(self._f(
                    "web", "apache_server_status",
                    "Apache /server-status page publicly accessible (exposes "
                    "requests, workers, uptime)",
                    source="Framework misconfig detector", source_url=url,
                    confidence=90, passive=True,
                    evidence={"severity": "medium", "exploitability": "theoretical",
                              "remediation": "Restrict <Location /server-status> "
                              "to Require ip of trusted hosts, or disable "
                              "mod_status in production."}))

        if not findings:
            findings.append(self._f(
                "web", "framework_exposure_clean",
                "No framework dev-mode exposures found (Django debug, Laravel "
                ".env, Rails secrets, Spring actuator, phpinfo, server-status)",
                source="Framework misconfig detector", source_url=base,
                confidence=70, passive=True,
                evidence={"severity": "low", "exploitability": "unknown",
                          "remediation": "No action needed. Keep dev endpoints "
                          "blocked in production."}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"checked {len(findings)} framework exposure probes")
        res.duration_ms = dur
        return res
