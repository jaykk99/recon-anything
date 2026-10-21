"""API / backend discovery plugin (Milestone 4).

Infers backend from headers/error pages, discovers docs (swagger,
openapi, graphql), runs GraphQL introspection, enumerates REST versions
and common paths, builds an HTTP method matrix, detects auth schemes,
decodes JWTs, checks CORS reflection, and assembles a live API map.
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from typing import Dict, List

from ..classifier import domain_from_target
from ..ratelimit import fetch
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

DOC_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/api-docs", "/api/docs", "/docs", "/redoc", "/graphql",
    "/.well-known/openapi.json", "/v3/api-docs", "/v2/api-docs",
    "/swagger-ui.html", "/swagger-ui/", "/swagger/index.html",
    "/api/swagger.json", "/api/openapi.json", "/api/v1/swagger.json",
    "/api/v2/swagger.json", "/api/openapi.yaml", "/api/docs/swagger.json",
    "/api/schema/", "/schema/", "/api/schema/swagger-ui/",
    "/graphiql", "/playground", "/altair", "/voyager",
    "/api/graphql", "/v1/graphql", "/query", "/api/query",
    "/api/redoc", "/redoc/", "/api/redoc/",
    "/api/openapi", "/openapi", "/api/v3/api-docs",
    "/api/documentation", "/documentation", "/api/spec.json",
    # Backend framework defaults (deep API dive, Jay 2026-10-18)
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/actuator/beans", "/actuator/configprops", "/actuator/info",
    "/metrics", "/prometheus", "/healthz", "/readyz", "/livez", "/health",
    "/api/health", "/api/v1/health", "/api/v2/health", "/api/status",
    "/wp-json/", "/wp-json/wp/v2/", "/wp-json/wp/v2/users",
    "/xmlrpc.php", "/wp-cron.php",
    "/api/v3/", "/api/v4/", "/api/internal/", "/api/private/",
    "/api/admin/", "/api/public/", "/internal/", "/private/",
    "/rest/", "/api/rest/", "/gql/", "/graphql/console",
    "/server-status", "/server-info", "/phpinfo.php", "/info.php",
    "/.well-known/", "/.well-known/security.txt",
    "/debug/", "/_debug/", "/console/", "/telescope/", "/horizon/",
    "/jmx-console/", "/web-console/", "/manager/html", "/manager/status",
]

API_WORDLIST = """users user me profile account accounts login logout register
signup signin auth token tokens refresh session sessions
health status metrics ping version info config settings
search query filter list create update delete
admin dashboard internal private public
files file upload uploads download media images
orders order cart checkout payment payments billing invoice invoices
products product items inventory stock
posts post comments comment messages message notifications
teams team org organization organizations members roles permissions
keys apikey webhooks webhook events logs audit
graphql api v1 v2 v3 rest
customers customer leads lead contacts vendors suppliers
employees employee payroll hr benefits
tickets ticket incidents incident alerts alert
reports report analytics stats dashboard
devices device sensors sensor gateways gateway
subscriptions subscription plans plan pricing
coupons coupon discounts discount promos promo
reviews review ratings rating feedback
categories category tags tag collections
articles article pages page menus menu
widgets widget plugins plugin themes theme
backups backup exports export imports import
migrations migration seeds seed jobs job
queues queue workers worker tasks task
caches cache sessions tokens invites invite
domains domain dns ssl certificates certificate
billing invoices payments refunds refund
shipping shipments tracking track
wishlist wishlists carts baskets
addresses address phones phone
avatars avatar profiles settings preferences
oauth saml sso ldap scim
webhooks callbacks callback integrations integration
exports imports migrations seeds
debug status healthz readyz livez
actuator prometheus metrics
.env config configuration environment
""".split()

ERROR_FINGERPRINTS = [
    ("Django", r"django|DisallowedHost|DEBUG = True", 85),
    ("Laravel", r"laravel|Whoops, looks like something went wrong", 85),
    ("Rails", r"rails|ActionController::", 85),
    ("Express", r"Cannot GET|at Layer\.handle", 80),
    ("Next.js", r"Application error: a client-side exception|_next/static", 80),
    ("ASP.NET", r"Server Error in '/' Application|asp.net", 85),
    ("Spring", r"Whitelabel Error Page|There was an unexpected error", 80),
    ("PHP", r"Fatal error|Warning:.*\.php", 80),
]


def _b64url_decode(s: str) -> dict:
    padded = s + "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


class ApiDiscoverPlugin(Plugin):
    id = "apidiscover"
    label = "API Discovery"
    accepts = ["domain", "url", "jwt"]
    passive = True
    cost = Cost.FREE
    group = "api"
    description = "Backend inference, docs discovery, GraphQL introspection, API map."
    # Enumerator-class plugin: up to 180 wordlist probes paced by the
    # shared per-host rate limiter (~10 rps) puts its floor near 30s
    # even before network latency; the 60s base default got it killed
    # mid-run on slow targets and the timeout discarded ALL findings.
    timeout_s = 120

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List[Finding] = []
        api_map: Dict[str, Dict] = {}
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        # --- JWT target: decode and audit ---
        if target.type == "jwt":
            findings.extend(self._audit_jwt(target.normalized))
            res = self._ok(findings, "JWT decoded and audited")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = (await web_base(ctx, target, domain)).rstrip("/")

        # --- backend inference from a 404 page ---
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET",
                            base + "/recon-anything-404-probe-xyz", timeout=15)
            body = r.text[:5000]
            for name, pat, conf in ERROR_FINGERPRINTS:
                if re.search(pat, body, re.I):
                    findings.append(self._f("api", "backend_hint",
                                            f"{name} (from error page fingerprint)",
                                            source="404 probe", confidence=conf,
                                            passive=passive))
                    break
            srv = r.headers.get("server", "")
            if srv:
                findings.append(self._f("api", "server_header", srv[:200],
                                        source="HTTP headers", confidence=90,
                                        passive=passive))
        except Exception:
            pass

        # --- docs discovery (concurrent: 14 sequential x 12s timeouts
        # become one paced window; same checks, same findings) ---
        sem = asyncio.Semaphore(8)

        async def check_doc(path: str):
            url = base + path
            async with sem:
                # Shared probe cache: backup.py / artifacts.py /
                # hiddenpaths.py probing the same URL reuse this response.
                probed = await ctx.probe(url, timeout=12)
            ctype = probed["headers"].get("content-type", "")
            head = probed["text"]
            if probed["status"] == 200 and ("json" in ctype or "graphql" in path.lower()
                                            or head.lstrip().startswith(("{", "["))):
                # Docs found: fetch the full body for OpenAPI parsing
                # (the probe cache only keeps a 4k head).
                try:
                    r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=12)
                    body = r.text
                except Exception:
                    body = head
                return ("docs", path, url, body)
            elif "graphql" in path and probed["status"] in (200, 400, 405):
                return ("gql", path, url, probed["status"])
            return None

        for item in await asyncio.gather(*[check_doc(p) for p in DOC_PATHS]):
            if not item:
                continue
            kind, path, url, payload = item
            if kind == "docs":
                findings.append(self._f("api", "api_docs", f"{path} looks like API docs",
                                        source="docs discovery", source_url=url,
                                        confidence=85, passive=passive))
                self._parse_openapi(payload, url, findings, api_map, passive)
            else:
                findings.append(self._f("api", "graphql_endpoint",
                                        f"{path} responds (status {payload})",
                                        source="docs discovery", source_url=url,
                                        confidence=70, passive=passive))

        # --- GraphQL introspection ---
        gql_url = base + "/graphql"
        introspected = await self._graphql_introspect(ctx, gql_url, findings,
                                                      api_map, passive)
        if not introspected:
            # try /api/graphql too
            await self._graphql_introspect(ctx, base + "/api/graphql", findings,
                                           api_map, passive)

        # --- JS endpoint extraction: parse homepage + JS for fetch/axios calls ---
        try:
            home_page = await ctx.fetch_page(base, timeout=20)
            if home_page:
                js_text = home_page["text"][:500000]
                # Find fetch() and axios calls with URL strings
                fetch_urls = re.findall(r"""fetch\s*\(\s*['"`]([^'"`]{3,200})['"`]""", js_text)
                axios_urls = re.findall(r"""axios\.(?:get|post|put|patch|delete|request)\s*\(\s*['"`]([^'"`]{3,200})['"`]""", js_text)
                xhr_urls = re.findall(r"""\.open\s*\(\s*['"`](?:GET|POST|PUT|PATCH|DELETE)['"`]\s*,\s*['"`]([^'"`]{3,200})['"`]""", js_text)
                # NEW: more patterns - $.ajax, $.get, $.post, superagent, ky, got
                jquery_urls = re.findall(r"""\$\.(?:ajax|get|post|getJSON)\s*\(\s*(?:\{[^}]{0,300}?url\s*:\s*)?['"`]([^'"`]{3,200})['"`]""", js_text)
                url_assign = re.findall(r"""(?:apiUrl|api_url|baseUrl|baseURL|endpoint|apiEndpoint)\s*[:=]\s*['"`]([^'"`]{3,200})['"`]""", js_text)
                # NEW: template literals with /api/ paths
                template_urls = re.findall(r"""`([^`]{0,200}?/(?:api|v\d|rest|graphql)[^`]{0,150})`""", js_text)
                # NEW: WebSocket URLs
                ws_urls = re.findall(r"""new\s+WebSocket\s*\(\s*['"`]([^'"`]{3,200})['"`]""", js_text)
                for ep_url in set(fetch_urls + axios_urls + xhr_urls + jquery_urls +
                                   url_assign + template_urls + ws_urls):
                    if ep_url.startswith(("http", "//")):
                        continue  # skip absolute URLs to other domains
                    if not ep_url.startswith("/"):
                        continue
                    if len(ep_url) > 200:
                        continue
                    findings.append(self._f("api", "endpoint_js",
                                            f"JS-referenced endpoint: {ep_url}",
                                            source="JS fetch/axios parsing",
                                            confidence=75, passive=passive))
                    api_map[ep_url] = {"methods": ["GET"], "status": "js-referenced",
                                       "auth": "unknown"}
                    ctx.publish("endpoints", base + ep_url)
        except Exception:
            pass

        # --- REST version + wordlist probing (concurrent; same probes) ---
        # Aggressive: check /api/, /v1/, /v2/, /v3/, /v4/, /rest/ prefixes even in passive
        probe_paths = []
        prefixes = ["/api", "/v1", "/v2", "/v3", "/v4", "/rest",
                    "/api/v1", "/api/v2", "/api/v3"] if passive else \
                   ["/api", "/v1", "/v2", "/v3", "/v4", "/rest",
                    "/api/v1", "/api/v2", "/api/v3", "/internal",
                    "/private"]
        words = API_WORDLIST[:30] if passive else API_WORDLIST
        for prefix in prefixes:
            for w in words:
                probe_paths.append(f"{prefix}/{w}")
                if len(probe_paths) >= 180:  # cap total probes
                    break
            if len(probe_paths) >= 180:
                break

        async def probe_path(path: str):
            url = base + path
            async with sem:
                # Shared probe cache: same URL probed by the sweep plugins
                # is fetched once per run.
                probed = await ctx.probe(url, timeout=10)
            status = probed["status"]
            if status in (200, 201, 301, 302, 401, 403, 405):
                note = f"{path} -> {status}"
                auth = self._detect_auth(probed["headers"])
                if auth:
                    note += f" [{auth}]"
                return (path, url, status, auth, note)
            return None

        for item in await asyncio.gather(*[probe_path(p) for p in probe_paths]):
            if not item:
                continue
            path, url, status, auth, note = item
            findings.append(self._f("api", "endpoint", note,
                                    source="path probe", source_url=url,
                                    confidence=70 if status < 400 else 55,
                                    passive=passive))
            api_map[path] = {"methods": ["GET"], "status": status,
                             "auth": auth or "unknown"}

        # --- method matrix on /api ---
        try:
            r = await fetch(ctx.http, ctx.limiter, "OPTIONS", base + "/api", timeout=12)
            allow = r.headers.get("allow", "")
            if allow:
                findings.append(self._f("api", "options_allow", allow[:200],
                                        source="OPTIONS /api", confidence=90, passive=passive))
        except Exception:
            pass

        # --- CORS reflection check ---
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", base,
                            headers={"Origin": "https://evil.example"},
                            timeout=12)
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "")
            if acao == "https://evil.example":
                sev = "CORS reflects arbitrary Origin"
                if acac.lower() == "true":
                    sev += " WITH credentials (high)"
                findings.append(self._f("leak", "cors_misconfig", sev,
                                        source="CORS probe", confidence=90, passive=passive))
            elif acao == "*":
                findings.append(self._f("api", "cors_wildcard",
                                        "CORS allows any origin (*)",
                                        source="CORS probe", confidence=75, passive=passive))
        except Exception:
            pass

        # --- API map summary finding ---
        if api_map:
            findings.append(self._f("api", "api_map_entries", str(len(api_map)),
                                    source="assembled", confidence=80, passive=passive,
                                    raw={"map": api_map}))

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"API discovery on {domain}: {len(api_map)} map entries")
        res.duration_ms = dur
        return res

    def _detect_auth(self, headers) -> str | None:
        www = headers.get("www-authenticate", "").lower()
        if "bearer" in www:
            return "bearer"
        if "basic" in www:
            return "basic"
        sc = headers.get("set-cookie", "").lower()
        if "session" in sc or "token" in sc:
            return "cookie"
        return None

    def _parse_openapi(self, text: str, url: str, findings: List[Finding],
                       api_map: Dict, passive: bool):
        try:
            doc = json.loads(text[:2000000])
        except Exception:
            return
        paths = doc.get("paths", {})
        for p, ops in list(paths.items())[:100]:
            if not isinstance(ops, dict):
                continue
            methods = [m.upper() for m in ops if m.lower() in
                       ("get", "post", "put", "patch", "delete", "options", "head")]
            api_map[p] = {"methods": methods, "status": "documented", "auth": "see docs"}
        if paths:
            findings.append(self._f("api", "openapi_paths",
                                    f"{len(paths)} paths documented",
                                    source="OpenAPI doc", source_url=url,
                                    confidence=95, passive=passive))

    async def _graphql_introspect(self, ctx, url, findings, api_map, passive) -> bool:
        q = {"query": "{__schema{queryType{name}mutationType{name}}}"}
        try:
            r = await fetch(ctx.http, ctx.limiter, "POST", url, json=q, timeout=15)
        except Exception:
            return False
        try:
            data = r.json()
        except Exception:
            return False
        schema = (data.get("data") or {}).get("__schema")
        if not schema:
            return False
        findings.append(self._f("api", "graphql_introspection",
                                "introspection ENABLED (schema readable)",
                                source="GraphQL introspection", source_url=url,
                                confidence=95, passive=passive))
        # full schema dump
        q2 = {"query": """{__schema{types{name kind fields{name type{name kind ofType{name kind}}}}}}}"""}
        try:
            r2 = await fetch(ctx.http, ctx.limiter, "POST", url, json=q2, timeout=20)
            d2 = r2.json()
            types = ((d2.get("data") or {}).get("__schema") or {}).get("types", [])
            names = [t.get("name") for t in types
                     if t.get("name") and not t["name"].startswith("__")][:80]
            findings.append(self._f("api", "graphql_types",
                                    ", ".join(names)[:600],
                                    source="GraphQL introspection", source_url=url,
                                    confidence=90, passive=passive,
                                    raw={"types": names}))
            qn = (schema.get("queryType") or {}).get("name")
            if qn:
                api_map["/graphql"] = {"methods": ["POST"], "status": "introspection-open",
                                       "auth": "unknown"}
        except Exception:
            pass
        return True

    def _audit_jwt(self, token: str) -> List[Finding]:
        out: List[Finding] = []
        parts = token.split(".")
        try:
            header = _b64url_decode(parts[0])
            payload = _b64url_decode(parts[1])
        except Exception as e:
            return [self._f("api", "jwt_error", f"cannot decode: {e}",
                            source="JWT", confidence=90)]
        out.append(self._f("api", "jwt_header", json.dumps(header)[:300],
                           source="JWT decode", confidence=95))
        interesting = {k: payload.get(k) for k in ("sub", "iss", "aud", "exp", "iat", "role", "scope") if k in payload}
        out.append(self._f("api", "jwt_claims", json.dumps(interesting, default=str)[:400],
                           source="JWT decode", confidence=95))
        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            out.append(self._f("leak", "jwt_weak", "alg=none accepted in header",
                               source="JWT audit", confidence=99))
        if alg in ("hs256",) and len(str(header.get("k", ""))) == 0:
            pass
        if "exp" not in payload:
            out.append(self._f("leak", "jwt_weak", "no exp claim (never expires)",
                               source="JWT audit", confidence=85))
        return out
