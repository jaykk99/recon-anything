"""API / backend discovery plugin (Milestone 4).

Infers backend from headers/error pages, discovers docs (swagger,
openapi, graphql), runs GraphQL introspection, enumerates REST versions
and common paths, builds an HTTP method matrix, detects auth schemes,
decodes JWTs, checks CORS reflection, and assembles a live API map.
"""
from __future__ import annotations

import base64
import json
import re
import time
from typing import Dict, List
from urllib.parse import urljoin

from ..classifier import classify, domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

DOC_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
    "/api-docs", "/api/docs", "/docs", "/redoc", "/graphql",
    "/.well-known/openapi.json", "/v3/api-docs", "/swagger-ui.html",
    "/api/swagger.json", "/api/openapi.json", "/api/v1/swagger.json",
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
        base = f"https://{domain}" if target.type == "domain" else target.normalized.rstrip("/")

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

        # --- docs discovery ---
        for path in DOC_PATHS:
            url = base + path
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=12)
            except Exception:
                continue
            ctype = r.headers.get("content-type", "")
            if r.status_code == 200 and ("json" in ctype or "graphql" in path.lower()
                                         or r.text.lstrip().startswith(("{", "["))):
                findings.append(self._f("api", "api_docs", f"{path} looks like API docs",
                                        source="docs discovery", source_url=url,
                                        confidence=85, passive=passive))
                self._parse_openapi(r.text, url, findings, api_map, passive)
            elif "graphql" in path and r.status_code in (200, 400, 405):
                findings.append(self._f("api", "graphql_endpoint",
                                        f"{path} responds (status {r.status_code})",
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

        # --- REST version + wordlist probing (active-leaning; light in passive) ---
        probe_paths = [f"/api/{w}" for w in API_WORDLIST[:30]] if passive \
            else [f"/api/{w}" for w in API_WORDLIST] + [f"/v1/{w}" for w in API_WORDLIST[:20]]
        for path in probe_paths:
            url = base + path
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=10)
            except Exception:
                continue
            if r.status_code in (200, 201, 301, 302, 401, 403, 405):
                note = f"{path} -> {r.status_code}"
                auth = self._detect_auth(r)
                if auth:
                    note += f" [{auth}]"
                findings.append(self._f("api", "endpoint", note,
                                        source="path probe", source_url=url,
                                        confidence=70 if r.status_code < 400 else 55,
                                        passive=passive))
                api_map[path] = {"methods": ["GET"], "status": r.status_code,
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

    def _detect_auth(self, r) -> str | None:
        www = r.headers.get("www-authenticate", "").lower()
        if "bearer" in www:
            return "bearer"
        if "basic" in www:
            return "basic"
        sc = r.headers.get("set-cookie", "").lower()
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
