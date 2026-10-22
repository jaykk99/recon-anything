"""Deterministic fixture site for plugin audits.

A rich fake website (vulnerable on purpose: weak HSTS, insecure cookie,
exposed .git/.env, permissive CORS, secrets in JS, a sourcemap, an
OpenAPI spec, GraphQL, phpinfo, backups) served through an httpx
MockTransport, so plugins run their REAL code paths - the real
``app.plugins.base.Ctx`` (fetch_page/probe/cache/singleflight), the
real rate limiter - with zero network and zero flakiness.

Used by:
  - tests/test_plugin_fixtures.py  (permanent health gate)
  - scripts/plugin_audit.py        (one-off full catalog runs)

The fixture values are obvious fakes on the reserved fixture.test
domain (a realistic-shaped dummy AWS key AKIA1234567890ABCDEF - NOT
AWS's documented "EXAMPLE" key, which several plugins deliberately
skip as a placeholder - plus FixturePass123!).
"""
from __future__ import annotations

import json
import os
import sys

import httpx

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HOST = "fixture.test"
BASE = f"https://{HOST}"

HOME_HTML = """<!DOCTYPE html>
<html><head>
<title>Fixture Corp - Sign In</title>
<meta name="generator" content="WordPress 6.4.2">
<link rel="manifest" href="/manifest.json">
<!-- TODO: remove before launch - db password = FixturePass123! staging: db01.internal -->
<script src="/static/app.js"></script>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-FIXTURE123"></script>
</head><body>
<h1>Fixture Corp</h1>
<img src="http://fixture.test/static/logo.png" alt="logo">
<iframe src="/embed"></iframe>
<form action="/login" method="post">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="hidden" name="csrf" value="abc123">
  <input type="submit" value="Sign in">
</form>
<form action="/search" method="get"><input type="text" name="q"></form>
<a href="/login">Login</a>
<a href="/admin/">Admin</a>
<a href="/api/v1/users">Users API</a>
<a href="/about">About</a>
<script>fetch("/api/v1/users?limit=10"); const API="https://api.fixture.test/v2";</script>
</body></html>"""

APP_JS = """
fetch('/api/v1/users');
fetch('/api/v1/orders');
const metrics = '/api/internal/metrics';
const AWS_KEY = "AKIA1234567890ABCDEF";
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkZpeHR1cmUifQ.dozjgNryP4J3jVmNHl0w5N_XgL0n3AAA";
// TODO remove before prod: password = "FixturePass123!"
//# sourceMappingURL=app.js.map
"""

APP_JS_MAP = json.dumps({
    "version": 3,
    "file": "app.js",
    "sources": ["webpack:///src/admin.js", "webpack:///src/config.js"],
    "sourcesContent": [
        "const INTERNAL='https://internal.fixture.test/admin';",
        "export const key='AKIA1234567890ABCDEF'; // fixture secret",
    ],
    "mappings": "",
})

OPENAPI = json.dumps({
    "openapi": "3.0.0",
    "info": {"title": "Fixture API", "version": "1.0.0"},
    "paths": {
        "/users": {"get": {"summary": "list users"}},
        "/login": {"post": {"summary": "sign in"}},
        "/admin": {"get": {"summary": "admin panel"}},
    },
})

GRAPHQL_SCHEMA = json.dumps({"data": {"__schema": {
    "queryType": {"name": "Query"},
    "types": [{"name": "Query", "fields": [
        {"name": "user"}, {"name": "users"}, {"name": "adminStats"}]}],
}}})

USERS_JSON = json.dumps([
    {"id": 1, "name": "Fixture Admin", "email": "admin@fixture.test",
     "role": "admin"},
    {"id": 2, "name": "Fixture User", "email": "user@fixture.test",
     "role": "user"},
])

CRT_JSON = json.dumps([
    {"name_value": "www.fixture.test\napi.fixture.test",
     "issuer_name": "Fixture CA", "common_name": "fixture.test"},
    {"name_value": "mail.fixture.test",
     "issuer_name": "Fixture CA", "common_name": "mail.fixture.test"},
])

NOT_FOUND = ("<html><head><title>404 Not Found</title></head><body>"
             "<h1>Not Found</h1><p>The requested URL was not found.</p>"
             "<address>Apache/2.4.49 (Unix) Server at fixture.test "
             "Port 443</address></body></html>")

# path -> (status, content_type, body, extra_headers)
ROUTES = {
    "/": (200, "text/html", HOME_HTML, {}),
    "/index.html": (200, "text/html", HOME_HTML, {}),
    "/login": (200, "text/html", HOME_HTML, {}),
    "/about": (200, "text/html",
               "<html><title>About</title>Fixture Corp. "
               "Contact us: admin@fixture.test</html>", {}),
    "/embed": (200, "text/html", "<html><body>embed</body></html>", {}),
    "/search": (200, "text/html", "<html><title>Search</title>results</html>", {}),
    "/admin/": (200, "text/html",
                "<html><title>Admin Dashboard</title>Admin Dashboard</html>", {}),
    "/admin": (200, "text/html",
               "<html><title>Admin Dashboard</title>Admin Dashboard</html>", {}),
    "/static/app.js": (200, "application/javascript", APP_JS, {}),
    "/static/app.js.map": (200, "application/json", APP_JS_MAP, {}),
    "/static/logo.png": (200, "image/png", b"\x89PNG\r\n\x1a\nfixture", {}),
    "/favicon.ico": (200, "image/x-icon", b"\x00\x00\x01\x00fixture", {}),
    "/.git/HEAD": (200, "text/plain", "ref: refs/heads/main\n", {}),
    "/.git/config": (200, "text/plain",
                     '[remote "origin"]\n\turl = https://github.com/fixture/fixture.git\n', {}),
    "/.env": (200, "text/plain",
              "DB_HOST=db.fixture.test\nDB_PASSWORD=FixturePass123!\n"
              "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", {}),
    "/robots.txt": (200, "text/plain",
                    "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n"
                    "Sitemap: https://fixture.test/sitemap.xml\n", {}),
    "/sitemap.xml": (200, "application/xml",
                     '<?xml version="1.0"?><urlset>'
                     "<url><loc>https://fixture.test/</loc></url>"
                     "<url><loc>https://fixture.test/login</loc></url>"
                     "<url><loc>https://fixture.test/admin/</loc></url>"
                     "</urlset>", {}),
    "/.well-known/security.txt": (200, "text/plain",
                                  "Contact: mailto:security@fixture.test\n"
                                  "Expires: 2027-01-01T00:00:00.000Z\n", {}),
    "/openapi.json": (200, "application/json", OPENAPI, {}),
    "/swagger.json": (200, "application/json", OPENAPI, {}),
    "/api/docs": (200, "text/html",
                  "<html><title>Swagger UI</title>swagger-ui fixture</html>", {}),
    "/graphql": (200, "application/json", GRAPHQL_SCHEMA, {}),
    "/phpinfo.php": (200, "text/html",
                     "<html><title>phpinfo()</title>"
                     "<h1>PHP Version 7.4.3</h1></html>", {}),
    "/server-status": (200, "text/html",
                       "Apache Server Status for fixture.test "
                       "Server Version: Apache/2.4.49", {}),
    "/wp-login.php": (200, "text/html",
                      '<html><form id="loginform">'
                      '<input name="log"><input name="pwd" type="password">'
                      "</form>wp-login fixture</html>", {}),
    "/wp-json/": (200, "application/json",
                  json.dumps({"name": "Fixture", "namespaces": ["wp/v2"]}), {}),
    "/api/v1/users": (200, "application/json", USERS_JSON, {}),
    "/api/v1/orders": (200, "application/json", "[]", {}),
    "/api/internal/metrics": (200, "application/json", '{"debug": true}', {}),
    "/backup.sql": (200, "application/sql",
                    "CREATE TABLE users (id INT, email TEXT);\n"
                    "INSERT INTO users VALUES (1, 'admin@fixture.test');", {}),
    "/backup.zip": (200, "application/zip",
                    b"PK\x03\x04" + b"fixture-backup-archive-contents " * 4, {}),
    "/crossdomain.xml": (200, "text/xml",
                         '<cross-domain-policy>'
                         '<site-control permitted-cross-domain-policies="all"/>'
                         "</cross-domain-policy>", {}),
    "/manifest.json": (200, "application/json",
                       json.dumps({"name": "Fixture Corp",
                                   "short_name": "Fixture",
                                   "start_url": "/",
                                   "display": "standalone"}), {}),
}

# Wayback CDX (output=json) rows for the fixture domain: header row +
# captures, in the array-of-arrays shape the CDX API returns.
CDX_JSON = json.dumps([
    ["timestamp", "original"],
    ["20230101000000", "https://fixture.test/old-page"],
    ["20230202000000", "https://fixture.test/backup.sql"],
    ["20230303000000", "https://fixture.test/.git/HEAD"],
    ["20230404000000", "https://fixture.test/static/app.js"],
    ["20230505000000", "https://fixture.test/.env"],
])

# Deliberately weak/default headers: no CSP, no X-Frame-Options, no
# X-Content-Type-Options; HSTS present but far too short; insecure cookie.
HOME_HEADERS = {
    "Server": "Apache/2.4.49 (Unix)",
    "X-Powered-By": "PHP/7.4.3",
    "Strict-Transport-Security": "max-age=300",
    "Set-Cookie": "sessionid=fixture123; Path=/",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Credentials": "true",
}


def _handler(request: httpx.Request) -> httpx.Response:
    url = request.url
    host = url.host
    path = url.path or "/"
    if host == "waf.fixture.test":
        # Cloudflare-fronted host: passive vendor fingerprints on every
        # response (__cf_bm cookie, CF-Ray, server) and a hard 403 block
        # page for the classic XSS probe string, like a real WAF serves.
        cf = {"Server": "cloudflare", "CF-Ray": "8abc1234-fixture",
              "Set-Cookie": "__cf_bm=abc123; path=/; HttpOnly"}
        if request.url.query and (
                b"%3Cscript%3E" in request.url.query
                or b"<script>" in request.url.query):
            return httpx.Response(
                403, headers=cf, request=request,
                content=("<title>Attention Required! | Cloudflare</title>"
                         "<h1>Sorry, you have been blocked</h1>"))
        return httpx.Response(
            200, headers=cf, request=request,
            content=("<html><head><title>protected</title></head>"
                     "<body>behind cloudflare</body></html>"))
    if host == "crt.sh":
        return httpx.Response(200, content=CRT_JSON,
                              headers={"Content-Type": "application/json"},
                              request=request)
    if host in ("web.archive.org",):
        if path.startswith("/cdx/"):
            return httpx.Response(200, content=CDX_JSON,
                                  headers={"Content-Type":
                                           "application/json"},
                                  request=request)
        body = ("http://fixture.test/old-page\n"
                "https://fixture.test/static/app.js\n"
                "https://fixture.test/backup.sql\n")
        return httpx.Response(200, content=body,
                              headers={"Content-Type": "text/plain"},
                              request=request)
    if host == "api.hackertarget.com":
        return httpx.Response(200, content="api.fixture.test\nmail.fixture.test\n",
                              headers={"Content-Type": "text/plain"},
                              request=request)
    if host in ("dns.google", "cloudflare-dns.com"):
        return httpx.Response(200, content=json.dumps({"Answer": [
            {"name": "fixture.test", "type": 1, "TTL": 300,
             "data": "192.0.2.10"}]}),
            headers={"Content-Type": "application/json"}, request=request)
    if host.endswith(HOST) or host == HOST:
        if path == "/graphql":
            if request.method.upper() == "GET":
                return httpx.Response(
                    200,
                    content="<html><title>GraphQL Playground</title></html>",
                    headers={"Content-Type": "text/html", **HOME_HEADERS},
                    request=request)
            # Answer like a real GraphQL server: a __typename probe gets
            # a __typename payload; an introspection query gets the
            # schema. Plugins distinguish the two.
            body = request.content.decode("utf-8", "ignore")
            if "__schema" in body:
                payload = GRAPHQL_SCHEMA
            elif "__typename" in body:
                payload = json.dumps({"data": {"__typename": "Query"}})
            else:
                payload = json.dumps({"data": {"user": {"name": "Fixture"}}})
            return httpx.Response(
                200, content=payload,
                headers={"Content-Type": "application/json", **HOME_HEADERS},
                request=request)
        status, ctype, body, extra = ROUTES.get(
            path, (404, "text/html", NOT_FOUND, {}))
        headers = {"Content-Type": ctype, **HOME_HEADERS, **extra}
        return httpx.Response(status, content=body, headers=headers,
                              request=request)
    # Any other external host: nothing there.
    return httpx.Response(404, content="", request=request)


def fixture_transport() -> httpx.MockTransport:
    return httpx.MockTransport(_handler)


def fixture_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=fixture_transport(),
                             follow_redirects=True,
                             headers={"User-Agent": "ReconAnything-Fixture/1.0"},
                             trust_env=False)


def seed_fixture_bus(ctx) -> None:
    """Pre-fill the discovery bus with what a phase-1 crawl of the
    fixture site would have published, so phase-2 chain plugins get
    realistic input when run standalone."""
    ctx.publish("subdomains", "www.fixture.test")
    ctx.publish("subdomains", "api.fixture.test")
    ctx.publish("subdomains", "mail.fixture.test")
    ctx.publish("js_files", f"{BASE}/static/app.js")
    ctx.publish("endpoints", f"{BASE}/api/v1/users")
    ctx.publish("endpoints", f"{BASE}/login")
    ctx.publish("tech", "wordpress 6.4.2")
    ctx.publish("tech", "apache 2.4.49")
    ctx.publish("tech", "php 7.4")
    ctx.publish("graphql_endpoints", f"{BASE}/graphql")
    ctx.publish("emails", "admin@fixture.test")
    ctx.publish("urls", f"{BASE}/")
    ctx.publish("urls", f"{BASE}/login")


def make_fixture_ctx(mode: str = "passive", seed: bool = True):
    """A REAL base.Ctx wired to the fixture transport."""
    from app import config
    from app.cache import Cache
    from app.plugins.base import Ctx
    from app.ratelimit import RateLimiter

    ctx = Ctx(run_id="fixture-audit", mode=mode, http=fixture_client(),
              cache=Cache(), keys={}, limiter=RateLimiter(),
              evidence_dir="/tmp", source_type="website")
    assert config  # silence linters; config imported for env parity
    if seed:
        seed_fixture_bus(ctx)
    return ctx


def url_target():
    from app.plugins.base import Target
    return Target(raw=f"{BASE}/", type="url", normalized=f"{BASE}/")


def domain_target():
    from app.plugins.base import Target
    return Target(raw=HOST, type="domain", normalized=HOST)


async def run_plugin_fixture(cls, target, mode: str = "passive",
                             timeout: float = 25.0):
    """Run one plugin class against the fixture; never raises.

    Returns (status_str, findings_list, error_str). Mirrors the
    missing-keys / accepts gating of the production runner.
    """
    import asyncio

    from app.plugins.base import PluginStatus

    plugin = cls()
    ctx = make_fixture_ctx(mode=mode)
    try:
        if plugin.missing_keys(ctx):
            return "skipped-key", [], ""
        if plugin.accepts and target.type not in plugin.accepts:
            return "n/a", [], ""
        result = await asyncio.wait_for(plugin.run(target, ctx),
                                        timeout=timeout)
        status = result.status
        if isinstance(status, PluginStatus):
            status = status.value
        return str(status), list(result.findings), result.reason or ""
    except asyncio.TimeoutError:
        return "timeout", [], f"timed out after {timeout}s"
    except Exception as e:  # noqa: BLE001 - audit must never die
        import traceback
        return "raised", [], f"{type(e).__name__}: {e}\n" + \
            traceback.format_exc(limit=6)
    finally:
        try:
            await ctx.http.aclose()
        except Exception:
            pass
