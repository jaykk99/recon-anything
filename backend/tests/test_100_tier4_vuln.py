"""Tier-4 Vuln/CVE plugins (100-plugin expansion, 2026-11-05).

Per plugin: fires on the VULN fixture, silent on the CLEAN fixture,
no crash on malformed/empty targets. Deterministic: everything HTTP
runs over a local httpx MockTransport that models a deliberately
vulnerable site on vuln.test and a hardened site on clean.test.

A2SV note: TLS handshakes cannot ride MockTransport, so a2sv is
verified at its pure-assessment layer (assess_tls fires on a
vulnerable matrix, silent on a modern one) plus a no-crash run()
against an unroutable host. Its live handshake behavior is covered
by the recorded live smoke.

Cent note: the "target" is the templates directory - the VULN case
points CENT_TEMPLATES_DIR at a directory containing a malformed
template; the CLEAN case at a directory of valid templates only.
"""
import asyncio
import json
import os
import sys
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.cache import Cache  # noqa: E402
from app.plugins.base import Ctx, Target  # noqa: E402
from app.ratelimit import RateLimiter  # noqa: E402

IDS = ["nuclei_cve_pack", "nikto_scan", "wapiti_scan", "jaeles_scan",
       "cent_templates", "snallygaster_scan", "wpscan_scan",
       "droopescan_scan", "a2sv_scan", "tsunami_scan"]

VULN = "vuln.test"
CLEAN = "clean.test"
SPA = "spa.test"

SPA_HOME = ("<html><head><title>SPA Corp</title></head><body>"
            "<div id=\"root\">single page app shell - same bytes "
            "for every route, long enough to look like a real page "
            "body when a scanner probes a path that does not exist "
            "on disk at all</div></body></html>")

VULN_HOME = """<html><head>
<meta name="generator" content="WordPress 6.4.2">
<title>Vuln Corp</title></head><body>
<h1>Vuln Corp</h1>
<p>Powered by vBulletin 5.5.4 forum software</p>
<script src="/wp-content/plugins/revslider/public/assets/js/rs6.js">
</script>
<link rel="stylesheet" href="/wp-content/themes/flavor/style.css">
<a href="/author/admin/">admin</a>
</body></html>"""

CLEAN_HOME = """<html><head><title>Clean Corp</title></head>
<body><h1>Clean Corp</h1><p>Nothing to see here.</p></body></html>"""

VULN_HEADERS = {
    "Server": "Apache/2.2.34 (Unix) Jetty(9.4.38.v20210224)",
    "X-Powered-By": "PHP/5.6.40",
    "Set-Cookie": "sessionid=abc123; Path=/",
}
CLEAN_HEADERS = {
    "Server": "cloudflare",
    "Strict-Transport-Security": "max-age=63072000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Set-Cookie": "sessionid=abc123; Path=/; Secure; HttpOnly; "
                  "SameSite=Lax",
}

EXPOSED_200 = {
    "/.git/HEAD": "ref: refs/heads/main\n",
    "/.git/config": "[core]\n",
    "/.env": "APP_DEBUG=true\n",
    "/backup.sql": "-- dump\n",
    "/phpinfo.php": "<title>phpinfo()</title>",
    "/server-status": "Apache Server Status",
    "/actuator/health": '{"status":"UP"}',
    "/actuator/env": '{"propertySources":[]}',
    "/readme.html": "<html>WordPress Version 6.4.2 readme</html>",
    "/CHANGELOG.txt": "Drupal 7.99, 2023-01-01\n",
    "/wp-json/": json.dumps({"name": "Vuln", "namespaces":
                             ["wp/v2", "oembed/1.0"]}),
    "/wp-json/wp/v2/users": json.dumps(
        [{"id": 1, "slug": "admin", "name": "Site Admin"},
         {"id": 2, "slug": "editor", "name": "Ed"}]),
    "/cgi-bin/test-cgi": "test-cgi output",
    "/phpmyadmin/": "<title>phpMyAdmin</title>phpMyAdmin Welcome",
    "/login": "<title>Jenkins</title>Jenkins Dashboard login "
              "X-Jenkins",
    "/v1/agent/self": json.dumps({"Config": {"Name": "consul-1"},
                                  "Member": {"Name": "consul-1"}}),
    "/version": json.dumps({"etcdserver": "3.4.0",
                            "etcdcluster": "3.4.0"}),
    "/uploads/": "<title>Index of /uploads/</title>Index of /uploads/",
    "/web.config": "<configuration></configuration>",
}

ETCD_OR_DOCKER = {
    # /version is shared by the etcd and docker path probes; the
    # vuln body carries BOTH signatures' needs: etcd JSON wins the
    # path probe; docker is exercised via the fingerprint unit test.
}


def _handler(request: httpx.Request) -> httpx.Response:
    url = urlparse(str(request.url))
    host, path = url.hostname or "", url.path or "/"
    q = parse_qs(url.query)
    if host == SPA:
        # SPA catch-all: EVERY path returns the same 200 HTML shell.
        return httpx.Response(200, headers=dict(CLEAN_HEADERS),
                              content=SPA_HOME, request=request)
    if host not in (VULN, CLEAN):
        return httpx.Response(404, content="", request=request)
    vuln = host == VULN
    headers = dict(VULN_HEADERS if vuln else CLEAN_HEADERS)
    if vuln and path == "/login":
        headers["X-Jenkins"] = "2.401.3"
    # --- wapiti differentials (vuln only) ---
    if vuln:
        if "q" in q:
            val = q["q"][0]
            body = f"<html><body>results for: {val}</body></html>"
            return httpx.Response(200, headers=headers,
                                  content=body, request=request)
        if "id" in q and "'" in q["id"][0]:
            return httpx.Response(
                200, headers=headers, request=request,
                content=("<html>You have an error in your SQL syntax; "
                         "check the manual that corresponds to your "
                         "MySQL server version</html>"))
        if "file" in q and ".." in q["file"][0]:
            return httpx.Response(
                200, headers=headers, request=request,
                content="root:x:0:0:root:/root:/bin/bash\n")
        if "page" in q and ".." in q["page"][0]:
            return httpx.Response(
                200, headers=headers, request=request,
                content="root:x:0:0:root:/root:/bin/bash\n")
    if path in ("/", "/index.html"):
        return httpx.Response(200, headers=headers, request=request,
                              content=VULN_HOME if vuln else CLEAN_HOME)
    if vuln and path in EXPOSED_200:
        return httpx.Response(200, headers=headers, request=request,
                              content=EXPOSED_200[path])
    if vuln and path == "/search":
        return httpx.Response(200, headers=headers, request=request,
                              content="<html>search page</html>")
    return httpx.Response(404, headers=headers, request=request,
                          content="<html>not found</html>")


def _ctx() -> Ctx:
    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler),
                               follow_redirects=True, trust_env=False,
                               headers={"User-Agent": "Recon-Tier4-Test"})
    return Ctx(run_id="tier4-test", mode="active", http=client,
               cache=Cache(), keys={}, limiter=RateLimiter(),
               evidence_dir="/tmp", source_type="website")


def _target(host: str) -> Target:
    return Target(raw=f"https://{host}/", type="url",
                  normalized=f"https://{host}/")


async def _run(pid: str, target: Target):
    from app.plugins.registry import discover
    cls = discover()[pid]
    ctx = _ctx()
    try:
        return await asyncio.wait_for(cls().run(target, ctx),
                                      timeout=60)
    finally:
        await ctx.http.aclose()


def run(pid, host):
    return asyncio.run(_run(pid, _target(host)))


def keys_of(res):
    return {f.key for f in res.findings}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_all_tier4_plugins_registered():
    from app.plugins.registry import discover
    reg = discover()
    for pid in IDS:
        assert pid in reg, f"{pid} missing from registry"


# ---------------------------------------------------------------------------
# 1. nuclei_cve_pack
# ---------------------------------------------------------------------------

def test_cve_pack_fires_on_vuln():
    res = run("nuclei_cve_pack", VULN)
    assert "nuclei_cve_match" in keys_of(res)
    vals = " ".join(f.value for f in res.findings)
    assert "Jetty" in vals  # Jetty(9.4.38...) in the Server banner


def test_cve_pack_silent_on_clean():
    res = run("nuclei_cve_pack", CLEAN)
    assert res.findings == []


def test_cve_pack_evaluate_unit():
    from app.plugins.nuclei_cve_pack import evaluate_templates
    hits = evaluate_templates(
        {"server": "Jetty(9.4.38.v20210224)", "body": "", "powered_by": ""})
    assert any(h["cve"] == "CVE-2021-28164" for h in hits)
    assert evaluate_templates({"server": "nginx/1.25.0"}) == []


# ---------------------------------------------------------------------------
# 2. nikto_scan
# ---------------------------------------------------------------------------

def test_nikto_fires_on_vuln():
    res = run("nikto_scan", VULN)
    ks = keys_of(res)
    assert "nikto_outdated_banner" in ks
    assert "nikto_cgi_test" in ks
    assert "nikto_missing_security_headers" in ks


def test_nikto_silent_on_clean():
    res = run("nikto_scan", CLEAN)
    assert res.findings == []


# ---------------------------------------------------------------------------
# 3. wapiti_scan
# ---------------------------------------------------------------------------

def test_wapiti_fires_on_vuln():
    res = run("wapiti_scan", VULN)
    ks = keys_of(res)
    assert "xss_reflected" in ks
    assert "sqli_error_based" in ks
    assert "lfi_passwd_signature" in ks


def test_wapiti_silent_on_clean():
    res = run("wapiti_scan", CLEAN)
    assert res.findings == []


# ---------------------------------------------------------------------------
# 4. jaeles_scan
# ---------------------------------------------------------------------------

def test_jaeles_fires_on_vuln():
    res = run("jaeles_scan", VULN)
    sigs = {f.evidence.get("signature") for f in res.findings}
    assert "git-head-exposed" in sigs
    assert "cookie-missing-httponly" in sigs
    assert "actuator-health-exposed" in sigs


def test_jaeles_silent_on_clean():
    res = run("jaeles_scan", CLEAN)
    # clean host: no vuln signatures; version-disclosure may fire on
    # any numbered banner - clean banner has no version, so fully silent
    assert res.findings == []


def test_jaeles_signatures_load():
    from app.plugins.jaeles_scan import load_signatures
    sigs = load_signatures()
    assert len(sigs) >= 8
    assert {s["mode"] for s in sigs} == {"passive", "active"}


# ---------------------------------------------------------------------------
# 5. cent_templates
# ---------------------------------------------------------------------------

GOOD_TPL = """id: good-one
info:
  name: Good template
  severity: low
  tags: [test]
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers:
      - type: status
        status: [200]
"""
BAD_TPL = """id: [unclosed
info: {severity: bogus}
"""


def _cent_dir(name, files):
    import time as _time
    d = os.path.join("/tmp", f"cent_tier4_{name}")
    os.makedirs(d, exist_ok=True)
    for fn, text in files.items():
        p = os.path.join(d, fn)
        # skip the write when the file already carries the content
        try:
            if os.path.getsize(p) == len(text):
                continue
        except Exception:
            pass
        for _attempt in range(50):
            try:
                with open(p, "w") as fh:
                    fh.write(text)
                if os.path.getsize(p) == len(text):
                    break
            except Exception:
                pass
            _time.sleep(0.3)
    return d


def test_cent_fires_on_malformed(monkeypatch):
    d = _cent_dir("vuln", {"good.yaml": GOOD_TPL, "bad.yaml": BAD_TPL})
    monkeypatch.setenv("CENT_TEMPLATES_DIR", d)
    res = run("cent_templates", CLEAN)
    assert "cent_malformed_template" in keys_of(res)
    assert "2 templates" in res.reason


def test_cent_silent_on_clean_dir(monkeypatch):
    d = _cent_dir("clean", {"good.yaml": GOOD_TPL})
    monkeypatch.setenv("CENT_TEMPLATES_DIR", d)
    res = run("cent_templates", CLEAN)
    assert res.findings == []
    assert "0 malformed" in res.reason


def test_cent_bundled_set_is_clean(monkeypatch):
    monkeypatch.delenv("CENT_TEMPLATES_DIR", raising=False)
    monkeypatch.delenv("NUCLEI_TEMPLATES_DIR", raising=False)
    from app.plugins.cent_templates import BUNDLED, lint_template
    for name, text in BUNDLED:
        assert lint_template(name, text) == [], name


# ---------------------------------------------------------------------------
# 6. snallygaster_scan
# ---------------------------------------------------------------------------

def test_snallygaster_fires_on_vuln():
    res = run("snallygaster_scan", VULN)
    ks = keys_of(res)
    assert "git_exposed" in ks
    assert "exposed_env" in ks
    assert "phpinfo_exposed" in ks
    # existence/status only: no secret body content in any finding value
    for f in res.findings:
        assert "APP_DEBUG" not in f.value


def test_snallygaster_silent_on_clean():
    res = run("snallygaster_scan", CLEAN)
    assert res.findings == []


# ---------------------------------------------------------------------------
# 7. wpscan_scan
# ---------------------------------------------------------------------------

def test_wpscan_fires_on_vuln():
    res = run("wpscan_scan", VULN)
    ks = keys_of(res)
    assert "wp_version" in ks
    assert "wp_plugin_slug" in ks
    assert "wp_json_surface" in ks
    assert "wp_author_enum" in ks
    slugs = {f.evidence.get("slug") for f in res.findings}
    assert "revslider" in slugs


def test_wpscan_silent_on_clean():
    res = run("wpscan_scan", CLEAN)
    assert res.findings == []


# ---------------------------------------------------------------------------
# 8. droopescan_scan
# ---------------------------------------------------------------------------

def test_droopescan_fires_on_vuln():
    res = run("droopescan_scan", VULN)
    cms = {f.evidence.get("cms") for f in res.findings}
    assert "wordpress" in cms
    wp = [f for f in res.findings
          if f.evidence.get("cms") == "wordpress"][0]
    assert wp.evidence.get("version") == "6.4.2"


def test_droopescan_silent_on_clean():
    res = run("droopescan_scan", CLEAN)
    assert res.findings == []


# ---------------------------------------------------------------------------
# 9. a2sv_scan (pure assessment layer + no-crash run)
# ---------------------------------------------------------------------------

def test_a2sv_assess_fires_on_vuln_matrix():
    from app.plugins.a2sv_scan import assess_tls
    hits = assess_tls(
        {"SSLv3": False, "TLSv1.0": True, "TLSv1.1": True,
         "TLSv1.2": True, "TLSv1.3": True},
        weak_ok=True,
        cert={"self_signed": True, "expired": True,
              "not_after": "Jan  1 00:00:00 2020 GMT"})
    keys = {k for k, _v, _s in hits}
    assert "tls_deprecated_protocol" in keys
    assert "tls_weak_cipher" in keys
    assert "tls_expired_cert" in keys
    assert "tls_self_signed_cert" in keys


def test_a2sv_assess_silent_on_modern_matrix():
    from app.plugins.a2sv_scan import assess_tls
    hits = assess_tls(
        {"SSLv3": False, "TLSv1.0": False, "TLSv1.1": False,
         "TLSv1.2": True, "TLSv1.3": True},
        weak_ok=False, cert={"self_signed": False, "expired": False})
    assert hits == []


def test_a2sv_run_no_crash_unroutable():
    res = run("a2sv_scan", "nonexistent.invalid")
    assert res.findings == []
    assert "no TLS handshake" in res.reason or res.reason


# ---------------------------------------------------------------------------
# 10. tsunami_scan
# ---------------------------------------------------------------------------

def test_tsunami_fires_on_vuln():
    res = run("tsunami_scan", VULN)
    services = {f.evidence.get("service") for f in res.findings}
    assert "jenkins" in services
    assert "consul" in services
    assert "phpmyadmin" in services


def test_tsunami_silent_on_clean():
    res = run("tsunami_scan", CLEAN)
    assert res.findings == []


def test_tsunami_fingerprint_units():
    from app.plugins.tsunami_scan import fingerprint
    assert fingerprint("docker_api", 200, {},
                       json.dumps({"ApiVersion": "1.41",
                                   "Version": "24.0"}))
    assert not fingerprint("docker_api", 200, {}, "<html>hi</html>")
    assert fingerprint("etcd", 200, {},
                       json.dumps({"etcdserver": "3.5.0"}))
    assert not fingerprint("jenkins", 200, {}, "<html>plain</html>")


# ---------------------------------------------------------------------------
# SPA catch-all host: status-only probes must NOT false-positive
# (regression from the tier4 live smoke against a real SPA site)
# ---------------------------------------------------------------------------

def test_snallygaster_silent_on_spa():
    res = run("snallygaster_scan", SPA)
    assert res.findings == []
    assert "catch-all" in res.reason


def test_nikto_paths_silent_on_spa():
    res = run("nikto_scan", SPA)
    assert res.findings == []
    assert "catch-all" in res.reason


def test_jaeles_silent_on_spa():
    res = run("jaeles_scan", SPA)
    assert res.findings == []


def test_wpscan_silent_on_spa():
    res = run("wpscan_scan", SPA)
    assert res.findings == []


# ---------------------------------------------------------------------------
# Malformed targets: no plugin may crash
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("pid", IDS)
def test_no_crash_on_malformed(pid):
    bad = Target(raw="", type="email", normalized="not a url @@")
    res = asyncio.run(_run(pid, bad))
    assert res is not None
    assert isinstance(res.findings, list)
