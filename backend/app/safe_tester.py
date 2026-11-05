"""Safe real-world vulnerability tester.

Sends REAL detection probes to the actual target, but strictly
non-destructive: read-only requests, no data modification, no deletion,
no exploitation beyond proving a vulnerability exists.

This is standard bug-bounty detection methodology. Every probe is:
- GET or HEAD only (never POST/PUT/DELETE)
- Rate-limited (small delay between requests)
- Detection-only (checks for a signal, extracts nothing sensitive)

Only use against targets you are authorized to test.
"""
from __future__ import annotations

import base64
import json
import re
import time
from typing import Dict, List, Tuple
from urllib.parse import urljoin

import httpx

USER_AGENT = "ReconAnything-SafeTest/1.0 (authorized security testing)"
REQUEST_DELAY = 0.5  # seconds between probes
TIMEOUT = 15


def _client() -> httpx.Client:
    from .net import sync_client
    return sync_client(
        timeout=TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    )


def _sleep():
    time.sleep(REQUEST_DELAY)


# ---------------------------------------------------------------------------
# Soft-404 / catch-all baseline. SPA and Next.js/Vercel apps answer EVERY
# unknown path with a 200 HTML shell, which makes naive "path returned 200"
# probes fire on files that don't exist. We fingerprint the catch-all once
# per target so path-existence probes can tell a real hit from the shell.
# ---------------------------------------------------------------------------

_CATCHALL_CACHE: Dict[str, Dict] = {}


def _catchall_sig(base: str) -> Dict:
    """Fetch a known-nonexistent path once per base and fingerprint it."""
    if base in _CATCHALL_CACHE:
        return _CATCHALL_CACHE[base]
    sig = {"status": None, "ctype": "", "len": 0, "prefix": ""}
    try:
        with _client() as c:
            r = c.get(urljoin(base, "/no-such-path-9a7f2c3d4e5f0b1a"))
        sig = {
            "status": r.status_code,
            "ctype": r.headers.get("content-type", "").split(";")[0].strip().lower(),
            "len": len(r.content),
            "prefix": (r.text or "")[:300],
        }
    except Exception:
        pass
    _CATCHALL_CACHE[base] = sig
    return sig


def _is_soft_404(base: str, r) -> bool:
    """True if r looks like the target's catch-all page (a 200 shell served
    for nonexistent paths), not a genuinely distinct resource."""
    sig = _catchall_sig(base)
    if sig.get("status") is None or sig["status"] >= 400:
        # The probe path 404'd honestly (or we couldn't baseline): a 200 is
        # then a real resource, so never treat it as a soft-404.
        return False
    try:
        ctype = r.headers.get("content-type", "").split(";")[0].strip().lower()
        if r.status_code != sig["status"] or ctype != sig["ctype"]:
            return False
        rl, sl = len(r.content), max(sig["len"], 1)
        close_len = abs(rl - sl) <= 0.10 * sl
        return close_len or (r.text or "")[:300] == sig["prefix"]
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Individual safe probes. Each returns (works: bool, detail: str).
# ---------------------------------------------------------------------------

def probe_git_head(base: str) -> Tuple[bool, str]:
    """GET /.git/HEAD - check if git repo is exposed (read-only)."""
    try:
        with _client() as c:
            r = c.get(urljoin(base, "/.git/HEAD"))
        if r.status_code == 200 and r.text.strip().startswith("ref:"):
            return True, f"Live test: /.git/HEAD returned 200 with '{r.text.strip()[:40]}'. Repo exposed."
        return False, f"Live test: /.git/HEAD returned {r.status_code}. Not exposed."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_env(base: str) -> Tuple[bool, str]:
    """GET /.env - check if a real env file is served (read-only). A 200 only
    counts if the body looks like KEY=VALUE env content, not an HTML shell."""
    try:
        with _client() as c:
            r = c.get(urljoin(base, "/.env"))
        if r.status_code != 200:
            return False, f"Live test: /.env returned {r.status_code}."
        if _is_soft_404(base, r):
            return False, "Live test: /.env returned 200 but it is the site's catch-all page, not an env file."
        ct = r.headers.get("content-type", "").lower()
        body = (r.text or "")[:2000]
        looks_env = bool(re.search(r"(?m)^\s*[A-Z][A-Z0-9_]{2,}=", body)) and "<html" not in body.lower()
        if looks_env:
            return True, f"Live test: /.env returned 200 ({ct or 'no ctype'}) with env-style KEY=VALUE content. Secrets exposed."
        return False, "Live test: /.env returned 200 but body is not env content (HTML/other). Not exposed."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_sqli(base: str, param: str = "id") -> Tuple[bool, str]:
    """GET with quote probe - check for SQL error (detection only, no extraction)."""
    try:
        with _client() as c:
            baseline = c.get(base, params={param: "1"})
            _sleep()
            probed = c.get(base, params={param: "1'"})
        err_sigs = ["sql syntax", "mysql", "sqlite", "postgresql", "ora-",
                    "odbc", "jdbc", "unclosed quotation"]
        base_body = baseline.text.lower()
        body = probed.text.lower()
        # Only count an error signature the quote INTRODUCED: if the same word
        # is already in the baseline page, it's page content, not a SQL error.
        new_hit = [s for s in err_sigs if s in body and s not in base_body]
        status_regressed = probed.status_code >= 500 and baseline.status_code < 500
        if new_hit or status_regressed:
            why = (f"new SQL error text '{new_hit[0]}'" if new_hit
                   else f"status {probed.status_code} vs baseline {baseline.status_code}")
            return True, (f"Live test: quote probe on ?{param}= triggered {why} "
                          "(differs from baseline). Injection likely.")
        return False, (f"Live test: quote probe returned {probed.status_code}, no "
                        "new SQL error vs baseline. Not injectable via this probe.")
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_cors(base: str) -> Tuple[bool, str]:
    """GET with evil Origin - check for reflected CORS (read-only)."""
    try:
        with _client() as c:
            r = c.get(base, headers={"Origin": "https://evil.example"})
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        if "evil.example" in acao:
            creds = " with Allow-Credentials: true" if acac.lower() == "true" else ""
            return True, f"Live test: server reflected evil origin{creds}. CORS misconfigured."
        return False, f"Live test: ACAO is '{acao or '(not set)'}'. Not vulnerable."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_s3(bucket_url: str) -> Tuple[bool, str]:
    """GET bucket root - check for public listing (read-only, no object download)."""
    try:
        with _client() as c:
            r = c.get(bucket_url)
        if r.status_code == 200 and "ListBucketResult" in r.text:
            return True, "Live test: bucket root returned ListBucketResult XML. Publicly listable."
        return False, f"Live test: bucket returned {r.status_code}."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_clickjack(base: str) -> Tuple[bool, str]:
    """GET page - check for missing frame protection headers (read-only)."""
    try:
        with _client() as c:
            r = c.get(base)
        xfo = r.headers.get("x-frame-options", "")
        csp = r.headers.get("content-security-policy", "")
        if not xfo and "frame-ancestors" not in csp:
            return True, "Live test: no X-Frame-Options or frame-ancestors. Clickjackable."
        return False, f"Live test: protected (XFO={xfo or 'none'}, CSP frame-ancestors present={('frame-ancestors' in csp)})."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_wordpress(base: str) -> Tuple[bool, str]:
    """GET /wp-json/ - check WordPress version disclosure (read-only)."""
    try:
        with _client() as c:
            r = c.get(urljoin(base, "/wp-json/wp/v2/"))
        ct = r.headers.get("content-type", "").lower()
        body = (r.text or "")[:800]
        is_wp_api = ("json" in ct or '"namespace"' in body or '"routes"' in body
                     or '"wp/v2"' in body)
        if r.status_code == 200 and is_wp_api and not _is_soft_404(base, r):
            return True, "Live test: /wp-json/wp/v2/ returned a WordPress REST API document. Version disclosable."
        return False, f"Live test: /wp-json/ returned {r.status_code} with no WP REST payload."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_bola(base: str) -> Tuple[bool, str]:
    """GET two object IDs - check for BOLA (read-only, no modification)."""
    # Generic: try common API patterns found during scan
    patterns = ["/api/users/1", "/api/users/2"]
    try:
        with _client() as c:
            r1 = c.get(urljoin(base, patterns[0]))
            _sleep()
            r2 = c.get(urljoin(base, patterns[1]))
        ct1 = r1.headers.get("content-type", "").lower()
        both_200 = r1.status_code == 200 and r2.status_code == 200
        looks_api = "json" in ct1 or r1.text.lstrip()[:1] in "[{"
        distinct = r1.text != r2.text  # two different objects, not one shared shell
        if (both_200 and looks_api and distinct and len(r1.text) > 50
                and not _is_soft_404(base, r1) and not _is_soft_404(base, r2)):
            return True, (f"Live test: {patterns[0]} and {patterns[1]} each returned a distinct "
                          "JSON object unauthenticated. Possible BOLA - verify with an authorized session.")
        return False, (f"Live test: IDs returned {r1.status_code}/{r2.status_code} "
                        "(not distinct API objects). No clear BOLA signal.")
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_jwt_offline(token_hint: str = "") -> Tuple[bool, str]:
    """Offline JWT header decode - zero requests."""
    # We cannot decode without a token; report the check method
    return (False,
            "Offline check: paste a JWT to decode its alg locally. "
            "No requests sent. Look for alg:none or weak HS256.")


def probe_shadow_it(subdomain: str) -> Tuple[bool, str]:
    """HEAD subdomain - check for old software banners (read-only)."""
    try:
        url = subdomain if subdomain.startswith("http") else f"https://{subdomain}"
        with _client() as c:
            r = c.head(url)
        server = r.headers.get("server", "")
        old_sigs = ["apache/2.2", "apache/2.4.1", "nginx/1.1", "nginx/1.4",
                    "php/5.", "iis/6", "iis/7.5"]
        old = [s for s in old_sigs if s in server.lower()]
        if old:
            return True, f"Live test: {subdomain} runs {old[0]} (outdated). Forgotten asset."
        return False, f"Live test: {subdomain} returned {r.status_code} ({server or 'no server header'})."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def _no_follow_client() -> httpx.Client:
    from .net import sync_client
    return sync_client(
        timeout=TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT},
    )


# ---------------------------------------------------------------------------
# Expanded detection probes (all GET/HEAD, non-destructive, detection-only).
# Each returns (works: bool, detail: str). works=True only on strong signals.
# ---------------------------------------------------------------------------

def probe_xss(base: str) -> Tuple[bool, str]:
    """GET with a unique canary in query params - check for raw reflection."""
    canary = 'qx7Z\'"<>'
    try:
        with _client() as c:
            r = c.get(base)
            # Pull up to 3 real form input names from the page
            names = re.findall(r'name=["\']([A-Za-z0-9_\-]+)["\']', r.text)[:3]
        seen = set()
        params = ["q", "search", "s", "keyword", "name"] + names
        tested = 0
        with _client() as c:
            for p in params:
                if p in seen:
                    continue
                seen.add(p)
                tested += 1
                r = c.get(base, params={p: canary})
                _sleep()
                # Raw canary with unencoded < reflected = strong XSS signal
                if canary in r.text:
                    return True, (f"Live test: raw canary reflected via ?{p}=. "
                                   "Reflected XSS is real on this page.")
        return False, (f"Live test: canary not raw-reflected in {tested} params "
                        "(q, search, s, keyword, name + form fields). Not vulnerable to this probe.")
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_open_redirect(base: str) -> Tuple[bool, str]:
    """GET with external URL in redirect-ish params - check for 3xx to evil host."""
    try:
        params = ["next", "redirect", "url", "return", "dest", "target", "continue", "r"]
        with _no_follow_client() as c:
            for p in params:
                r = c.get(base, params={p: "https://example.com/"})
                _sleep()
                loc = r.headers.get("location", "")
                if r.status_code in (301, 302, 303, 307, 308) and "example.com" in loc:
                    return True, (f"Live test: ?{p}=https://example.com/ returned "
                                   f"{r.status_code} with Location: {loc[:80]}. Open redirect confirmed.")
        return False, (f"Live test: no 3xx redirect to example.com from {len(params)} "
                        "params. Not vulnerable to this probe.")
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_ssrf(base: str) -> Tuple[bool, str]:
    """GET with cloud metadata IP in URL-ish params - check for internal fetch."""
    try:
        params = ["url", "uri", "path", "file", "dest", "target", "redirect", "u"]
        probe = "http://169.254.169.254/latest/meta-data/ami-id"
        with _client() as c:
            for p in params:
                r = c.get(base, params={p: probe})
                _sleep()
                body = r.text.lower()
                if "ami-id" in body or "instance-id" in body:
                    return True, (f"Live test: ?{p}=<metadata-ip> leaked cloud metadata "
                                   "markers. SSRF CONFIRMED. If the response contains "
                                   "credentials, report immediately and do not retain them.")
        return False, (f"Live test: metadata IP not fetched via {len(params)} params. "
                        "No SSRF signal from this probe.")
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_idor(base: str) -> Tuple[bool, str]:
    """GET id+1 and id-1 of discovered numeric IDs - check for direct object access."""
    try:
        with _client() as c:
            r = c.get(base)
            ids = re.findall(r"/users/(\d+)", r.text) + re.findall(r"[?&]id=(\d+)", r.text)
            if not ids:
                return False, ("Live test: no numeric object IDs found on the base page. "
                                "Needs manual testing with an authenticated session.")
            oid = int(ids[0])
            results = []
            for n in (oid + 1, oid - 1):
                if n < 1:
                    continue
                rn = c.get(base, params={"id": str(n)})
                _sleep()
                results.append((n, rn))
        # Strong signal only: both 200, substantial JSON, DIFFERENT id values
        if len(results) == 2 and all(rn.status_code == 200 for _, rn in results):
            bodies = [rn.text for _, rn in results]
            if all(len(b) > 50 for b in bodies):
                ids_in = []
                ok = True
                for b in bodies:
                    try:
                        data = json.loads(b)
                        s = json.dumps(data)
                        m = re.search(r'"id"\s*:\s*"?(\d+)"?', s)
                        if not m:
                            ok = False
                            break
                        ids_in.append(m.group(1))
                    except Exception:
                        ok = False
                        break
                if ok and len(set(ids_in)) == 2:
                    return True, (f"Live test: ids {results[0][0]} and {results[1][0]} both returned "
                                   "200 with different JSON object data. IDOR likely.")
        return False, ("Live test: no strong IDOR signal. "
                        "Needs manual testing with an authenticated session.")
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_auth_bypass(base: str) -> Tuple[bool, str]:
    """GET common admin paths - check for 200 without a login gate (read-only)."""
    try:
        paths = ["/admin", "/admin/", "/administrator", "/wp-admin", "/dashboard", "/manager/html"]
        login_markers = ['type="password"', 'name="password"', "sign in", "log in", "/login"]
        admin_markers = ["admin", "dashboard", "manager", "logout", "settings", "users"]
        with _client() as c:
            try:
                home = (c.get(base).text or "")[:600]
            except Exception:
                home = ""
            for p in paths:
                r = c.get(urljoin(base + "/", p.lstrip("/")))
                _sleep()
                if r.status_code != 200 or _is_soft_404(base, r):
                    continue
                low = r.text.lower()
                gated = any(m in low for m in login_markers)
                is_home_shell = (r.text or "")[:600] == home  # SPA served the same page
                looks_admin = any(m in low for m in admin_markers)
                if not gated and not is_home_shell and looks_admin:
                    return True, (f"Live test: {p} returned a distinct admin page (200, no login markers). "
                                   "Admin area may be reachable without auth - verify manually.")
        return False, (f"Live test: checked {len(paths)} admin paths, all gated, missing, or just the app shell. "
                        "No bypass found.")
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_dir_traversal(base: str) -> Tuple[bool, str]:
    """GET with traversal payload in file-ish params - check for /etc/passwd leak (read-only)."""
    try:
        params = ["file", "path", "page", "include", "template", "name", "f"]
        payload = "....//....//....//etc/passwd"
        with _client() as c:
            for p in params:
                r = c.get(base, params={p: payload})
                _sleep()
                if "root:x:0:0" in r.text:
                    return True, (f"Live test: ?{p}={payload} leaked /etc/passwd contents. "
                                   "Path traversal CONFIRMED (read-only check).")
        return False, (f"Live test: traversal payload not reflected via {len(params)} "
                        "params. Not vulnerable to this probe.")
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_xxe(base: str) -> Tuple[bool, str]:
    """GET with internal-entity XML in ?xml= - check if the entity expands."""
    try:
        payload = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe "xxeProbe9">]><r>&xxe;</r>'
        with _client() as c:
            r = c.get(base, params={"xml": payload})
        if "xxeProbe9" in r.text:
            return True, ("Live test: internal entity 'xxeProbe9' was expanded and reflected. "
                           "XXE CONFIRMED via GET param.")
        return False, ("Live test: entity not expanded. Inconclusive over GET, "
                        "test manually with POST if an XML endpoint exists.")
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_ssti(base: str) -> Tuple[bool, str]:
    """GET with math payloads in template-ish params - check for evaluation."""
    try:
        params = ["name", "q", "search", "template", "view"]
        tested = 0
        with _client() as c:
            base_body = c.get(base).text
            _sleep()
            if "9352" in base_body:
                return False, ("Live test: baseline page already contains '9352'. "
                                "Cannot distinguish evaluation. Needs manual testing.")
            for p in params:
                for payload in ("{{1336*7}}", "${1336*7}"):
                    r = c.get(base, params={p: payload})
                    _sleep()
                    tested += 1
                    if "9352" in r.text:
                        return True, (f"Live test: payload {payload} evaluated to 9352 via ?{p}=. "
                                       "SSTI CONFIRMED.")
        return False, (f"Live test: {tested} payload deliveries, no template evaluation. "
                        "Not vulnerable to this probe.")
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_crlf(base: str) -> Tuple[bool, str]:
    """GET with CRLF payload - check if the injected header lands in the response (GET only)."""
    try:
        params = ["next", "url", "redirect", "q"]
        for p in params:
            # Literal %0d%0a passed in the raw URL so it is not double-encoded
            url = base + "/?" + p + "=test%0d%0aX-Injected-Probe9:%20yes"
            with _client() as c:
                r = c.get(url)
            _sleep()
            header_names = [k.lower() for k in r.headers.keys()]
            if "x-injected-probe9" in header_names:
                return True, (f"Live test: CRLF payload via ?{p}= injected X-Injected-Probe9 "
                               "into response headers. CRLF injection CONFIRMED.")
        return False, (f"Live test: no injected header from {len(params)} params. "
                        "Not vulnerable to this probe.")
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_host_header(base: str) -> Tuple[bool, str]:
    """GET with a forged Host header - check for reflection in Location or body."""
    try:
        with _no_follow_client() as c:
            r = c.get(base, headers={"Host": "evil.example"})
        loc = r.headers.get("location", "")
        body = r.text
        if "evil.example" in loc:
            return True, (f"Live test: forged Host reflected in Location header: {loc[:80]}. "
                           "Password-reset poisoning risk: reset links may point at evil.example.")
        if "evil.example" in body:
            return True, ("Live test: forged Host 'evil.example' reflected in response body links. "
                           "Password-reset poisoning risk: reset links may point at evil.example.")
        return False, "Live test: forged Host header not reflected. Not vulnerable to this probe."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


# ---------------------------------------------------------------------------
# Second wave: info-disclosure and config probes (all GET/HEAD, read-only).
# Each detail carries the exact curl command that proves the finding,
# so Jay sees real commands and real output.
# ---------------------------------------------------------------------------

def probe_svn(base: str) -> Tuple[bool, str]:
    """GET /.svn/entries - check for Subversion metadata exposure."""
    try:
        with _client() as c:
            r = c.get(urljoin(base, "/.svn/entries"))
        body = (r.text or "")[:200]
        # Real .svn/entries starts with a numeric format-version line; reject
        # the HTML catch-all that merely happens to contain "dir" or "svn".
        is_entries = bool(re.match(r"^\s*\d+\s", body)) and "<html" not in body.lower()
        if r.status_code == 200 and is_entries and not _is_soft_404(base, r):
            return True, (f"Live test: /.svn/entries returned a Subversion entries file. SVN metadata exposed. "
                           f"Proved with: curl -s {base}/.svn/entries | head -5")
        return False, f"Live test: /.svn/entries returned {r.status_code} (no SVN entries payload)."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_ds_store(base: str) -> Tuple[bool, str]:
    """GET /.DS_Store - check for macOS metadata exposure (lists filenames)."""
    try:
        with _client() as c:
            r = c.get(urljoin(base, "/.DS_Store"))
        if r.status_code == 200 and r.content[:4] == b"Bud1":
            return True, (f"Live test: /.DS_Store returned 200 with Bud1 magic. "
                           f"Directory listing of filenames recoverable. "
                           f"Proved with: curl -s {base}/.DS_Store | xxd | head -3")
        return False, f"Live test: /.DS_Store returned {r.status_code}."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_backup_files(base: str) -> Tuple[bool, str]:
    """GET common backup names - check for downloadable archives/dumps."""
    names = ["/backup.zip", "/www.zip", "/site.zip", "/db.sql", "/backup.sql"]
    try:
        with _client() as c:
            for n in names:
                r = c.get(urljoin(base, n))
                _sleep()
                if r.status_code == 200 and len(r.content) > 100 and not _is_soft_404(base, r):
                    ct = r.headers.get("content-type", "").lower()
                    is_zip = r.content[:2] == b"PK"
                    is_gzip = r.content[:2] == b"\x1f\x8b"
                    is_sql = r.text[:200].lower().lstrip().startswith(
                        ("-- ", "insert ", "create table", "drop table", "/*"))
                    is_archive_ct = (any(x in ct for x in ("zip", "octet-stream", "x-sql",
                                     "gzip", "x-tar", "download")) and "html" not in ct)
                    # Only a real binary/dump signature counts - a 200 HTML page
                    # whose name contains "backup" is not a downloadable backup.
                    if is_zip or is_gzip or is_sql or is_archive_ct:
                        kind = ("zip archive" if is_zip else "gzip archive" if is_gzip
                                else "SQL dump" if is_sql else "binary archive")
                        return True, (f"Live test: {n} returned 200 ({kind}, "
                                       f"{len(r.content)} bytes). Downloadable backup. "
                                       f"Proved with: curl -sI {base}{n}")
        return False, f"Live test: checked {len(names)} backup names, none downloadable."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_phpinfo(base: str) -> Tuple[bool, str]:
    """GET /phpinfo.php - check for phpinfo disclosure."""
    try:
        with _client() as c:
            r = c.get(urljoin(base, "/phpinfo.php"))
        if r.status_code == 200 and not _is_soft_404(base, r) and ("phpinfo()" in r.text or "PHP Version" in r.text):
            m = re.search(r"PHP Version ([\d.]+)", r.text)
            ver = m.group(1) if m else "unknown"
            return True, (f"Live test: /phpinfo.php returned 200 (PHP {ver}). "
                           f"Full config disclosed - feeds CVE targeting. "
                           f"Proved with: curl -s {base}/phpinfo.php | grep -i 'PHP Version'")
        return False, f"Live test: /phpinfo.php returned {r.status_code}."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_server_status(base: str) -> Tuple[bool, str]:
    """GET /server-status - check for Apache status disclosure."""
    try:
        with _client() as c:
            r = c.get(urljoin(base, "/server-status"))
        if r.status_code == 200 and not _is_soft_404(base, r) and "Apache Status" in r.text:
            return True, (f"Live test: /server-status returned 200 with 'Apache Status'. "
                           f"Internal worker/request details visible. "
                           f"Proved with: curl -s {base}/server-status | head -10")
        return False, f"Live test: /server-status returned {r.status_code}."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_admin_panels(base: str) -> Tuple[bool, str]:
    """GET known admin panels - detection only, no login attempts."""
    panels = [
        ("/phpmyadmin/", "phpMyAdmin"),
        ("/adminer.php", "Adminer"),
        ("/wp-login.php", "wp-login.php"),
        ("/wp-admin/", "wp-admin"),
    ]
    try:
        found = []
        with _client() as c:
            for path, label in panels:
                r = c.get(urljoin(base, path))
                _sleep()
                low = r.text.lower()
                if r.status_code == 200 and not _is_soft_404(base, r) and (
                        "phpmyadmin" in low or "adminer" in low or
                        'type="password"' in low or "wp-login" in low):
                    found.append(f"{label} ({path})")
        if found:
            return True, (f"Live test: admin panels reachable (detection only, no login "
                           f"attempted): {', '.join(found)}. "
                           f"Proved with: curl -s -o /dev/null -w '%{{http_code}}' {base}/phpmyadmin/")
        return False, f"Live test: checked {len(panels)} admin panels, none reachable."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_cookie_flags(base: str) -> Tuple[bool, str]:
    """GET base - check Set-Cookie flags (read-only)."""
    try:
        with _client() as c:
            r = c.get(base)
        cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") \
            else [v for k, v in r.headers.items() if k.lower() == "set-cookie"]
        if not cookies:
            return False, "Live test: no Set-Cookie headers. Nothing to flag."
        weak = []
        for ck in cookies:
            low = ck.lower()
            name = ck.split("=")[0][:30]
            missing = []
            if "httponly" not in low:
                missing.append("HttpOnly")
            if "secure" not in low:
                missing.append("Secure")
            if "samesite" not in low:
                missing.append("SameSite")
            if missing:
                weak.append(f"{name} missing {', '.join(missing)}")
        if weak:
            return True, (f"Live test: {len(weak)} cookie(s) missing flags: "
                           f"{'; '.join(weak[:3])}. "
                           f"Proved with: curl -sI {base} | grep -i set-cookie")
        return False, f"Live test: {len(cookies)} cookie(s), all flags set."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_jwt_live(base: str) -> Tuple[bool, str]:
    """GET base - extract JWTs from the page and check alg offline (read-only)."""
    try:
        with _client() as c:
            r = c.get(base)
        tokens = re.findall(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", r.text)
        if not tokens:
            return False, "Live test: no JWTs found in the page. Nothing to check."
        for tok in tokens[:3]:
            header_b64 = tok.split(".")[0]
            header_b64 += "=" * (-len(header_b64) % 4)
            try:
                header = json.loads(base64.urlsafe_b64decode(header_b64).decode("utf-8", "replace"))
            except Exception:
                continue
            alg = str(header.get("alg", "")).lower()
            if alg == "none":
                return True, (f"Live test: JWT with alg:none found in page. "
                               f"Signature validation bypass likely. "
                               f"Proved with: curl -s {base} | grep -o 'eyJ[^\"'\"' ]*' | head -1")
            if alg in ("hs256", "hs384", "hs512"):
                return True, (f"Live test: JWT uses {alg} (symmetric). If the secret is weak "
                               f"or leaked, tokens can be forged - check for secret exposure. "
                               f"Proved with: curl -s {base} | grep -o 'eyJ[^\"'\"' ]*' | head -1")
        return False, f"Live test: {len(tokens)} JWT(s) found, algs look sane (checked header only)."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_debug_pprof(base: str) -> Tuple[bool, str]:
    """GET /debug/pprof/ - check for Go pprof exposure."""
    try:
        with _client() as c:
            r = c.get(urljoin(base, "/debug/pprof/"))
        if r.status_code == 200 and not _is_soft_404(base, r) and ("pprof" in r.text.lower() or "profiles:" in r.text):
            return True, (f"Live test: /debug/pprof/ returned 200. Go runtime profiles "
                           f"exposed (goroutine stacks, heap). "
                           f"Proved with: curl -s {base}/debug/pprof/ | head -10")
        return False, f"Live test: /debug/pprof/ returned {r.status_code}."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_actuator(base: str) -> Tuple[bool, str]:
    """GET /actuator/env - check for Spring actuator exposure."""
    try:
        with _client() as c:
            r = c.get(urljoin(base, "/actuator/env"))
        if r.status_code == 200 and not _is_soft_404(base, r) and ("propertySources" in r.text or "profiles" in r.text):
            return True, (f"Live test: /actuator/env returned 200 with propertySources. "
                           f"Spring environment (often secrets) disclosed. "
                           f"Proved with: curl -s {base}/actuator/env | head -c 300")
        return False, f"Live test: /actuator/env returned {r.status_code}."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_csp(base: str) -> Tuple[bool, str]:
    """GET base - inspect Content-Security-Policy header (read-only)."""
    try:
        with _client() as c:
            r = c.get(base)
        csp = r.headers.get("content-security-policy", "")
        if not csp:
            return True, "Live test: no Content-Security-Policy header set. No CSP protection."
        weak = [d for d in ("'unsafe-inline'", "'unsafe-eval'") if d in csp]
        wildcard = any(w in csp for w in ("default-src *", "script-src *", "default-src 'self' *"))
        if weak or wildcard:
            why = ", ".join(weak) if weak else "wildcard source"
            return True, f"Live test: CSP present but bypassable ({why}). Inline/remote script allowed."
        return False, "Live test: CSP header present with no obvious bypass directives."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_hsts(base: str) -> Tuple[bool, str]:
    """GET over http:// without following redirects - is plaintext served
    (no upgrade to https, no HSTS)? Read-only."""
    host = base.split("://", 1)[-1]
    try:
        with _no_follow_client() as c:
            r = c.get("http://" + host)
        loc = r.headers.get("location", "")
        if r.status_code in (301, 302, 303, 307, 308) and loc.startswith("https://"):
            return False, f"Live test: http:// returned {r.status_code} redirect to https. HTTPS enforced."
        if r.status_code < 400:
            return True, (f"Live test: http://{host} served {r.status_code} without redirect to https. "
                          f"Plaintext HTTP reachable (HSTS downgrade possible).")
        return False, f"Live test: http:// returned {r.status_code}."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_verbose_errors(base: str) -> Tuple[bool, str]:
    """GET a nonexistent path - check the error page for stack-trace / debug
    markers (read-only, no payloads)."""
    markers = ["traceback (most recent call last)", "stack trace", "at java.",
               "werkzeug", "django.core", "symfony", "nullpointerexception",
               "sqlstate", "exception in thread", ".py\", line "]
    try:
        with _client() as c:
            r = c.get(urljoin(base, "/this-path-should-not-exist-9a7f2c"))
        body = (r.text or "")[:20000].lower()
        hit = [m for m in markers if m in body]
        if hit:
            return True, f"Live test: error page leaked debug markers ('{hit[0]}'). Verbose errors enabled."
        return False, f"Live test: error page returned {r.status_code} with no stack-trace markers."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


def probe_debug_toolbar(base: str) -> Tuple[bool, str]:
    """GET base - look for dev debug toolbar / profiler markers in headers or
    body (read-only)."""
    markers = ["djdt", "django-debug-toolbar", "sf-toolbar", "symfony profiler",
               "werkzeug debugger", "x-debug-token", "__debug__/", "flask-debugtoolbar"]
    try:
        with _client() as c:
            r = c.get(base)
        body = (r.text or "")[:40000].lower()
        hdr = " ".join(f"{k}:{v}" for k, v in r.headers.items()).lower()
        hit = [m for m in markers if m in body or m in hdr]
        if hit:
            return True, f"Live test: debug toolbar/profiler marker '{hit[0]}' present. Dev tooling in production."
        return False, "Live test: no debug toolbar/profiler markers found."
    except Exception as e:
        return False, f"Live test failed: {str(e)[:100]}"


# ---------------------------------------------------------------------------
# Orchestrator: run every candidate's real probe, return what worked.
# ---------------------------------------------------------------------------

PROBE_MAP = {
    "git-exposed": lambda base, c: probe_git_head(base),
    "env-secrets": lambda base, c: probe_env(base),
    "sqli": lambda base, c: probe_sqli(base),
    "cors": lambda base, c: probe_cors(base),
    "s3-open": lambda base, c: probe_s3(_s3_url(c) or base),
    "clickjack": lambda base, c: probe_clickjack(base),
    "cms-cve": lambda base, c: probe_wordpress(base),
    "bola": lambda base, c: probe_bola(base),
    "jwt": lambda base, c: probe_jwt_offline(),
    "shadow-it": lambda base, c: probe_shadow_it(_shadow_host(c) or base),
    "xss-reflected": lambda base, c: probe_xss(base),
    "open-redirect": lambda base, c: probe_open_redirect(base),
    "ssrf": lambda base, c: probe_ssrf(base),
    "idor": lambda base, c: probe_idor(base),
    "auth-bypass": lambda base, c: probe_auth_bypass(base),
    "dir-traversal": lambda base, c: probe_dir_traversal(base),
    "xxe": lambda base, c: probe_xxe(base),
    "ssti": lambda base, c: probe_ssti(base),
    "crlf": lambda base, c: probe_crlf(base),
    "host-header": lambda base, c: probe_host_header(base),
    "svn-exposed": lambda base, c: probe_svn(base),
    "ds-store": lambda base, c: probe_ds_store(base),
    "backup-files": lambda base, c: probe_backup_files(base),
    "phpinfo": lambda base, c: probe_phpinfo(base),
    "server-status": lambda base, c: probe_server_status(base),
    "admin-panels": lambda base, c: probe_admin_panels(base),
    "cookie-flags": lambda base, c: probe_cookie_flags(base),
    "jwt-live": lambda base, c: probe_jwt_live(base),
    "debug-pprof": lambda base, c: probe_debug_pprof(base),
    "actuator-env": lambda base, c: probe_actuator(base),
    "csp-bypass": lambda base, c: probe_csp(base),
    "hsts-downgrade": lambda base, c: probe_hsts(base),
    "verbose-errors": lambda base, c: probe_verbose_errors(base),
    "debug-toolbar": lambda base, c: probe_debug_toolbar(base),
}

# Candidates that are real findings but can't be confirmed with an HTTP
# GET/HEAD probe (different protocol, or require a method the safe tester
# won't send). These were already evidenced by the scan itself, so they get
# an honest note rather than reading as a failed probe.
NO_HTTP_PROBE = {
    "smtp-cleartext-auth": "SMTP-level finding, not reachable over HTTP",
    "tls-deprecated": "TLS handshake finding, not reachable over HTTP",
    "ip-blocklisted": "DNS blocklist finding, not reachable over HTTP",
    "typosquat": "DNS/registration finding, not reachable over HTTP",
    "graphql-introspection": "needs a POST introspection query (probes are GET/HEAD only)",
    "http-trace": "needs the TRACE method (probes are GET/HEAD only)",
}


def _s3_url(candidate: Dict) -> str:
    m = re.search(r"https?://[a-z0-9.\-]+\.s3[.\-][a-z0-9.\-/]+", candidate.get("poc_code", ""))
    return m.group(0) if m else ""


def _shadow_host(candidate: Dict) -> str:
    m = re.search(r"https://([a-z0-9.\-]+)", candidate.get("poc_code", ""))
    return m.group(1) if m else ""


def _reachable_base(base: str) -> str:
    """Pick the scheme that actually connects.

    `base` already carries a scheme (default https). If https fails at the
    connection level, retry as http so plain-HTTP-only hosts still get
    probed instead of every probe failing and reporting "no finding". Any
    HTTP response (even 4xx/5xx) counts as a reachable scheme.
    """
    candidates = [base]
    if base.startswith("https://"):
        candidates.append("http://" + base[len("https://"):])
    for cand in candidates:
        try:
            with _client() as c:
                c.get(cand)
            return cand
        except Exception:
            continue
    return base


def run_real_tests(base_url: str, candidates: List[Dict]) -> Dict:
    """Run real (safe, non-destructive) detection probes against the target.

    Only GET/HEAD. Rate-limited. Returns which candidates were confirmed.
    """
    base = (base_url or "").strip().rstrip("/")
    # Domain/IP targets normalize to a bare host (no scheme); httpx rejects a
    # scheme-less URL, which would make every probe throw and report works=False
    # ("no finding") even when advise() produced real candidates. Default to https.
    if base and "://" not in base:
        base = "https://" + base
    base = base or "https://example.com"
    # Fall back to http:// if https doesn't connect, so HTTP-only hosts probe.
    base = _reachable_base(base)
    results = []
    for c in candidates:
        fn = PROBE_MAP.get(c["id"])
        if not fn:
            note = NO_HTTP_PROBE.get(c["id"])
            detail = (f"Evidenced by the scan; not independently re-probed — {note}."
                      if note else "No safe probe available for this candidate.")
            results.append({
                "id": c["id"], "name": c["name"], "severity": c["severity"],
                "confidence": c["confidence"], "works": False,
                "detail": detail,
                "poc_code": c["poc_code"], "poc_lang": c["poc_lang"],
                "why_viable": c["why_viable"], "remediation": c["remediation"],
            })
            continue
        try:
            works, detail = fn(base, c)
        except Exception as e:
            works, detail = False, f"Probe error: {str(e)[:120]}"
        results.append({
            "id": c["id"], "name": c["name"], "severity": c["severity"],
            "confidence": c["confidence"], "works": works, "detail": detail,
            "poc_code": c["poc_code"], "poc_lang": c["poc_lang"],
            "why_viable": c["why_viable"], "remediation": c["remediation"],
        })
        _sleep()
    working = [r for r in results if r["works"]]
    return {
        "target": base,
        "total_tested": len(results),
        "working_count": len(working),
        "results": results,
        "working": working,
        "disclaimer": ("Real detection probes sent to the target. All probes are "
                       "read-only (GET/HEAD only), rate-limited, and non-destructive. "
                       "Only test targets you are authorized to test."),
    }
