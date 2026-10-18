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
    return httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=True,
        trust_env=False,
        headers={"User-Agent": USER_AGENT},
    )


def _sleep():
    time.sleep(REQUEST_DELAY)


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
    """HEAD /.env - check if env file is served (read-only, no body read)."""
    try:
        with _client() as c:
            r = c.head(urljoin(base, "/.env"))
        if r.status_code == 200:
            ct = r.headers.get("content-type", "")
            return True, f"Live test: /.env returned 200 ({ct}). Secrets may be exposed."
        return False, f"Live test: /.env returned {r.status_code}."
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
        body = probed.text.lower()
        hit = any(s in body for s in err_sigs)
        if probed.status_code == 500 or hit:
            return True, (f"Live test: quote probe on ?{param}= returned "
                          f"{probed.status_code} with SQL error text. Injection likely.")
        return False, (f"Live test: quote probe returned {probed.status_code}, "
                        "no SQL error. Not injectable via this probe.")
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
        if r.status_code == 200:
            return True, "Live test: /wp-json/wp/v2/ returned 200. WP version disclosable."
        return False, f"Live test: /wp-json/ returned {r.status_code}."
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
        if r1.status_code == 200 and r2.status_code == 200 and len(r1.text) > 50 and len(r2.text) > 50:
            return True, (f"Live test: both {patterns[0]} and {patterns[1]} returned 200 "
                          "with content. Possible BOLA - verify with authorized session.")
        return False, (f"Live test: IDs returned {r1.status_code}/{r2.status_code}. "
                        "No clear BOLA signal.")
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
    return httpx.Client(
        timeout=TIMEOUT,
        follow_redirects=False,
        trust_env=False,
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
        with _client() as c:
            for p in paths:
                r = c.get(urljoin(base + "/", p.lstrip("/")))
                _sleep()
                if r.status_code == 200:
                    low = r.text.lower()
                    if not any(m in low for m in login_markers):
                        return True, (f"Live test: {p} returned 200 with no login form markers. "
                                       "Admin area may be reachable without auth.")
        return False, (f"Live test: checked {len(paths)} admin paths, all gated or missing. "
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
}


def _s3_url(candidate: Dict) -> str:
    m = re.search(r"https?://[a-z0-9.\-]+\.s3[.\-][a-z0-9.\-/]+", candidate.get("poc_code", ""))
    return m.group(0) if m else ""


def _shadow_host(candidate: Dict) -> str:
    m = re.search(r"https://([a-z0-9.\-]+)", candidate.get("poc_code", ""))
    return m.group(1) if m else ""


def run_real_tests(base_url: str, candidates: List[Dict]) -> Dict:
    """Run real (safe, non-destructive) detection probes against the target.

    Only GET/HEAD. Rate-limited. Returns which candidates were confirmed.
    """
    base = (base_url or "").rstrip("/") or "https://example.com"
    results = []
    for c in candidates:
        fn = PROBE_MAP.get(c["id"])
        if not fn:
            results.append({
                "id": c["id"], "name": c["name"], "severity": c["severity"],
                "confidence": c["confidence"], "works": False,
                "detail": "No safe probe available for this candidate.",
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
