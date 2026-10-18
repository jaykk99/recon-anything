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
