"""Per-host deep probing for live subdomains.

Subdomain enumeration finds the attack surface and liveness tells you
which hosts answer - but neither tells you what a host EXPOSES. A scan of
a big target (crypto.com: ~569 subdomains, ~210 live) was reducing each
live host to a title string. This module takes a live host and runs a
small set of high-signal, content-verified checks so "210 live hosts"
becomes "here is what each host actually leaks":

  CORS - send Origin: https://evil.example.com and read the response.
    ACAO reflecting that arbitrary origin WITH
    Access-Control-Allow-Credentials: true is a real cross-origin
    data-theft vuln (high). ACAO reflecting it without credentials is
    lower risk (low). ACAO: * without credentials is the normal
    public-API config and is NOT a finding. (The old CORS detector
    guessed from source; this verifies from the live response - the
    reports showed its guesses were all false.)

  security headers - missing HSTS / CSP / X-Frame-Options /
    X-Content-Type-Options / Referrer-Policy (low: hardening gaps).

  exposed files - GET a curated high-value path set and run the content
    verifier (exposure_signatures.confirm_exposure): a confirmed .git /
    .env / backup / API schema, proof-backed, per host.

  cookies - Set-Cookie missing Secure / HttpOnly (low).

fetch is injected: fetch(url, extra_headers) -> (status, headers, body)
where headers is a case-insensitive-readable dict. Pure analyzers are
unit-tested; the orchestrator is tested with a fake fetch. No network in
this module - the caller owns the HTTP client and its SSRF guard.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple

from .plugins.exposure_signatures import confirm_exposure

EVIL_ORIGIN = "https://evil.example.com"

# High-signal paths worth a GET on every live host. Kept short on
# purpose: each is content-verified, so a hit is a real finding, and a
# small list keeps per-host cost low across hundreds of hosts.
EXPOSURE_PATHS = (
    "/.git/HEAD", "/.git/config", "/.env", "/.svn/entries",
    "/.DS_Store", "/config.json", "/appsettings.json",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/server-status", "/.aws/credentials", "/phpinfo.php",
)

_SEC_HEADERS = {
    "strict-transport-security": "HSTS (allows TLS downgrade / SSL strip)",
    "content-security-policy": "CSP (no XSS/content-injection defense)",
    "x-frame-options": "X-Frame-Options (clickjacking)",
    "x-content-type-options": "X-Content-Type-Options (MIME sniffing)",
    "referrer-policy": "Referrer-Policy (referrer leakage)",
}


def _get(headers: Dict[str, str], name: str) -> str:
    """Case-insensitive header read."""
    name = name.lower()
    for k, v in (headers or {}).items():
        if k.lower() == name:
            return v or ""
    return ""


def analyze_cors(origin_sent: str, headers: Dict[str, str]
                 ) -> Optional[Dict[str, Any]]:
    """Verdict on a CORS response to a cross-origin request. None = safe
    / not a finding."""
    acao = _get(headers, "access-control-allow-origin").strip()
    acac = _get(headers, "access-control-allow-credentials").strip().lower()
    creds = acac == "true"
    if not acao:
        return None
    if acao == origin_sent:
        if creds:
            return {"severity": "high",
                    "detail": (f"reflects arbitrary Origin ({origin_sent}) "
                               "with credentials: any site can read "
                               "authenticated responses (cross-origin "
                               "data theft)"),
                    "proof": f"ACAO: {acao}; ACAC: true"}
        return {"severity": "low",
                "detail": (f"reflects arbitrary Origin ({origin_sent}) "
                           "without credentials: lower risk, but confirm "
                           "no sensitive data is returned without cookies"),
                "proof": f"ACAO: {acao}; ACAC not true"}
    if acao.lower() == "null" and creds:
        return {"severity": "high",
                "detail": ("ACAO: null with credentials: reachable from a "
                           "sandboxed iframe / data: URL"),
                "proof": "ACAO: null; ACAC: true"}
    if acao == "*" and creds:
        # Browsers reject * + credentials, but it signals a broken CORS
        # layer worth flagging.
        return {"severity": "medium",
                "detail": ("ACAO: * with ACAC: true: spec-invalid CORS "
                           "config, indicates a broken allow-origin layer"),
                "proof": "ACAO: *; ACAC: true"}
    return None  # ACAO: * without creds = normal public API, not a finding


def analyze_security_headers(headers: Dict[str, str]) -> List[str]:
    """Missing hardening headers, as human labels."""
    missing = []
    for h, label in _SEC_HEADERS.items():
        if not _get(headers, h):
            missing.append(label)
    return missing


def analyze_cookies(headers: Dict[str, str]) -> List[str]:
    """Set-Cookie flags worth flagging (Secure / HttpOnly)."""
    issues = []
    for k, v in (headers or {}).items():
        if k.lower() != "set-cookie":
            continue
        low = v.lower()
        name = v.split("=", 1)[0].strip()[:40]
        if "secure" not in low:
            issues.append(f"cookie '{name}' missing Secure")
        if "httponly" not in low:
            issues.append(f"cookie '{name}' missing HttpOnly")
    return issues


FetchFn = Callable[[str, Dict[str, str]], Tuple[int, Dict[str, str], str]]


def deep_probe_host(host: str, fetch: FetchFn, scheme: str = "https"
                    ) -> List[Dict[str, Any]]:
    """Run the deep checks against one live host. `fetch(url, headers)`
    returns (status, headers, body); it must raise nothing (the caller
    catches network errors and returns a sentinel). Returns a list of
    finding dicts; never raises."""
    base = f"{scheme}://{host}"
    out: List[Dict[str, Any]] = []

    # Root request with a hostile Origin: drives CORS + reads headers.
    try:
        status, headers, _ = fetch(base + "/", {"Origin": EVIL_ORIGIN})
    except Exception:
        status, headers = 0, {}
    if status:
        cors = analyze_cors(EVIL_ORIGIN, headers)
        if cors:
            out.append({"host": host, "type": "cors", **cors})
        for label in analyze_security_headers(headers):
            out.append({"host": host, "type": "security_header",
                        "severity": "low",
                        "detail": f"missing {label}", "proof": ""})
        for issue in analyze_cookies(headers):
            out.append({"host": host, "type": "cookie", "severity": "low",
                        "detail": issue, "proof": ""})

    # Content-verified exposed files.
    for path in EXPOSURE_PATHS:
        try:
            st, hd, body = fetch(base + path, {})
        except Exception:
            continue
        if st not in (200, 201, 206) or not body:
            continue
        conf = confirm_exposure(path, st, body, hd)
        if conf:
            out.append({"host": host, "type": "exposed_file",
                        "severity": conf["severity"],
                        "detail": f"{conf['label']} at {path}",
                        "proof": conf["proof"], "path": path,
                        "verified": True})
    return out


async def deep_probe_host_async(host: str, afetch, scheme: str = "https"
                                ) -> List[Dict[str, Any]]:
    """Async twin of deep_probe_host: `afetch(url, headers)` is awaited
    and returns (status, headers, body). Same checks, same output shape;
    it reuses the pure analyzers so the logic stays the one that's unit
    tested. Never raises."""
    base = f"{scheme}://{host}"
    out: List[Dict[str, Any]] = []
    try:
        status, headers, _ = await afetch(base + "/", {"Origin": EVIL_ORIGIN})
    except Exception:
        status, headers = 0, {}
    if status:
        cors = analyze_cors(EVIL_ORIGIN, headers)
        if cors:
            out.append({"host": host, "type": "cors", **cors})
        for label in analyze_security_headers(headers):
            out.append({"host": host, "type": "security_header",
                        "severity": "low", "detail": f"missing {label}",
                        "proof": ""})
        for issue in analyze_cookies(headers):
            out.append({"host": host, "type": "cookie", "severity": "low",
                        "detail": issue, "proof": ""})
    for path in EXPOSURE_PATHS:
        try:
            st, hd, body = await afetch(base + path, {})
        except Exception:
            continue
        if st not in (200, 201, 206) or not body:
            continue
        conf = confirm_exposure(path, st, body, hd)
        if conf:
            out.append({"host": host, "type": "exposed_file",
                        "severity": conf["severity"],
                        "detail": f"{conf['label']} at {path}",
                        "proof": conf["proof"], "path": path,
                        "verified": True})
    return out
