"""WAF / protection fingerprinting.

Vendor-specific signatures for Cloudflare, Akamai, Imperva, AWS WAF /
CloudFront, Sucuri, DataDome, PerimeterX/HUMAN, Kasada, Fastly, Azure WAF,
F5 BIG-IP/ASM, ModSecurity, Distil, and Reblaze.

classify_response() tells apart:
  clean        - normal response (vendor noted if headers say so)
  waf          - vendor-identified WAF block, or generic block wording
  rate-limit   - 429, or 503 with retry wording / rate-limit markers
  js-challenge - JS challenge / captcha interstitial page
  blocked      - 403 with no WAF fingerprint (generic access denied)
  not-found    - 404 / 410
  server-error - 5xx from the origin with no protection markers

Detection only. Never attempts to bypass, solve challenges, or evade.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import httpx

# Verdict kinds. "blocked" = access denied with no vendor fingerprint;
# "waf" = vendor-identified (or explicit WAF wording).
CLEAN = "clean"
WAF = "waf"
RATE_LIMIT = "rate-limit"
JS_CHALLENGE = "js-challenge"
BLOCKED = "blocked"
NOT_FOUND = "not-found"
SERVER_ERROR = "server-error"

# Kinds that mean "protection is fighting back" - the ones that trigger
# graceful backoff on the host.
BLOCK_KINDS = (WAF, RATE_LIMIT, JS_CHALLENGE, BLOCKED)


@dataclass
class WafVerdict:
    kind: str
    vendor: Optional[str] = None
    evidence: str = ""


# (header name, value substring or None, vendor)
# A None value means the header's mere presence attributes the vendor.
VENDOR_HEADERS: List[Tuple[str, Optional[str], str]] = [
    # Cloudflare
    ("cf-ray", None, "Cloudflare"),
    ("cf-mitigated", None, "Cloudflare"),
    ("cf-cache-status", None, "Cloudflare"),
    ("cf-bgs", None, "Cloudflare"),
    ("cf-apo-via", None, "Cloudflare"),
    ("cf-ew-via", None, "Cloudflare"),
    ("cf-warp-tag", None, "Cloudflare"),
    ("cdn-loop", "cloudflare", "Cloudflare"),
    ("server", "cloudflare", "Cloudflare"),
    # Akamai
    ("x-akamai-transformed", None, "Akamai"),
    ("akamai-origin-hop", None, "Akamai"),
    ("x-akamaized", None, "Akamai"),
    ("x-akamai-request-id", None, "Akamai"),
    ("server", "akamai", "Akamai"),
    # Imperva / Incapsula
    ("x-iinfo", None, "Imperva"),
    ("x-cdn", "imperva", "Imperva"),
    # AWS WAF / CloudFront / Shield
    ("x-amz-cf-id", None, "AWS WAF / CloudFront"),
    ("x-amz-cf-pop", None, "AWS WAF / CloudFront"),
    ("x-amzn-requestid", None, "AWS WAF"),
    ("x-amzn-remapped-connection", None, "AWS WAF"),
    # Azure WAF / Front Door
    ("x-azure-ref", None, "Azure WAF"),
    ("x-azure-requestchain", None, "Azure WAF"),
    ("x-azure-socketip", None, "Azure WAF"),
    # Sucuri
    ("x-sucuri-id", None, "Sucuri"),
    ("x-sucuri-cache", None, "Sucuri"),
    # DataDome
    ("x-datadome", None, "DataDome"),
    # PerimeterX / HUMAN
    ("x-perimeterx", None, "PerimeterX / HUMAN"),
    # Kasada
    ("x-kasada", None, "Kasada"),
    ("x-kpsdk-ct", None, "Kasada"),
    # Fastly (often fronts a WAF)
    ("x-fastly", None, "Fastly"),
    ("fastly-restarts", None, "Fastly"),
    ("server", "fastly", "Fastly"),
    # F5 BIG-IP / ASM
    ("x-waf-event", None, "F5 BIG-IP"),
    # ModSecurity
    ("x-mod-security", None, "ModSecurity"),
    # Distil Networks
    ("x-distil-cs", None, "Distil"),
    ("x-distil-r", None, "Distil"),
    # Barracuda
    ("x-barracuda", None, "Barracuda"),
    ("barra_counter_session", None, "Barracuda"),
    # Citrix / NetScaler
    ("x-nsc", None, "Citrix NetScaler"),
    ("citrix_ns_id", None, "Citrix NetScaler"),
    ("ns_af", "citrix", "Citrix NetScaler"),
    # Radware
    ("x-rdwr", None, "Radware"),
    # Fortinet FortiWeb
    ("x-fw-version", None, "Fortinet FortiWeb"),
    ("fortiwaf", None, "Fortinet FortiWeb"),
    # Palo Alto
    ("x-pan", None, "Palo Alto"),
    # Check Point
    ("x-checkpoint", None, "Check Point"),
    # Cloudbric
    ("x-cloudbric", None, "Cloudbric"),
    # StackPath
    ("x-hw", None, "StackPath"),
    ("x-stackpath", None, "StackPath"),
    # KeyCDN
    ("x-keycdn", None, "KeyCDN"),
    # BunnyCDN
    ("cdn-bunny", None, "BunnyCDN"),
    ("x-bunny", None, "BunnyCDN"),
    # G-Core
    ("x-gcore", None, "G-Core"),
    # Edgio (formerly Limelight)
    ("x-edg", None, "Edgio"),
    ("x-ll", None, "Edgio"),
    # Wordfence
    ("x-wf", None, "Wordfence"),
    # ShieldSquare
    ("x-shieldsquare", None, "ShieldSquare"),
    # Arkose Labs
    ("x-arkose", None, "Arkose Labs"),
    # Shape Security
    ("x-shape", None, "Shape Security"),
    # Reblaze (already in body markers, add header)
    ("x-reblaze", None, "Reblaze"),
    # Signal Sciences
    ("x-sigsci", None, "Signal Sciences"),
    # ThreatX
    ("x-threatx", None, "ThreatX"),
    # Wallarm
    ("x-wallarm", None, "Wallarm"),
    # Generic WAF telltales
    ("x-waf", None, "Generic WAF"),
    ("x-protected-by", None, "Generic WAF"),
    ("x-firewall", None, "Generic WAF"),
]

# (cookie name, vendor) - matched against the Set-Cookie header blob.
VENDOR_COOKIES: List[Tuple[str, str]] = [
    ("__cf_bm", "Cloudflare"),
    ("cf_clearance", "Cloudflare"),
    ("__cfruid", "Cloudflare"),
    ("cf_use_ob", "Cloudflare"),
    ("_cfuvid", "Cloudflare"),
    ("_abck", "Akamai"),
    ("bm_sv", "Akamai"),
    ("bm_sz", "Akamai"),
    ("ak_bmsc", "Akamai"),
    ("aws-waf-token", "AWS WAF"),
    ("incap_ses_", "Imperva"),
    ("visid_incap_", "Imperva"),
    ("_px3", "PerimeterX / HUMAN"),
    ("_pxvid", "PerimeterX / HUMAN"),
    ("pxcts", "PerimeterX / HUMAN"),
    ("__kasada", "Kasada"),
    ("kpsdk", "Kasada"),
    ("datadome", "DataDome"),
    ("bigipserver", "F5 BIG-IP"),
    ("f5_cspm", "F5 BIG-IP"),
    ("ts01", "F5 BIG-IP"),
    ("as_av", "F5 BIG-IP"),
    ("sucuri_cloudproxy", "Sucuri"),
    ("_barracuda_", "Barracuda"),
    ("ns_af", "Citrix NetScaler"),
    ("citrix_ns_id", "Citrix NetScaler"),
    ("f5avr", "F5 BIG-IP"),
    ("x-csrf", "Generic WAF"),
]

# (body marker, vendor, is_challenge_page)
# Challenge markers describe interstitial/captcha pages; plain markers
# describe vendor block pages.
VENDOR_BODY: List[Tuple[str, str, bool]] = [
    # Cloudflare challenge + block pages
    ("just a moment", "Cloudflare", True),
    ("checking your browser", "Cloudflare", True),
    ("challenge-platform", "Cloudflare", True),
    ("window._cf_chl_opt", "Cloudflare", True),
    ("cf-challenge", "Cloudflare", True),
    ("cf_chl", "Cloudflare", True),
    ("attention required", "Cloudflare", True),
    ("cloudflare ray id", "Cloudflare", False),
    ("error code: 1015", "Cloudflare", False),   # rate limited
    ("error code: 1020", "Cloudflare", False),   # access denied (firewall rule)
    ("error code: 1010", "Cloudflare", False),   # bad browser
    ("error code: 1006", "Cloudflare", False),   # banned IP
    ("error code: 1009", "Cloudflare", False),   # banned country
    ("error code: 1012", "Cloudflare", False),   # captcha bypass
    ("error code: 1101", "Cloudflare", False),   # rendering error
    # Akamai block pages
    ("reference #", "Akamai", False),
    ("denied by ip", "Akamai", False),
    ("akamai edge", "Akamai", False),
    ("access denied", "Akamai", False),
    # Imperva / Incapsula
    ("incapsula", "Imperva", False),
    ("imperva", "Imperva", False),
    ("incident id", "Imperva", False),
    ("_incapsula_resource", "Imperva", True),
    # AWS WAF / CloudFront
    ("generated by cloudfront", "AWS WAF / CloudFront", False),
    ("the request could not be satisfied", "AWS WAF / CloudFront", False),
    ("request blocked", "AWS WAF", False),
    ("aws waf", "AWS WAF", False),
    # Azure
    ("azure front door", "Azure WAF", False),
    ("azure web application firewall", "Azure WAF", False),
    # Sucuri
    ("sucuri website firewall", "Sucuri", False),
    ("access denied - sucuri", "Sucuri", False),
    # DataDome
    ("datadome", "DataDome", True),
    ("geo.captcha-delivery.com", "DataDome", True),
    ("device check", "DataDome", True),
    # PerimeterX / HUMAN
    ("perimeterx", "PerimeterX / HUMAN", True),
    ("press & hold", "PerimeterX / HUMAN", True),
    ("please verify you are a human", "PerimeterX / HUMAN", True),
    # Kasada
    ("kasada", "Kasada", True),
    # Fastly
    ("fastly error", "Fastly", False),
    # F5
    ("the requested url was rejected", "F5 BIG-IP", False),
    ("request rejected", "F5 BIG-IP", False),
    ("big-ip", "F5 BIG-IP", False),
    ("f5 networks", "F5 BIG-IP", False),
    # ModSecurity
    ("mod_security", "ModSecurity", False),
    ("not acceptable!", "ModSecurity", False),
    # Distil
    ("distil networks", "Distil", True),
    ("distil_r_captcha", "Distil", True),
    # Reblaze
    ("reblaze", "Reblaze", False),
    # Generic WAF wording (no vendor)
    ("web application firewall", None, False),  # type: ignore
    ("blocked by", None, False),  # type: ignore
]

# Generic challenge markers when no vendor matched.
GENERIC_CHALLENGE_MARKERS = (
    "captcha",
    "recaptcha",
    "cf-turnstile",
    "hcaptcha",
    "verify you are human",
    "are you a robot",
    "enable javascript",
    "javascript is required",
)

# Generic "you are blocked" wording with no vendor attribution.
GENERIC_BLOCK_MARKERS = (
    "request blocked",
    "access denied",
    "forbidden",
    "ip address has been blocked",
    "your ip has been blocked",
)

# Statuses whose bodies are worth scanning for protection markers.
# 404s and clean 2xx are skipped for speed (headers still checked).
_BODY_SCAN_STATUSES = frozenset({400, 401, 403, 405, 406, 419, 429, 501, 503})


def detect_vendors(headers: Dict[str, str], cookies: str = "") -> List[str]:
    """Vendor names attributed from headers/cookies, in match order."""
    found: List[str] = []
    for name, val, vendor in VENDOR_HEADERS:
        hv = headers.get(name)
        if hv is None:
            continue
        if val is None or val.lower() in hv.lower():
            if vendor not in found:
                found.append(vendor)
    cl = (cookies or "").lower()
    for cname, vendor in VENDOR_COOKIES:
        if cname.lower() in cl and vendor not in found:
            found.append(vendor)
    return found


def classify_response(resp: httpx.Response, scan_body: bool = True) -> WafVerdict:
    """Classify one HTTP response. Never raises."""
    try:
        return _classify(resp, scan_body)
    except Exception:
        return WafVerdict(CLEAN, None, "classification failed")


def _classify(resp: httpx.Response, scan_body: bool) -> WafVerdict:
    status = resp.status_code
    headers = {k.lower(): v for k, v in resp.headers.items()}
    cookies = resp.headers.get("set-cookie", "")

    vendors = detect_vendors(headers, cookies)
    vendor = vendors[0] if vendors else None

    body = ""
    if scan_body and status in _BODY_SCAN_STATUSES:
        try:
            body = (resp.text or "")[:200000].lower()
        except Exception:
            body = ""

    body_vendor: Optional[str] = None
    challenge = False
    generic_block = False
    if body:
        for marker, mv, is_ch in VENDOR_BODY:
            if marker in body:
                if mv and body_vendor is None:
                    body_vendor = mv
                if is_ch:
                    challenge = True
        if any(m in body for m in GENERIC_CHALLENGE_MARKERS):
            challenge = True
        if any(m in body for m in GENERIC_BLOCK_MARKERS):
            generic_block = True
    vendor = vendor or body_vendor
    ev = f"status {status}"
    if vendor:
        ev += f", vendor {vendor}"

    if status == 429:
        return WafVerdict(RATE_LIMIT, vendor,
                          ev + " - explicit 429 rate limit")
    if status in (404, 410):
        return WafVerdict(NOT_FOUND, vendor, ev + " - page not found")
    if status == 503:
        blob = " ".join(headers.keys()) + " " + body
        if "retry-after" in headers or "retry" in blob or "rate" in blob:
            return WafVerdict(RATE_LIMIT, vendor,
                              ev + " - 503 with retry wording")
        if challenge or vendor:
            return WafVerdict(JS_CHALLENGE, vendor,
                              ev + " - 503 challenge/interstitial page")
        return WafVerdict(SERVER_ERROR, vendor,
                          ev + " - origin unavailable")
    if challenge:
        return WafVerdict(JS_CHALLENGE, vendor,
                          ev + " - challenge/captcha page")
    if status in (400, 401, 403, 405, 406, 419, 501):
        if vendor:
            return WafVerdict(WAF, vendor, ev + " - vendor block page")
        if generic_block:
            return WafVerdict(WAF, None, ev + " - generic block wording")
        return WafVerdict(BLOCKED, None,
                          ev + " - access denied, no WAF fingerprint")
    if status >= 500:
        return WafVerdict(SERVER_ERROR, vendor,
                          ev + " - origin server error")
    # 2xx/3xx: clean, but keep vendor attribution for reporting
    # ("behind Cloudflare, not blocking").
    return WafVerdict(CLEAN, vendor, ev + " - normal response")
