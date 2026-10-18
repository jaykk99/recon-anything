"""Anti-blocking helpers for authorized scans.

For authorized testing only. Evasion here means completing an authorized
scan without being blocked, not attacking. These helpers rotate realistic
browser fingerprints, add timing jitter, and encode payloads so defensive
servers do not flag the scan as bot traffic. Never try to solve JS
challenges or captchas: detect them and report back instead.

Proxy support: every HTTP client is built through app.net, which honors
HTTP_PROXY and HTTPS_PROXY environment variables, so no code is needed
here for proxies.
"""
from __future__ import annotations

import random
import re
from typing import Dict, List
from urllib.parse import quote

# Real, current browser User-Agent strings (checked Oct 2026).
BROWSER_UAS: List[str] = [
    # Chrome 155 on Windows 11 (reports as Windows 10)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
    # Chrome 155 on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
    # Chrome 155 on Android
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/155.0.0.0 Mobile Safari/537.36",
    # Edge 155 on Windows (Chromium based)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 Edg/155.0.2353.36",
    # Edge 155 on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 Edg/155.0.2353.36",
    # Firefox 148 on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) "
    "Gecko/20100101 Firefox/148.0",
    # Firefox 148 on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:148.0) "
    "Gecko/20100101 Firefox/148.0",
    # Firefox 148 on Android
    "Mozilla/5.0 (Android 16; Mobile; rv:148.0) "
    "Gecko/148.0 Firefox/148.0",
    # Safari 26 on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/26.1 Safari/605.1.15",
    # Safari on iPhone (iOS 18)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Mobile/15E148 "
    "Safari/604.1",
]

_CHROME_LIKE = ("Chrome", "CriOS", "Edg")


def rotate_ua() -> str:
    """Return a random real browser User-Agent."""
    return random.choice(BROWSER_UAS)


def browser_headers(ua: str) -> Dict[str, str]:
    """Realistic request headers matching the given User-Agent."""
    is_chrome_like = any(tag in ua for tag in _CHROME_LIKE)
    is_firefox = "Firefox" in ua
    headers: Dict[str, str] = {
        "User-Agent": ua,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8"
            if not is_firefox
            else "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": random.choice(
            ["en-US,en;q=0.9", "en-US,en;q=0.8,fr;q=0.7", "en-CA,en;q=0.9"]
        ),
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    if is_chrome_like:
        major = re.search(r"(?:Chrome|CriOS|Edg)/(\d+)", ua)
        brand_version = major.group(1) if major else "155"
        headers["Sec-Ch-Ua"] = (
            f'"Chromium";v="{brand_version}", '
            f'"Google Chrome";v="{brand_version}", '
            f'"Not=A?Brand";v="99"'
        )
        headers["Sec-Ch-Ua-Mobile"] = "?1" if "Mobile" in ua else "?0"
        headers["Sec-Ch-Ua-Platform"] = (
            '"Windows"'
            if "Windows" in ua
            else '"macOS"'
            if "Macintosh" in ua
            else '"Android"'
            if "Android" in ua
            else '"iOS"'
        )
        headers["Sec-Fetch-Dest"] = "document"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-Site"] = "none"
        headers["Sec-Fetch-User"] = "?1"
    elif is_firefox:
        headers["Sec-Fetch-Dest"] = "document"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-Site"] = "none"
        headers["Sec-Fetch-User"] = "?1"
    return headers


def random_xff() -> str:
    """Random public IPv4 for X-Forwarded-For rotation."""
    while True:
        octets = [random.randint(1, 254) for _ in range(4)]
        first = octets[0]
        # Skip private / reserved ranges
        if first in (10, 127):
            continue
        if first == 172 and 16 <= octets[1] <= 31:
            continue
        if first == 192 and octets[1] == 168:
            continue
        return ".".join(str(o) for o in octets)


_ENCODE_METHODS = ("url", "double-url", "unicode", "mixed-case")


def encode_payload(payload: str, method: str) -> str:
    """Encode a payload with the given method.

    Methods: "url", "double-url", "unicode", "mixed-case".
    """
    if method == "url":
        return quote(payload, safe="")
    if method == "double-url":
        return quote(quote(payload, safe=""), safe="")
    if method == "unicode":
        return "".join(
            ch if ch.isalnum() else f"%u{ord(ch):04X}" for ch in payload
        )
    if method == "mixed-case":
        out = []
        upper = random.choice([True, False])
        for ch in payload:
            if ch.isalpha():
                out.append(ch.upper() if upper else ch.lower())
                upper = not upper
            else:
                out.append(ch)
        return "".join(out)
    raise ValueError(f"unknown encode method: {method!r} (want one of {_ENCODE_METHODS})")


def jitter_delay(base: float, factor: float = 0.5) -> float:
    """Randomized delay around base to break timing patterns."""
    if factor < 0 or factor > 1:
        raise ValueError("factor must be between 0 and 1")
    low = base * (1 - factor)
    high = base * (1 + factor)
    return random.uniform(low, high)


_JS_CHALLENGE_MARKERS = (
    "cf-challenge",
    "jschl",
    "checking your browser",
    "just a moment",
    "cf_chl",
    "challenge-platform",
    "captcha",
    "recaptcha",
    "cf-turnstile",
    "window._cf_chl_opt",
)


def detect_js_challenge(html: str) -> bool:
    """True if the page looks like a JS challenge or captcha.

    Detection only. Never try to solve challenges or captchas.
    """
    lowered = html.lower()
    return any(marker in lowered for marker in _JS_CHALLENGE_MARKERS)
