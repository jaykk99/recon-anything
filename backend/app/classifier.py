"""Universal input classifier.

Single search bar: auto-detect the input type via ordered regex + validation.
Order matters: more specific types are checked before generic ones.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


def _is_jwt(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 3:
        return False
    try:
        for p in parts[:2]:
            padded = p + "=" * (-len(p) % 4)
            json.loads(base64.urlsafe_b64decode(padded))
        return True
    except Exception:
        return False


# $-prefixed password-hash formats (bcrypt, crypt family, Argon2,
# scrypt, PBKDF2). Matched against the lowercased copy below: the
# character classes are case-insensitive-safe (length + charset are
# preserved by lowercasing), and `normalized` keeps the original
# string, so detection here never corrupts the value.
_DOLLAR_HASH_TYPES = [
    (re.compile(r"\$2[aby]\$\d{2}\$[./a-z0-9]{53}"), "bcrypt"),
    (re.compile(r"\$argon2(?:id|i|d)\$[^$\s]+\$[^$\s]+\$[^$\s]+"
                r"\$[a-z0-9+/=]+"), "argon2"),
    (re.compile(r"\$scrypt\$[^$\s]+\$[^$\s]+\$[a-z0-9+/=]+"), "scrypt"),
    (re.compile(r"\$pbkdf2-sha(?:256|512)\$[^$\s]+\$[^$\s]+"
                r"\$[a-z0-9+/=]+"), "pbkdf2"),
    (re.compile(r"\$1\$[./a-z0-9]{1,16}\$[./a-z0-9]{22}"), "md5crypt"),
    (re.compile(r"\$5\$(?:rounds=\d+\$)?[./a-z0-9]{1,16}"
                r"\$[./a-z0-9]{43}"), "sha256crypt"),
    (re.compile(r"\$6\$(?:rounds=\d+\$)?[./a-z0-9]{1,16}"
                r"\$[./a-z0-9]{86}"), "sha512crypt"),
]


def _hash_type(s: str) -> Optional[str]:
    s = s.strip().lower()
    if re.fullmatch(r"[0-9a-f]{32}", s):
        return "md5"
    if re.fullmatch(r"[0-9a-f]{40}", s):
        return "sha1"
    if re.fullmatch(r"[0-9a-f]{64}", s):
        return "sha256"
    for pat, name in _DOLLAR_HASH_TYPES:
        if pat.fullmatch(s):
            return name
    return None


def _looks_like_btc(s: str) -> bool:
    s = s.strip()
    return bool(re.fullmatch(r"(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}", s))


def _looks_like_eth(s: str) -> bool:
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", s.strip()))


# --- Solana -------------------------------------------------------------
# Base58 alphabet (no 0, O, I, l). A Solana public key is 32 bytes,
# which base58-encodes to 32-44 chars. Decoding and checking the byte
# length is the real validator: it keeps BTC legacy addresses (25-byte
# payload), hex hashes, and random base58-ish usernames out.
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def _b58decode(s: str) -> Optional[bytes]:
    try:
        n = 0
        for ch in s:
            n = n * 58 + _B58_INDEX[ch]
        body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
        pad = len(s) - len(s.lstrip("1"))
        return b"\x00" * pad + body
    except (KeyError, OverflowError):
        return None


def _looks_like_solana(s: str) -> bool:
    s = s.strip()
    # Explicit chain prefixes: solana:<addr> / sol:<addr>.
    low = s.lower()
    for prefix in ("solana:", "sol:"):
        if low.startswith(prefix):
            return _looks_like_solana(s[len(prefix):])
    if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", s):
        return False
    # BTC keeps priority in its own shapes: bech32, and the short
    # legacy forms (<=35 chars starting 1/3). A longer base58 string
    # that decodes to exactly 32 bytes is a Solana key, never a BTC
    # address (legacy BTC payloads are 25 bytes).
    if s.startswith("bc1"):
        return False
    if len(s) <= 35 and _looks_like_btc(s):
        return False
    decoded = _b58decode(s)
    return decoded is not None and len(decoded) == 32


def _is_pump_url(s: str) -> bool:
    """pump.fun coin page: pump.fun/coin/<mint> or pump.fun/<mint>."""
    s = s.strip()
    if not re.match(r"(?i)^https?://", s):
        return False
    try:
        p = urlparse(s)
    except Exception:
        return False
    if (p.netloc or "").lower() not in ("pump.fun", "www.pump.fun"):
        return False
    parts = [seg for seg in (p.path or "").split("/") if seg]
    if len(parts) == 2 and parts[0] == "coin":
        return _looks_like_solana(parts[1])
    if len(parts) == 1:
        return _looks_like_solana(parts[0])
    return False


def _is_asn(s: str) -> bool:
    return bool(re.fullmatch(r"(?i)as\d{1,10}", s.strip()))


def _is_domain(s: str) -> bool:
    s = s.strip().lower().rstrip(".")
    if len(s) > 253 or "." not in s:
        return False
    labels = s.split(".")
    if any(len(l) == 0 or len(l) > 63 for l in labels):
        return False
    tld = labels[-1]
    if not re.fullmatch(r"[a-z]{2,24}", tld):
        return False
    return all(re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", l) for l in labels)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def _is_cidr(s: str) -> bool:
    try:
        ipaddress.ip_network(s.strip(), strict=False)
        return "/" in s
    except ValueError:
        return False


def _is_email(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}", s.strip()))


def _is_phone(s: str) -> bool:
    digits = re.sub(r"\D", "", s)
    return 7 <= len(digits) <= 15 and bool(re.fullmatch(r"\+?[\d\s().-]{7,25}", s.strip()))


def _is_url(s: str) -> bool:
    s = s.strip()
    if not re.match(r"(?i)^https?://", s):
        return False
    try:
        p = urlparse(s)
        return bool(p.netloc)
    except Exception:
        return False


_COMMON_TLDS = {
    "com", "org", "net", "io", "dev", "app", "co", "ai", "me", "us", "uk",
    "ca", "de", "fr", "au", "in", "br", "jp", "cn", "ru", "nl", "se",
    "xyz", "info", "biz", "online", "site", "tech", "store", "blog",
    "cloud", "page", "top", "win", "pro", "name", "tv", "cc",
}


def _looks_android_pkg(s: str) -> bool:
    s = s.strip()
    if not re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+", s):
        return False
    if " " in s:
        return False
    labels = s.split(".")
    tld = labels[-1]
    # Real domains end in a TLD: any 2-letter ending is a country-code
    # TLD, and the common gTLDs are listed - both mean "domain", never a
    # package id.
    if len(tld) == 2 or tld in _COMMON_TLDS:
        return False
    # Package ids are reverse-DNS: they START with a TLD-like segment
    # (com.vendor.app, com.whatsapp). A dotted name that does not start
    # with one is a hostname - canary.test, victim.gg, data.technology,
    # www.example.technology. The old heuristic ("package-shaped and
    # the last label is not a well-known TLD") classified every such
    # domain as play_store, and since play_store is checked before
    # domain, every domain plugin (subdomains, secrets, ports, ...)
    # silently skipped the target as "not applicable": a full scan
    # reporting all plugins ok with ZERO findings (found 2026-10-23).
    return labels[0] in _PACKAGE_PREFIXES


# First labels of reverse-DNS package ids (com.vendor.app shape).
_PACKAGE_PREFIXES = {
    "com", "org", "net", "io", "me", "co", "app", "dev", "ai", "tv",
    "cc", "us", "uk", "de", "jp", "au", "ca", "fr", "in", "br", "ru",
    "nl", "se", "pro", "info", "biz", "name", "mobi", "global", "inc",
    "ltd", "plc", "gmbh", "gov", "edu", "mil",
}


def _is_play_store(s: str) -> bool:
    s = s.strip()
    if "play.google.com/store/apps/details" in s:
        return True
    return _looks_android_pkg(s)


def _is_app_store(s: str) -> bool:
    s = s.strip()
    return "apps.apple.com" in s or bool(re.fullmatch(r"\d{6,}", s))


def _is_github(s: str) -> bool:
    s = s.strip()
    if "github.com/" in s:
        return True
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)?", s) and "/" in s)


def _is_package(s: str) -> bool:
    s = s.strip()
    return bool(re.fullmatch(r"(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*", s, re.I))


def classify(raw: str) -> Dict:
    """Return {"type": ..., "normalized": ..., "confidence": ...}."""
    s = (raw or "").strip()
    if not s:
        return {"type": "unknown", "normalized": s, "confidence": 0}

    checks: List[Tuple[str, callable, int]] = [
        ("jwt", _is_jwt, 98),
        # Store URLs must beat the generic url check: mobile accepts only
        # play_store/app_store, and url would swallow them otherwise,
        # leaving the mobile plugin permanently unreachable.
        ("play_store", _is_play_store, 88),
        ("app_store", _is_app_store, 85),
        # pump.fun coin pages must beat the generic url check, or the
        # Solana contract plugin never sees them.
        ("solana_contract", _is_pump_url, 97),
        ("url", _is_url, 97),
        ("email", _is_email, 96),
        ("cidr", _is_cidr, 96),
        ("ip", _is_ip, 96),
        ("asn", _is_asn, 95),
        ("file_hash", lambda x: _hash_type(x) is not None, 95),
        # Solana keys before the generic fallbacks (username, npm,
        # github): a 43-44 char base58 string is a chain address, not
        # a person or a package. BTC/ETH are checked inside
        # _looks_like_solana so their shapes keep priority.
        ("solana_contract", _looks_like_solana, 92),
        ("crypto_wallet", lambda x: _looks_like_btc(x) or _looks_like_eth(x), 90),
        ("phone", _is_phone, 80),
        ("github", _is_github, 80),
        ("domain", _is_domain, 90),
        ("npm_package", _is_package, 60),
    ]
    for ttype, fn, conf in checks:
        try:
            if fn(s):
                return {"type": ttype, "normalized": s, "confidence": conf,
                        "detail": _hash_type(s) if ttype == "file_hash" else None}
        except Exception:
            continue
    # person / company name fallback
    if re.fullmatch(r"[A-Za-z][A-Za-z .,'-]{1,80}", s):
        return {"type": "person_or_company", "normalized": s, "confidence": 55}
    return {"type": "username", "normalized": s, "confidence": 50}


def classify_batch(text: str) -> List[Dict]:
    """Multi-line paste of mixed targets."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip().strip(",;")
        if line:
            c = classify(line)
            c["raw"] = line
            out.append(c)
    return out


def domain_from_target(ttype: str, normalized: str) -> Optional[str]:
    """Best-effort domain extraction for plugin routing."""
    if ttype == "domain":
        return normalized.lower()
    if ttype == "url":
        try:
            return urlparse(normalized).netloc.split(":")[0].lower()
        except Exception:
            return None
    if ttype == "email":
        return normalized.split("@")[-1].lower()
    return None
