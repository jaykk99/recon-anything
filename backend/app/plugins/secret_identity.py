"""Exposed-secret identification, full value shown.

Problem this solves: a finding that only says "a secret leaked" does not
let the owner tell *which* secret leaked. Every identification finding
therefore carries the found secret IN FULL (Jay's order, 2026-10-29,
reversing the 2026-10-27 masked-only rule), plus rich metadata:

- the full secret value, exactly as found (``full_value``)
- source file/URL and the exact line and column of the match
- secret type (the variable/field name that carried it)
- length, a masked preview, and a SHA-256 fingerprint (kept as extra
  metadata; the local fingerprint matcher in
  backend/scripts/match_secret_fingerprint.py still works as an
  additional identification tool)
- surrounding context exactly as found, with the value visible in it
- for wallet material, the derived public wallet and balance, but only
  when the caller already has them (this module never derives a wallet
  from private material and never looks a balance up on its own)

Tests and canaries use invented fake values only.
"""
from __future__ import annotations

import hashlib
import math
import re
import time
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from ..classifier import domain_from_target
from ..net import web_base
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_PLACEHOLDERS = {
    "example", "sample", "test", "testing", "demo", "placeholder",
    "changeme", "yourkey", "your_key", "mykey", "fakekey",
}


def fingerprint(secret: str) -> str:
    """SHA-256 fingerprint of a secret value, as ``sha256:<hex>``.

    The fingerprint identifies a secret without revealing it: two
    identical values always produce the same fingerprint, and the
    fingerprint cannot be turned back into the value.
    """
    return "sha256:" + hashlib.sha256(
        (secret or "").encode("utf-8")).hexdigest()


def mask_value(secret: str, show: int = 4) -> str:
    """Masked form of a secret: first/last few chars only, never full."""
    s = (secret or "").strip()
    if len(s) <= show * 2:
        return "***"
    return s[:show] + "..." + s[-show:]


def locate(text: str, secret: str) -> Tuple[Optional[int], Optional[int]]:
    """Return (line, column) of the first occurrence, 1-based, or Nones."""
    idx = (text or "").find(secret or "")
    if idx < 0 or not secret:
        return None, None
    before = text[:idx]
    line = before.count("\n") + 1
    column = idx - (before.rfind("\n"))  # 1-based column
    return line, column


def context_snippet(text: str, secret: str, window: int = 80) -> str:
    """Surrounding context exactly as found, secret visible in it.

    Returns a snippet of ``window`` chars on each side of the first
    match, with the secret left in place so the owner sees the value
    in its original context.
    """
    if not secret or secret not in (text or ""):
        return (text or "")[: window * 2]
    idx = text.find(secret)
    start = max(0, idx - window)
    end = min(len(text), idx + len(secret) + window)
    return text[start:end]


def identify_finding(
    *,
    source: str,
    source_url: Optional[str],
    secret_type: str,
    secret: str,
    context_text: Optional[str] = None,
    derived_public_wallet: Optional[str] = None,
    balance: Optional[str] = None,
) -> Dict[str, Any]:
    """Build identification evidence for one exposed secret.

    The returned dict carries the full secret in ``full_value`` (and in
    the ``context`` snippet, exactly as found), plus the fingerprint
    and masked preview as extra metadata. ``derived_public_wallet``
    and ``balance`` are public data supplied by the caller; they are
    passed through unchanged and are never derived here from private
    material.
    """
    line, column = (locate(context_text, secret)
                    if context_text is not None else (None, None))
    evidence: Dict[str, Any] = {
        "secret_type": secret_type,
        "full_value": secret,
        "length": len(secret or ""),
        "masked_value": mask_value(secret),
        "fingerprint": fingerprint(secret),
        "source": source,
        "source_url": source_url,
        "line": line,
        "column": column,
        "context": (context_snippet(context_text, secret)
                    if context_text is not None else None),
        "full_value_included": True,
        "remediation": ("Rotate this credential immediately, remove it "
                        "from served code/config, and audit access logs "
                        "for misuse. The full value is shown above; "
                        "the fingerprint can also be matched locally "
                        "against your vault."),
        "scope_note": ("Authorized testing only: verify you own this "
                       "asset or it is in an approved bounty scope "
                       "before acting on this finding."),
    }
    if derived_public_wallet:
        evidence["derived_public_wallet"] = derived_public_wallet
    if balance is not None:
        evidence["balance"] = balance
    return evidence


def contains_full_secret(obj: Any, secret: str) -> bool:
    """Recursively check whether ``secret`` appears anywhere in ``obj``.

    Used by tests to prove a finding carries the full value.
    Masked forms contain only a few chars of the value, so only the
    complete string counts as a hit.
    """
    if not secret:
        return False
    if isinstance(obj, str):
        return secret in obj
    if isinstance(obj, dict):
        return any(contains_full_secret(v, secret) for v in obj.values())
    if isinstance(obj, (list, tuple, set)):
        return any(contains_full_secret(v, secret) for v in obj)
    return False


def _is_placeholder(value: str) -> bool:
    low = (value or "").strip().lower().strip("\"' ")
    return low in _PLACEHOLDERS or "example" in low or "sample" in low


# Key names that merely CONTAIN a secret-ish word but never carry a secret:
# i18n/UI strings (tokenDescription, footer_resources_list_your_token),
# config pointers (tokenizedStockBaseUrl, *Endpoint, *Address). Matching
# these is what turned crypto.com's translation strings into 40 fake
# "exposed secret" findings.
_KEY_DENY = re.compile(
    r"(?i)(description|_?name|label|title|tooltip|placeholder|message|"
    r"_?text|_?list|count|index|_?url|uri|base_?url|endpoint|address|"
    r"symbol|_?type|_id$|heading|header|footer|i18n|locale|translation|"
    r"caption|resources|filter_|desc$)")

# Real-credential prefixes: if the value starts like a known token it is a
# secret regardless of entropy (short known tokens still matter).
_SECRET_PREFIX = re.compile(
    r"(?i)(sk_|pk_|rk_|ey[A-Za-z0-9_-]{8}|AKIA|ASIA|AIza|ghp_|gho_|ghs_|"
    r"github_pat_|xox[baprs]-|glpat-|hf_|sk-|npm_|SG\.|-----BEGIN)")


def _shannon(s: str) -> float:
    """Shannon entropy in bits/char. Prose ~2.8-3.1; random keys 3.5-5."""
    n = len(s) or 1
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _looks_like_secret(value: str) -> bool:
    """True only for values that actually look like a credential.

    A real API key, token or secret has no internal whitespace, is not a
    URL or path, and is either high-entropy or carries a known token
    prefix. This rejects natural-language i18n values ("List your token",
    "Powering the Crypto.com Ecosystem") and config URLs, which is where
    the substring-only key match produced its false positives.
    """
    v = (value or "").strip()
    if len(v) < 16:
        return False
    if any(ch.isspace() for ch in v):
        return False
    if v.lower().startswith(("http://", "https://", "/", "www.", "data:")):
        return False
    if _SECRET_PREFIX.search(v):
        return True
    if _shannon(v) < 3.2:
        return False
    token_chars = sum(1 for ch in v if ch.isalnum() or ch in "-_+/=.~")
    return token_chars / len(v) >= 0.95


# Generic assignment shapes: a variable/field whose name says it carries
# a secret, followed by a quoted value. Narrow on purpose: this plugin
# identifies exposures, it does not try to enumerate every key format
# (that is the job of the dedicated secret-harvesting plugins).
_ASSIGNMENT_RE = re.compile(
    r"(?i)([A-Za-z0-9_]*?(?:api_key|secret|token)[A-Za-z0-9_]*)\s*"
    r"[:=]\s*[\"']([^\"']{16,})[\"']")


class SecretIdentityPlugin(Plugin):
    id = "secret_identity"
    label = "Exposed Secret Identification"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = ("Identify exactly which secret is exposed: the "
                   "full value as found, plus source, line, type, "
                   "length, and fingerprint.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        base = await web_base(ctx, target, domain)

        async def get_home():
            try:
                page = await ctx.fetch_page(base, timeout=25)
                if page is None:
                    raise RuntimeError("homepage fetch failed")
                return {"html": page["text"][:500000], "url": page["url"]}
            except Exception as e:  # noqa: BLE001 - degraded, not error
                return {"error": str(e)[:200] or type(e).__name__}

        home, _ = await ctx.cache.cached("http", f"secret_identity:{base}",
                                         get_home)
        if "error" in home:
            res = self._degraded(f"fetch failed: {home['error']}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        texts: List[Tuple[str, str, str]] = [
            ("homepage HTML", home["html"], home["url"])]
        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']',
                          home["html"], re.I)
        for src in srcs[:10]:
            if src.startswith("data:"):
                continue
            try:
                from urllib.parse import urljoin, urlparse
                full = urljoin(home["url"], src)
                host = urlparse(full).netloc
                if host and not host.endswith(domain):
                    continue
                page = await ctx.fetch_page(full, timeout=20)
                if page is not None:
                    texts.append((f"JS bundle {host or 'inline'}",
                                  page["text"][:500000], page["url"]))
            except Exception:  # noqa: BLE001 - one bad bundle skips
                continue

        findings: List[Finding] = []
        seen = set()
        for where, text, url in texts:
            for match in _ASSIGNMENT_RE.finditer(text):
                var_name, value = match.group(1), match.group(2)
                if _is_placeholder(value):
                    continue
                # The key name only contains "token"/"secret" as a
                # substring (tokenDescription, list_your_token) - not a
                # secret-bearing field.
                if _KEY_DENY.search(var_name):
                    continue
                # The value does not look like a credential (prose, URL,
                # low entropy). Identification requires an actual secret.
                if not _looks_like_secret(value):
                    continue
                fp = fingerprint(value)
                if fp in seen:
                    continue
                seen.add(fp)
                evidence = identify_finding(
                    source=where, source_url=url,
                    secret_type=var_name.lower(), secret=value,
                    context_text=text)
                findings.append(self._f(
                    "leak", "exposed_secret_identified",
                    (f"Exposed secret identified: {var_name.lower()} "
                     f"{value} at {url} "
                     f"line {evidence['line']} "
                     f"(fingerprint {fp[:19]}...)"),
                    where, source_url=url, confidence=75,
                    evidence=evidence, passive=True))
        res = self._ok(findings,
                       f"{len(findings)} secret(s) identified")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
