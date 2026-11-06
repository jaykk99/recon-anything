"""Shared helpers for the Cat-4 (300-expansion) Web3 frontend / OSINT
plugins. Not a plugin itself (no Plugin subclass here): artifact
collection, masking, and small decoders shared by the cat4 modules.

Artifact model: these plugins analyse OPERATOR-SUPPLIED artifacts
(JS bundles, page source, session/storage dumps, trace JSON, decoded
calldata, probe results) plus keyless public reads. Supplied artifacts
arrive on the discovery bus under the "cat4_artifacts" key: a list of
strings (raw bundle/page/dump text) and/or dicts (already-parsed JSON
structures). Live capture/interception of third-party sessions is
never performed; capture-named items are static detectors over the
supplied material only.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Ctx, Target

ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")
TXHASH_RE = re.compile(r"0x[0-9a-fA-F]{64}")
HEXDATA_RE = re.compile(r"0x[0-9a-fA-F]{8,}")

# Well-known function selectors -> human name. Read-only identification.
SELECTORS: Dict[str, str] = {
    "a9059cbb": "transfer(address,uint256)",
    "095ea7b3": "approve(address,uint256)",
    "23b872dd": "transferFrom(address,address,uint256)",
    "a22cb465": "setApprovalForAll(address,bool)",
    "70a08231": "balanceOf(address)",
    "18160ddd": "totalSupply()",
    "313ce567": "decimals()",
    "06fdde03": "name()",
    "95d89b41": "symbol()",
    "8da5cb5b": "owner()",
    "d0e30db0": "deposit()",
    "2e1a7d4d": "withdraw(uint256)",
    "3659cfe6": "upgradeTo(address)",
    "4f1ef286": "upgradeToAndCall(address,bytes)",
    "252dba42": "aggregate((address,bytes)[])",
    "bce38bd7": "tryAggregate(bool,(address,bytes)[])",
    "82ad56cb": "aggregate3((address,bool,bytes)[])",
    "174dea71": "aggregate3Value((address,bool,uint256,bytes)[])",
    "5ae401dc": "multicall(bytes[])",
    "ac9650d8": "multicall(uint256,bytes[])",
    "7ff36ab5": "swapExactETHForTokens(uint256,address[],address,uint256)",
    "38ed1739": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    "18cbafe5": "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
    "022c0d9f": "swap(uint256,uint256,address,bytes)",
    "e8e33700": "addLiquidity(address,address,uint256,uint256)",
    "baa2abde": "removeLiquidity(address,address,uint256)",
    "c45a0155": "factory()",
    "e6a43905": "getPair(address,address)",
    "0902f1ac": "getReserves()",
}

# Selectors that move value or grant spending rights (used by decoders).
VALUE_MOVING_SELECTORS = {"a9059cbb", "23b872dd", "2e1a7d4d", "d0e30db0"}
APPROVAL_SELECTORS = {"095ea7b3", "a22cb465"}
READONLY_SELECTORS = {"70a08231", "18160ddd", "313ce567", "06fdde03",
                      "95d89b41", "8da5cb5b", "0902f1ac", "c45a0155",
                      "e6a43905"}


def selector_name(sel: str) -> str:
    return SELECTORS.get((sel or "").lower().replace("0x", ""), "")


def mask_value(value: Any, keep: int = 6) -> str:
    """Masked evidence form: short prefix + length, never the secret."""
    s = str(value if value is not None else "")
    if len(s) <= keep:
        return "***"
    return f"{s[:keep]}*** (len {len(s)})"


def fingerprint(value: Any) -> str:
    """Stable short fingerprint of a secret-shaped value (SHA-256)."""
    s = str(value if value is not None else "")
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:16]


def get_artifacts(ctx: Ctx) -> List[Any]:
    """Operator-supplied artifacts from the discovery bus (raw list)."""
    try:
        items = ctx.consume("cat4_artifacts")
    except Exception:
        items = []
    return list(items or [])


def artifact_texts(ctx: Ctx) -> List[str]:
    """Artifacts rendered as text (dicts/lists become JSON text)."""
    out: List[str] = []
    for item in get_artifacts(ctx):
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, (dict, list)):
            try:
                out.append(json.dumps(item))
            except Exception:
                continue
    return out


def artifact_dicts(ctx: Ctx) -> List[Dict[str, Any]]:
    """Artifacts as dicts: dicts pass through, JSON strings are parsed."""
    out: List[Dict[str, Any]] = []
    for item in get_artifacts(ctx):
        if isinstance(item, dict):
            out.append(item)
        elif isinstance(item, str):
            try:
                parsed = json.loads(item)
            except Exception:
                continue
            if isinstance(parsed, dict):
                out.append(parsed)
            elif isinstance(parsed, list):
                out.append({"items": parsed})
    return out


def parse_json_maybe(text: Any) -> Optional[Any]:
    if isinstance(text, (dict, list)):
        return text
    if not isinstance(text, str):
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def find_addresses(text: str) -> List[str]:
    seen: List[str] = []
    for m in ADDR_RE.finditer(text or ""):
        a = m.group(0)
        if a.lower() not in [x.lower() for x in seen]:
            seen.append(a)
    return seen


async def gather_page_texts(ctx: Ctx, target: Target,
                            max_js: int = 8) -> List[Tuple[str, str, str]]:
    """Fetch the target homepage + inline scripts + same-host JS bundles.

    Returns [(label, text, url)]. Empty list when the target is not a
    web target or the fetch degrades. Never raises.
    """
    out: List[Tuple[str, str, str]] = []
    if target.type not in ("domain", "url"):
        return out
    try:
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return out
        base = await web_base(ctx, target, domain)
        page = await ctx.fetch_page(base, timeout=20)
        if not page:
            return out
        html = (page.get("text") or "")[:500000]
        page_url = page.get("url") or base
        out.append(("page", html, page_url))
        inline = " ".join(re.findall(
            r"<script(?![^>]+src=)[^>]*>(.*?)</script>", html,
            re.I | re.S))[:300000]
        if inline.strip():
            out.append(("inline <script>", inline, page_url))
        srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']',
                          html, re.I)
        srcs = [s for s in srcs if not s.startswith("data:")][:max_js]
        for src in srcs:
            full = urljoin(page_url, src)
            host = urlparse(full).netloc
            if host and domain and not host.endswith(domain):
                continue
            try:
                r = await fetch(ctx.http, ctx.limiter, "GET", full,
                                timeout=12)
                if r.status_code == 200 and r.text:
                    out.append((f"JS {src[:60]}", r.text[:300000], full))
            except Exception:
                continue
    except Exception:
        return out
    return out


async def all_texts(ctx: Ctx, target: Target,
                    max_js: int = 8) -> List[Tuple[str, str, str]]:
    """Page/JS texts plus every supplied artifact rendered as text."""
    texts = await gather_page_texts(ctx, target, max_js=max_js)
    for i, t in enumerate(artifact_texts(ctx)):
        texts.append((f"artifact[{i}]", t[:500000], ""))
    raw = (target.normalized or "").strip()
    if len(raw) > 60 and (raw.startswith("{") or raw.startswith("0x")):
        texts.append(("target", raw[:500000], ""))
    return texts


async def fetch_json(ctx: Ctx, url: str, method: str = "GET",
                     payload: Optional[Dict[str, Any]] = None,
                     timeout: int = 15) -> Optional[Any]:
    """Keyless JSON read with clean degraded handling (None on failure)."""
    try:
        kwargs: Dict[str, Any] = {"timeout": timeout, "max_retries": 1}
        if payload is not None:
            kwargs["json"] = payload
        r = await fetch(ctx.http, ctx.limiter, method, url, **kwargs)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception:
        return None
