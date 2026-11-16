"""Shared helpers for the 300-expansion Category-3 (crypto/ZK) plugins.

Analyses are pure functions over operator-supplied artifacts (source
code, config, key/signature sets, circuit artifacts) collected from
ctx.shared and, for URL targets, the fetched homepage text. No network
access is required for the core analysis and no plugin ever attempts
decryption, cracking, or a live oracle attack.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any, List, Tuple

Finding3 = Tuple[str, str, str, str]  # key, value, severity, remediation


def find_values(objs: Any, key: str) -> List[Any]:
    """Recursively collect every value stored under `key` in objs."""
    out: List[Any] = []
    if isinstance(objs, dict):
        for k, v in objs.items():
            if str(k).lower() == key.lower():
                out.append(v)
            out.extend(find_values(v, key))
    elif isinstance(objs, list):
        for item in objs:
            out.extend(find_values(item, key))
    return out


def first(objs: Any, *keys: str):
    for k in keys:
        vals = find_values(objs, k)
        if vals:
            return vals[0]
    return None


def has(text: str, *subs: str) -> bool:
    t = text.lower()
    return any(s.lower() in t for s in subs)


def rx(text: str, pattern: str) -> bool:
    return re.search(pattern, text, re.I | re.S) is not None


def _stringify(item: Any) -> str:
    if isinstance(item, str):
        return item
    try:
        return json.dumps(item)
    except Exception:
        return str(item)


async def collect(ctx, target) -> Tuple[str, List[Any]]:
    """Gather (combined_text, structured_objects) for a plugin run."""
    texts: List[str] = []
    objs: List[Any] = []
    for bucket in (ctx.shared or {}).values():
        items = bucket if isinstance(bucket, list) else [bucket]
        for item in items:
            if isinstance(item, (dict, list)):
                objs.append(item)
                texts.append(_stringify(item))
            elif isinstance(item, str):
                texts.append(item)
                try:
                    parsed = json.loads(item)
                    if isinstance(parsed, (dict, list)):
                        objs.append(parsed)
                except Exception:
                    pass
    raw = getattr(target, "raw", "") or ""
    if raw and not raw.lower().startswith(("http://", "https://")):
        texts.append(raw)
    if getattr(target, "type", "") == "url":
        try:
            page = await asyncio.wait_for(
                ctx.fetch_page(target.normalized or raw), timeout=8)
            if page:
                t = page.get("text") if isinstance(page, dict) else ""
                if t:
                    texts.append(t[:200000])
        except Exception:
            pass
    return "\n".join(texts), objs


async def run_cat3(plugin, analyze, target, ctx):
    try:
        text, objs = await collect(ctx, target)
        findings = []
        for key, value, sev, rem in analyze(text, objs):
            findings.append(plugin._f(
                "web3", key, value, "cat3-supplied-artifact",
                confidence=85,
                evidence={"severity": sev, "remediation": rem}))
        return plugin._ok(findings)
    except Exception as exc:  # never raise fatally
        return plugin._ok([], f"cat3 analysis degraded: {exc}")
