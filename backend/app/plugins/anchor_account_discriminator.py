"""Anchor account discriminator audit.
Flags UncheckedAccount/AccountUnchecked use, try_from without a discriminator check, and duplicate 8-byte discriminators across account types."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from .base import Plugin

RULES = [('UncheckedAccount|AccountUnchecked', 'verify_discriminator|check_discriminator', 'anchor_unchecked_account', 'high', 'Anchor program uses an unchecked account type, so deserialization can accept an account of the wrong type (discriminator not verified)', "Use typed Account<'info, T> accounts so Anchor verifies the 8-byte discriminator before field reads."), ('try_from\\s*\\(', 'discriminator', 'anchor_try_from_no_discriminator_check', 'medium', 'Account data is deserialized via try_from without any discriminator verification in the program', 'Verify the 8-byte discriminator before reading account fields.')]

def _collision_hits(text):
    seen, hits = {}, []
    for m in re.finditer(r"discriminator\s*[:=]\s*\[([0-9,\s]+)\]", text):
        val = re.sub(r"\s+", "", m.group(1))
        if val in seen:
            hits.append({"key": "anchor_discriminator_collision",
                "value": f"Duplicate Anchor discriminator [{val}] used by more than one account type in the same program",
                "severity": "high",
                "remediation": "Give every account type a unique discriminator derived from its type name."})
        seen[val] = True
    return hits


def _rules_analyze(text):
    """Pure analysis: returns list of hit dicts. No I/O, never raises."""
    hits = []
    if not text or not isinstance(text, str):
        return hits
    for pattern, guard, key, severity, value, remediation in RULES:
        try:
            if not re.search(pattern, text, re.I | re.S):
                continue
            if guard and re.search(guard, text, re.I | re.S):
                continue
        except re.error:
            continue
        hits.append({"key": key, "value": value, "severity": severity,
                     "remediation": remediation})
    return hits


async def _get_artifact(target, ctx):
    try:
        for kind in ("artifacts", "source", "sources", "code",
                     "artifact_text", "files", "contracts"):
            for item in ctx.consume(kind):
                if isinstance(item, str) and len(item) > 20:
                    return item
                if isinstance(item, dict):
                    import json as _j
                    return _j.dumps(item)
    except Exception:
        pass
    raw = (getattr(target, "raw", "") or "").strip()
    norm = (getattr(target, "normalized", "") or "").strip()
    if raw and (len(raw) > 30 or raw.startswith("{") or "\n" in raw):
        return raw
    if norm.startswith("http"):
        try:
            page = await ctx.fetch_page(norm)
            if page:
                txt = page.get("text") if isinstance(page, dict) else getattr(page, "text", "")
                if txt:
                    return txt
        except Exception:
            pass
    return raw


class AnchorAccountDiscriminator(Plugin):
    id = "anchor_account_discriminator"
    label = "Anchor Account Discriminator"
    accepts = ["url", "domain", "text", "address", "contract"]
    group = "web3"
    description = "Checks Anchor account discriminators: uniqueness, verification before field reads, no unchecked accounts."
    passive = True

    async def run(self, target, ctx):
        try:
            text = await _get_artifact(target, ctx)
            hits = analyze_artifact(text or "")
            findings = [
                self._f("web3", h["key"], h["value"], self.id,
                        confidence=85,
                        evidence={"severity": h.get("severity", "medium"),
                                  "remediation": h.get("remediation", "")})
                for h in hits]
            return self._ok(
                findings,
                reason=f"{len(findings)} alt-chain finding(s) from artifact analysis")
        except Exception as exc:  # never raise fatally
            return self._ok([], reason=f"degraded: {type(exc).__name__}: {exc}")


def analyze_artifact(text):
    hits = _rules_analyze(text)
    try:
        hits.extend(_collision_hits(text or ""))
    except Exception:
        pass
    return hits
