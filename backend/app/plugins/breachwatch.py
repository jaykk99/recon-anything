"""Breach Watch (defensive, keyless).

Checks whether an email address appears in PUBLIC breach dumps via the
keyless XposedOrNot API:

- GET https://api.xposedornot.com/v1/check-email/{email}
  -> {"breaches": [[names...]], "email": ..., "status": ...}
  ("Error" status / empty list = clean)
- GET https://api.xposedornot.com/v1/breach-analytics?email={email}
  -> per-breach details: password_risk, xposed_data (data classes),
  xposed_date, verified.

Severity mapping (honest, from the breach's own metadata):
- password_risk in {plaintext, easytocrack} or "Passwords" in xposed_data
  -> HIGH (rotate this password everywhere it was reused, now)
- breached but no password data (emails/names/phones only) -> MEDIUM
- clean -> no findings, one "clean" note finding at low severity

DEFENSIVE ONLY. This tells the owner of an address whether it shows up
in public dumps so they can rotate credentials. It never attempts
logins, never brute-forces, never touches the breached services.
Rate limits (429) are reported as rate-limited, not failures.

All native Python, zero API keys, keyless throughout.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx

from ..ratelimit import RateLimiter, fetch
from .base import (Cost, Ctx, Finding, Plugin, PluginResult, Target,
                   safe_json_dict)
from .secretutils import evidence_block

XON_CHECK = "https://api.xposedornot.com/v1/check-email/{email}"
XON_ANALYTICS = "https://api.xposedornot.com/v1/breach-analytics?email={email}"
UA = "ReconAnything-BreachWatch/1.0"

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# password_risk values that mean "change it right now".
PLAINTEXT_RISK = {"plaintext", "easytocrack", "easy_to_crack"}

# Cap breach findings per email so one heavily-breached address doesn't
# flood the run; the summary still reports the full count.
MAX_BREACH_FINDINGS = 25


def _severity_for(password_risk: str, xposed_data: str) -> str:
    """Map XposedOrNot breach metadata to high/medium."""
    pr = (password_risk or "").strip().lower().replace(" ", "")
    data = (xposed_data or "").lower()
    if pr in PLAINTEXT_RISK or "password" in data:
        return "high"
    return "medium"


def _parse_check_email(payload: Dict[str, Any]) -> List[str]:
    """Extract breach names from the check-email response."""
    breaches = payload.get("breaches") or []
    names: List[str] = []
    # API returns {"breaches": [[name, name, ...]]} - a list with one list.
    for group in breaches:
        if isinstance(group, list):
            names.extend(str(n) for n in group if n)
        elif group:
            names.append(str(group))
    # Deduplicate, preserve order.
    seen = set()
    out = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _parse_analytics(payload: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    """Map breach name -> {password_risk, xposed_data, xposed_date, verified}."""
    info: Dict[str, Dict[str, str]] = {}
    try:
        details = (payload.get("ExposedBreaches") or {}).get("breaches_details") or []
    except Exception:
        return info
    for b in details:
        if not isinstance(b, dict):
            continue
        name = str(b.get("breach") or "")
        if not name:
            continue
        info[name] = {
            "password_risk": str(b.get("password_risk") or "unknown"),
            "xposed_data": str(b.get("xposed_data") or ""),
            "xposed_date": str(b.get("xposed_date") or ""),
            "verified": str(b.get("verified") or ""),
        }
    return info


async def check_email_breaches(
    email: str,
    http: httpx.AsyncClient,
    limiter: Any = None,
) -> Tuple[str, List[Dict[str, str]], Optional[str]]:
    """Run the XposedOrNot breach check for one email.

    Returns (status, breaches, note) where status is one of:
    "breached" | "clean" | "rate_limited" | "unreachable" | "invalid".
    breaches is a list of {name, password_risk, xposed_data, xposed_date,
    verified, severity}.
    """
    email = (email or "").strip().lower()
    if not EMAIL_RE.match(email):
        return "invalid", [], f"not a valid email address: {email!r}"
    if limiter is None:
        limiter = RateLimiter(default_rps=2.0)  # polite default for direct calls

    # 1) Breach-name lookup.
    try:
        r = await fetch(http, limiter, "GET", XON_CHECK.format(email=quote(email)),
                        timeout=20, headers={"User-Agent": UA})
    except Exception as e:
        return "unreachable", [], f"XposedOrNot unreachable: {str(e)[:120]}"
    if r.status_code == 429:
        return "rate_limited", [], "XposedOrNot rate limited (429): try again in a few minutes"
    if r.status_code != 200:
        return "unreachable", [], f"XposedOrNot returned HTTP {r.status_code}"
    try:
        payload = r.json()
    except Exception:
        return "unreachable", [], "XposedOrNot returned non-JSON"
    if not isinstance(payload, dict):
        return "unreachable", [], "XposedOrNot returned unexpected shape"

    names = _parse_check_email(payload)
    if not names:
        return "clean", [], "no breaches found for this address"

    # 2) Per-breach details (data classes, password risk) for severity.
    details: Dict[str, Dict[str, str]] = {}
    try:
        r2 = await fetch(http, limiter, "GET",
                         XON_ANALYTICS.format(email=quote(email)),
                         timeout=20, headers={"User-Agent": UA})
        if r2.status_code == 200:
            details = _parse_analytics(safe_json_dict(r2.json()))
    except Exception:
        pass  # details are a bonus; names alone still produce findings

    breaches = []
    for name in names:
        d = details.get(name, {})
        pr = d.get("password_risk", "unknown")
        xd = d.get("xposed_data", "")
        breaches.append({
            "name": name,
            "password_risk": pr,
            "xposed_data": xd,
            "xposed_date": d.get("xposed_date", ""),
            "verified": d.get("verified", ""),
            "severity": _severity_for(pr, xd),
        })
    return "breached", breaches, None


class BreachWatchPlugin(Plugin):
    id = "breachwatch"
    label = "Breach Watch"
    accepts = ["email"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = ("Defensive breach check for your own addresses: XposedOrNot "
                   "keyless lookup, per-breach severity from leaked data classes. "
                   "Never attempts logins.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        email = target.normalized.strip().lower()
        status, breaches, note = await check_email_breaches(
            email, ctx.http, ctx.limiter)

        findings: List[Finding] = []
        if status == "invalid":
            return self._error(note or "invalid email")
        if status == "rate_limited":
            return self._rate_limited(note or "rate limited")
        if status == "unreachable":
            return self._degraded(note or "XposedOrNot unreachable")
        if status == "clean":
            findings.append(self._f(
                "identity", "breachwatch_clean",
                f"{email}: not found in any public breach dump (clean)",
                source="xposedornot", confidence=85, passive=True,
                evidence=evidence_block(
                    email, "breachwatch_clean", "credential", "low",
                    {"checked_via": "api.xposedornot.com (keyless)"})))
            res = self._ok(findings, "clean: no breaches found")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        # Breached: one finding per breach (capped), high severity when
        # passwords were exposed.
        for b in breaches[:MAX_BREACH_FINDINGS]:
            sev = b["severity"]
            what = b["xposed_data"].replace(";", ", ") or "details unavailable"
            when = f" (breach date: {b['xposed_date']})" if b["xposed_date"] else ""
            findings.append(self._f(
                "leak", f"breachwatch_{b['name']}",
                f"{email} appears in the {b['name']} breach{when}. "
                f"Exposed: {what}.",
                source="xposedornot", confidence=90, passive=True,
                evidence=evidence_block(
                    email, "breachwatch_breach", "credential", sev,
                    {"breach": b["name"],
                     "password_risk": b["password_risk"],
                     "xposed_data": b["xposed_data"],
                     "xposed_date": b["xposed_date"],
                     "verified": b["verified"],
                     "checked_via": "api.xposedornot.com (keyless)"})))
        if len(breaches) > MAX_BREACH_FINDINGS:
            findings.append(self._f(
                "identity", "breachwatch_more",
                f"...and {len(breaches) - MAX_BREACH_FINDINGS} more breaches "
                f"({len(breaches)} total). Rotate passwords everywhere.",
                source="xposedornot", confidence=90, passive=True,
                evidence=evidence_block(
                    email, "breachwatch_more", "credential", "high",
                    {"total_breaches": len(breaches)})))

        res = self._ok(
            findings,
            f"{len(breaches)} breach(es) found for {email}; "
            f"{sum(1 for b in breaches if b['severity'] == 'high')} involve passwords")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
