"""Email breach exposure checker (defensive OSINT).

Checks whether emails tied to the target appear in PUBLIC breach data:

- HaveIBeenPwned v3 breachedaccount API (needs HIBP_API_KEY in ctx.keys
  as "hibp"; skipped gracefully with a note when missing).
- HaveIBeenPwned /breaches?domain= listing (no key needed) for
  domain-wide breach exposure.

Read-only lookups against public breach compilations. No logins, no
brute-forcing, no password attempts anywhere. Every finding names the
breach, the breach date, and exactly which data classes were exposed so
the owner knows what to rotate.
"""
from __future__ import annotations

import time
from typing import List
from urllib.parse import quote

from ..classifier import domain_from_target
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .secretutils import evidence_block

HIBP_V3 = "https://haveibeenpwned.com/api/v3"
UA = "ReconAnything/1.0"

# Data classes that mean "rotate this now".
SENSITIVE_CLASSES = {
    "passwords", "password hints", "email addresses", "usernames",
    "phone numbers", "physical addresses", "dates of birth",
    "security questions and answers", "ip addresses", "auth tokens",
}


class EmailBreachPlugin(Plugin):
    id = "email_breach"
    label = "Email Breach Exposure"
    accepts = ["domain", "url", "email"]
    passive = True
    cost = Cost.FREEMIUM
    group = "identity"
    description = ("Check emails against public breach data (HaveIBeenPwned): "
                   "which breaches, what data was exposed, when.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List[Finding] = []
        key = ctx.keys.get("hibp")

        # 1) Email-target direct lookup: breachedaccount API (needs key).
        if target.type == "email":
            email = target.normalized.strip().lower()
            if key:
                await self._breached_account(email, ctx, key, findings)
            else:
                findings.append(self._f(
                    "leak", "hibp_note",
                    "HIBP account check skipped: no HIBP_API_KEY configured "
                    "(add it in Keys so emails can be checked against "
                    "breach data)",
                    source="haveibeenpwned", confidence=50, passive=True,
                    evidence=evidence_block("", "hibp_no_key", "credential",
                                            "low")))

        # 2) Domain-wide: which breaches ever touched this domain
        #    (unauthenticated /breaches endpoint, works without a key).
        domain = domain_from_target(target.type, target.normalized)
        if domain:
            await self._domain_breaches(domain, ctx, findings)

        # 3) Also check harvested emails from the discovery bus (bounded).
        emails = [e for e in ctx.consume("emails")][:5]
        if key and emails and target.type != "email":
            for email in emails:
                await self._breached_account(email, ctx, key, findings)

        dur = int((time.monotonic() - t0) * 1000)
        note = (f"{len(findings)} breach findings"
                + ("" if key else " (HIBP account checks need API key)"))
        res = self._ok(findings, note)
        res.duration_ms = dur
        return res

    async def _breached_account(self, email: str, ctx: Ctx, key: str,
                                findings: List[Finding]) -> None:
        url = f"{HIBP_V3}/breachedaccount/{quote(email)}"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25,
                            headers={"hibp-api-key": key, "User-Agent": UA})
        except Exception as e:
            findings.append(self._f(
                "leak", "hibp_note", f"HIBP request failed for {email}: "
                f"{str(e)[:120]}", source="haveibeenpwned",
                confidence=40, passive=True,
                evidence=evidence_block(email, "hibp_error", "credential",
                                        "low")))
            return
        if r.status_code == 404:
            findings.append(self._f(
                "identity", "breach_clean",
                f"{email}: not found in any public breach (clean)",
                source="haveibeenpwned", confidence=80, passive=True,
                evidence=evidence_block(email, "hibp_clean", "credential",
                                        "low")))
            return
        if r.status_code == 429:
            findings.append(self._f(
                "leak", "hibp_note", "HIBP rate limited: slow down and retry",
                source="haveibeenpwned", confidence=40, passive=True,
                evidence=evidence_block("", "hibp_429", "credential", "low")))
            return
        if r.status_code in (401, 403):
            findings.append(self._f(
                "leak", "hibp_note",
                f"HIBP rejected the API key (HTTP {r.status_code}): "
                "check the key and re-scan", source="haveibeenpwned",
                confidence=50, passive=True,
                evidence=evidence_block("", "hibp_auth", "credential", "low")))
            return
        if r.status_code != 200:
            findings.append(self._f(
                "leak", "hibp_note",
                f"HIBP returned HTTP {r.status_code} for {email}",
                source="haveibeenpwned", confidence=40, passive=True,
                evidence=evidence_block(email, "hibp_http", "credential",
                                        "low")))
            return
        try:
            breaches = r.json()
        except Exception:
            return
        for b in breaches:
            name = b.get("Name", "?")
            date = b.get("BreachDate", "?")
            classes = b.get("DataClasses") or []
            pwned = b.get("PwnCount", 0)
            hot = any(c.lower() in SENSITIVE_CLASSES for c in classes)
            sev = "high" if hot else "medium"
            value = (f"{email} found in breach '{name}' ({date}, "
                     f"{pwned:,} accounts). Exposed: {', '.join(classes[:8])}")
            ev = evidence_block(email, "hibp_breach", "credential", sev,
                                {"breach": name, "breach_date": date,
                                 "data_classes": classes,
                                 "pwn_count": pwned, "verified": b.get(
                                     "IsVerified", False)})
            findings.append(self._f(
                "leak", "breach_account", value, source="haveibeenpwned",
                source_url="https://haveibeenpwned.com/", confidence=95,
                passive=True, evidence=ev))

    async def _domain_breaches(self, domain: str, ctx: Ctx,
                               findings: List[Finding]) -> None:
        url = f"{HIBP_V3}/breaches?domain={quote(domain)}"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25,
                            headers={"User-Agent": UA})
        except Exception:
            return  # unauthenticated helper; never fail the plugin on it
        if r.status_code != 200:
            return
        try:
            breaches = r.json()
        except Exception:
            return
        for b in breaches[:20]:
            name = b.get("Name", "?")
            date = b.get("BreachDate", "?")
            classes = b.get("DataClasses") or []
            sev = ("high" if any(c.lower() in SENSITIVE_CLASSES for c in classes)
                   else "low")
            value = (f"Domain breach '{name}' ({date}) exposed data tied to "
                     f"{domain}: {', '.join(classes[:8])}")
            ev = evidence_block(domain, "hibp_domain_breach", "credential",
                                sev, {"breach": name, "breach_date": date,
                                      "data_classes": classes})
            findings.append(self._f(
                "leak", "breach_domain", value, source="haveibeenpwned",
                source_url="https://haveibeenpwned.com/", confidence=85,
                passive=True, evidence=ev))
