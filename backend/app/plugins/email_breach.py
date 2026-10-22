"""Email breach exposure checker (defensive OSINT).

Checks whether emails tied to the target appear in PUBLIC breach data:

- HaveIBeenPwned v3 breachedaccount API (needs HIBP_API_KEY in ctx.keys
  as "hibp"; per-account checks only run when the key is present).
- ProxyNova COMB public breach-compilation search (KEYLESS): per-email
  and per-domain lookups that always run, key or no key, and return the
  actual exposed passwords (redacted in findings).
- XposedOrNot keyless API: per-email breach-name lookup.
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
from .base import (Cost, Ctx, Finding, Plugin, PluginResult, Target,
                   safe_json_dict, safe_json_list)
from .secretutils import evidence_block, redact

HIBP_V3 = "https://haveibeenpwned.com/api/v3"
UA = "ReconAnything/1.0"

_PLACEHOLDER_WORDS = {
    "unknown", "redacted", "[redacted]", "not found", "notfound",
    "n/a", "null", "none", "hidden", "placeholder", "changeme",
}


def is_placeholder(pw: str) -> bool:
    """True for mask/placeholder values in breach compilations rather
    than real passwords ("***", "xxxx", "?", "redacted", ...).

    Referenced by _proxynova_email's line parser but never defined -
    any ProxyNova hit with a matching email line raised NameError out
    of run() and the runner discarded ALL of this plugin's findings
    for the target.
    """
    v = pw.strip().lower()
    if not v:
        return True
    if v in _PLACEHOLDER_WORDS:
        return True
    # pure mask strings: only *, x, ?, -, . characters
    return all(c in "*x?-." for c in v)

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
        ran_keyless = False

        # 1) Email-target direct lookup. Keyless checks (ProxyNova COMB
        #    passwords + XposedOrNot breach names) ALWAYS run; HIBP
        #    per-account check runs only with a key.
        if target.type == "email":
            email = target.normalized.strip().lower()
            ran_keyless = await self._proxynova_email(email, ctx, findings)
            if await self._xposedornot_email(email, ctx, findings):
                ran_keyless = True
            if key:
                await self._breached_account(email, ctx, key, findings)
            else:
                findings.append(self._f(
                    "leak", "hibp_note",
                    "HIBP per-account check skipped: no HIBP_API_KEY "
                    "configured (add it in Keys for full breach-account "
                    "verification; keyless compilation search ran above)",
                    source="haveibeenpwned", confidence=50, passive=True,
                    evidence=evidence_block("", "hibp_no_key", "credential",
                                            "low")))

        # 2) Domain-wide: which breaches ever touched this domain
        #    (unauthenticated /breaches endpoint, works without a key).
        domain = domain_from_target(target.type, target.normalized)
        domain_checked = False
        if domain:
            domain_checked = await self._domain_breaches(domain, ctx, findings)

        # 3) Also check harvested emails from the discovery bus (bounded).
        #    Keyless lookups always run; HIBP only with a key.
        emails = [e for e in ctx.consume("emails")][:5]
        if emails and target.type != "email":
            for email in emails:
                email = str(email).strip().lower()
                if "@" not in email:
                    continue
                if await self._proxynova_email(email, ctx, findings):
                    ran_keyless = True
                if await self._xposedornot_email(email, ctx, findings):
                    ran_keyless = True
            if key:
                for email in emails:
                    email = str(email).strip().lower()
                    if "@" in email:
                        await self._breached_account(email, ctx, key, findings)

        # Never silent: a zero must always explain what was checked and
        # what was missing, so Jay never sees an empty plugin again.
        if not findings:
            if not key and not domain_checked and not ran_keyless:
                detail = ("no HIBP_API_KEY configured, and the keyless "
                          "lookups could not be reached")
            elif not key and (domain_checked or ran_keyless):
                detail = ("no HIBP_API_KEY configured; keyless lookups ran "
                          "and found nothing")
            elif not key:
                detail = ("no HIBP_API_KEY configured; the keyless HIBP "
                          "domain lookup ran and this domain appears in no "
                          "known breach")
            elif not domain_checked:
                detail = "HIBP could not be reached for the domain lookup"
            else:
                detail = "HIBP reported no breaches for this target"
            findings.append(self._f(
                "leak", "hibp_note",
                f"Breach check complete, nothing found ({detail}).",
                source="haveibeenpwned", confidence=60, passive=True,
                evidence=evidence_block("", "hibp_no_result", "credential",
                                        "low")))

        dur = int((time.monotonic() - t0) * 1000)
        note = (f"{len(findings)} breach findings"
                + ("" if key else " (keyless only; HIBP_API_KEY adds "
                                 "per-account verification)"))
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
        # Malformed payloads (error object instead of array, bad JSON)
        # degrade to "no data", never raise.
        breaches = safe_json_list(r)
        for b in breaches:
            name = b.get("Name", "?")
            date = b.get("BreachDate", "?")
            classes = b.get("DataClasses") or []
            if not isinstance(classes, list):
                classes = []
            classes = [str(c) for c in classes]
            try:
                pwned = int(b.get("PwnCount", 0) or 0)
            except (ValueError, TypeError):
                pwned = 0
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

    async def _proxynova_email(self, email: str, ctx: Ctx,
                               findings: List[Finding]) -> bool:
        """Keyless per-email breach-compilation lookup via the ProxyNova
        COMB API (public Collection of Many Breaches data). Returns the
        exposed password pairs, redacted. True when the API answered
        (even with zero hits); False when unreachable. Never fails the
        plugin. No key needed."""
        url = f"https://api.proxynova.com/comb?query={quote(email)}"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25,
                            headers={"User-Agent": UA})
        except Exception:
            return False
        if r.status_code != 200:
            return False
        jd = safe_json_dict(r)
        lines = jd.get("lines")
        if not isinstance(lines, list):
            return False
        try:
            count = int(jd.get("count", 0) or 0)
        except (ValueError, TypeError):
            count = 0
        pairs = []
        for line in lines[:50]:
            if not isinstance(line, str) or ":" not in line:
                continue
            addr, _, pw = line.partition(":")
            if addr.strip().lower() != email.lower():
                continue
            pw = pw.strip()
            if not pw or is_placeholder(pw) or len(pw) < 2:
                continue
            pairs.append(pw)
        if pairs:
            samples = ", ".join(redact(p, 2) for p in pairs[:5])
            value = (f"HIGH: {redact(email, 4)} appears in the public COMB "
                     f"breach compilation with {count:,}+ exposed "
                     f"passwords (samples: {samples}). Rotate every "
                     f"password ever used with this email.")
            ev = evidence_block(email, "comb_password_exposure",
                                "credential", "high",
                                {"password_count": count,
                                 "samples_redacted": [redact(p, 2)
                                                      for p in pairs[:10]],
                                 "verify_url": url,
                                 "action": ("Rotate every password ever "
                                            "used with this email; enable "
                                            "2FA everywhere.")})
            findings.append(self._f(
                "leak", "comb_exposure", value,
                source="ProxyNova COMB (keyless public breach data)",
                source_url=url, confidence=90, passive=True, evidence=ev))
        else:
            findings.append(self._f(
                "identity", "comb_clean",
                f"{redact(email, 4)}: not found in the public COMB "
                f"compilation (keyless check)",
                source="ProxyNova COMB (keyless public breach data)",
                confidence=75, passive=True,
                evidence=evidence_block(email, "comb_clean", "credential",
                                        "low")))
        return True

    async def _xposedornot_email(self, email: str, ctx: Ctx,
                                 findings: List[Finding]) -> bool:
        """Keyless per-email breach-name lookup via XposedOrNot. True when
        the API answered; False when unreachable. No key needed."""
        url = f"https://api.xposedornot.com/v1/check-email/{quote(email)}"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25,
                            headers={"User-Agent": UA})
        except Exception:
            return False
        if r.status_code != 200:
            return False
        jd = safe_json_dict(r)
        breaches = jd.get("breaches")
        names: List[str] = []
        if isinstance(breaches, list):
            for b in breaches:
                if isinstance(b, list):
                    names.extend(str(x) for x in b)
                elif isinstance(b, str):
                    names.append(b)
        names = [n for n in names if n and n != "No breaches found"]
        if names:
            value = (f"{redact(email, 4)} appears in {len(names)} public "
                     f"breaches: {', '.join(names[:12])}"
                     + ("..." if len(names) > 12 else ""))
            ev = evidence_block(email, "xposedornot_breaches", "credential",
                                "high", {"breaches": names[:30],
                                          "action": ("Rotate passwords tied "
                                                     "to this email.")})
            findings.append(self._f(
                "leak", "breach_account", value,
                source="XposedOrNot (keyless)", confidence=85,
                passive=True, evidence=ev))
        return True

    async def _domain_breaches(self, domain: str, ctx: Ctx,
                               findings: List[Finding]) -> bool:
        """Keyless domain breach lookup. Returns True when HIBP answered
        (even with zero breaches); False when unreachable. Never fails
        the plugin."""
        url = f"{HIBP_V3}/breaches?domain={quote(domain)}"
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=25,
                            headers={"User-Agent": UA})
        except Exception:
            return False  # unauthenticated helper; never fail the plugin on it
        if r.status_code != 200:
            return False
        breaches = safe_json_list(r)
        for b in breaches[:20]:
            name = b.get("Name", "?")
            date = b.get("BreachDate", "?")
            classes = b.get("DataClasses") or []
            if not isinstance(classes, list):
                classes = []
            classes = [str(c) for c in classes]
            sev = ("high" if any(c.lower() in SENSITIVE_CLASSES
                                 for c in classes)
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
        return True
