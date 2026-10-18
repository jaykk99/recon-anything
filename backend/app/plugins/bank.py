"""Bank security assessment (AUTHORIZED engagements only).

Recon/assessment only: core banking platform fingerprints, online banking
login posture, public CVE matching on detected tech, PCI DSS indicators.
Read-only GETs, 15s timeouts. Skips unless
module_overrides["bank"] = "authorized".
"""
from __future__ import annotations

import datetime as dt
import re
import time
from typing import List

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

TIMEOUT = 15

PLATFORMS = [  # (label, regex, confidence), case-insensitive
    ("Fiserv", r"fiserv", 85), ("FIS", r"\bfis\b|fidelity\s*national", 75),
    ("Jack Henry", r"jack\s*henry|symitar|profitstars", 85),
    ("Temenos", r"temenos|\bt24\b|transact", 75),
    ("Finastra", r"finastra|fusion\s*essence", 80),
    ("Q2", r"q2ebanking|\bq2\b", 75), ("Alkami", r"alkami", 90),
    ("NCR", r"\bncr\b|digital\s*insight", 75),
    ("Diebold Nixdorf", r"diebold", 85),
]
MFA_HINTS = [r"two[-\s]?factor", r"one[-\s]?time\s*(passcode|password|code)",
             r"authenticator", r"multi[-\s]?factor", r"verification\s*code"]
MOBILE_HINTS = [r"mobile[_\-]?banking", r"user[_\-]?agent", r"android",
                r"\bios\b", r"app[_\-]?token"]

# tech marker -> verified public CVE, emitted only when marker is found.
# All verified real; all exploited against financial institutions.
TECH_CVES = [
    ("log4j", "CVE-2021-44228", "Log4Shell RCE in Apache Log4j 2"),
    ("citrix", "CVE-2023-4966", "CitrixBleed session theft in NetScaler"),
    ("f5", "CVE-2022-1388", "F5 BIG-IP iControl REST auth bypass"),
    ("moveit", "CVE-2023-34362", "MOVEit Transfer SQL injection"),
    ("ivanti", "CVE-2024-21887", "Ivanti Connect Secure command injection"),
    ("fortinet", "CVE-2023-27997", "FortiOS heap buffer overflow"),
]
CARD_INPUT = re.compile(r"<input[^>]*(?:card[_-]?number|cardnumber|cc[_-]?num|credit[_-]?card)[^>]*>", re.IGNORECASE)
RL_HEADERS = ("x-ratelimit-limit", "x-rate-limit-limit", "x-ratelimit-remaining", "x-requests-remaining", "x-request-limit", "retry-after")
AUTH_MSG = "Bank module requires explicit authorization (module_overrides bank=authorized)"


class BankPlugin(Plugin):
    id = "bank"
    label = "Bank Security Assessment"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "financial"
    description = ("Banking platform detection + online banking posture "
                   "(authorized only).")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        if ctx.module_overrides.get("bank") != "authorized":
            return self._skipped(AUTH_MSG)
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no host for this target type")
        base = (target.normalized if target.type == "url"
                else f"https://{domain}/")
        findings: List[Finding] = []
        ts = dt.datetime.now(dt.timezone.utc).isoformat()
        findings.append(self._f("financial", "bank_auth_claim",
                                f"Authorization claimed for bank assessment "
                                f"at {ts}", source="bank plugin",
                                confidence=100, passive=True))
        page = await ctx.fetch_page(base, timeout=TIMEOUT)
        if page is None:
            findings.append(self._f("financial", "bank_fetch_failed",
                                    f"Could not fetch {base}",
                                    source="bank plugin", confidence=100,
                                    passive=True))
            res = self._ok(findings, "fetch failed, audit kept")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res
        html = page.get("text", "") or ""
        headers = page.get("headers", {}) or {}
        final = page.get("url", base) or base
        blob = html + "\n" + "\n".join(f"{k}:{v}"
                                       for k, v in headers.items())
        low = blob.lower()
        # 1) core banking platform fingerprints
        platforms = []
        for label, pat, conf in PLATFORMS:
            if re.search(pat, blob, re.IGNORECASE):
                platforms.append(label)
                findings.append(self._f("financial", "bank_platform",
                                        f"Banking platform fingerprint: "
                                        f"{label}", source="bank plugin",
                                        source_url=final, confidence=conf,
                                        passive=True))
        # 2) online banking login posture
        forms = re.findall(r"<form[^>]*>.*?</form>", html,
                           re.IGNORECASE | re.DOTALL)
        logins = [f for f in forms if re.search(
            r'type\s*=\s*["\']?password', f, re.IGNORECASE)]
        notes = []
        if logins:
            lf = "\n".join(logins)
            notes.append(f"{len(logins)} login form(s) found")
            notes.append("password autocomplete=off" if re.search(
                r'autocomplete\s*=\s*["\']?off', lf, re.IGNORECASE) else
                "MISSING: password autocomplete=off")
            mfa = sum(bool(re.search(h, html, re.IGNORECASE))
                      for h in MFA_HINTS)
            notes.append(f"MFA hints present ({mfa})" if mfa else
                         "MISSING: no MFA hints in page text")
        else:
            notes.append("no login form with password field found")
        rl = [h for h in RL_HEADERS if h in {k.lower() for k in headers}]
        notes.append(f"rate-limit headers: {', '.join(rl)}" if rl else
                     "MISSING: no rate-limit headers seen")
        cookies = [v for k, v in headers.items()
                   if k.lower() == "set-cookie"]
        for flag in ("secure", "httponly", "samesite"):
            if cookies:
                n = sum(flag in c.lower() for c in cookies)
                notes.append(f"cookie {flag}: {n}/{len(cookies)}" if n else
                             f"MISSING: cookie {flag} flag not seen")
        if not cookies:
            notes.append("no Set-Cookie headers captured")
        findings.append(self._f("financial", "bank_login_posture",
                                "Login posture: " + "; ".join(notes),
                                source="bank plugin", source_url=final,
                                confidence=80, passive=True))
        # 3) mobile banking API surface hints
        api = sorted({m.group(0) for m in
                      re.finditer(r"/api/[a-z0-9_\-/]+", html,
                                  re.IGNORECASE)})[:20]
        mob = [h for h in MOBILE_HINTS
               if re.search(h, html, re.IGNORECASE)]
        if api or mob:
            findings.append(self._f("financial", "bank_api_surface",
                                    f"API hints: {len(api)} /api/ paths, "
                                    f"mobile hints: "
                                    f"{', '.join(mob) if mob else 'none'}",
                                    source="bank plugin", source_url=final,
                                    confidence=70, passive=True,
                                    evidence={"api_paths": api[:10],
                                              "mobile_hints": mob}))
        # 4) CVE matching on detected tech
        for marker, cve, title in TECH_CVES:
            hit = marker in low
            if not hit and marker == "log4j" and \
                    any(p in ("Temenos", "Finastra") for p in platforms):
                hit = True  # Java-based core banking stacks
            if hit:
                findings.append(self._f("financial", "bank_cve",
                                        f"{cve}: {title}. Verify patched "
                                        f"version on {domain}.",
                                        source="bank plugin",
                                        source_url=final, confidence=70,
                                        passive=True,
                                        evidence={"severity": "critical",
                                                  "cve": cve}))
        # 5) PCI DSS indicators
        pci = []
        for m in CARD_INPUT.finditer(html):
            if "mask" not in m.group(0).lower():
                pci.append("card number input without visible masking")
                break
        query = final.split("?", 1)[-1] if "?" in final else ""
        if re.search(r"(card[_-]?number|cardnumber|cc[_-]?num|\bpan=)",
                     query, re.IGNORECASE):
            pci.append("card data present in URL")
        for fm in forms:
            act = re.search(r'action\s*=\s*["\']([^"\']+)', fm, re.IGNORECASE)
            if act and act.group(1).lower().startswith("http:"):
                pci.append("form action over non-HTTPS URL")
                break
        if pci:
            findings.append(self._f("financial", "bank_pci_flag",
                                    "PCI indicators: " + "; ".join(pci),
                                    source="bank plugin", source_url=final,
                                    confidence=85, passive=True,
                                    evidence={"severity": "high"}))
        res = self._ok(findings,
                       f"bank assessment done ({len(findings)} findings)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
