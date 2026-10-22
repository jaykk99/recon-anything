"""Email infrastructure security (defensive OSINT).

Audits the target's email authentication posture from public DNS only:

- SPF: present? too permissive (+all / ?all)? >10 DNS lookups (permerror)?
- DMARC: _dmarc record present? policy none/quarantine/reject? alignment?
- DKIM: any signing selector published (_domainkey)?
- MX: mail provider identification, missing MX.

Rolls up into an email spoofing risk rating so the owner knows whether
attackers can send mail that looks like it comes from this domain.
Read-only DNS lookups. No packets to the target's mail servers.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple

import dns.asyncresolver
import asyncio
import dns.resolver

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .secretutils import evidence_block

# Common DKIM selectors worth probing.
DKIM_SELECTORS = [
    "default", "selector1", "selector2", "google", "k1", "k2",
    "mail", "dkim", "s1", "s2", "everlytick", "mandrill", "cm",
    "protonmail", "zoho", "mxvault",
]

MX_PROVIDERS = [
    ("google", "Google Workspace / Gmail"),
    ("outlook", "Microsoft 365 / Outlook"),
    ("protection.outlook", "Microsoft 365 / Outlook"),
    ("zoho", "Zoho Mail"),
    ("protonmail", "Proton Mail"),
    ("yandex", "Yandex Mail"),
    ("mailgun", "Mailgun"),
    ("sendgrid", "SendGrid"),
    ("amazonses", "Amazon SES"),
    ("pphosted", "Proofpoint"),
    ("mimecast", "Mimecast"),
]

SPF_MECH = re.compile(r"(?i)([+\-~?]?)(all|include|a|mx|ptr|ip4|ip6|exists|redirect)")


def _resolvers() -> List[dns.asyncresolver.Resolver]:
    out = []
    try:
        r = dns.asyncresolver.Resolver()
        r.lifetime = 8
        out.append(r)
    except Exception:
        pass
    for ns in ("8.8.8.8", "1.1.1.1"):
        try:
            r = dns.asyncresolver.Resolver(configure=False)
            r.nameservers = [ns]
            r.lifetime = 8
            out.append(r)
        except Exception:
            continue
    return out


async def _txt(name: str) -> List[str]:
    for rs in _resolvers():
        try:
            ans = await rs.resolve(name, "TXT")
            return [str(x).strip('"') for x in ans]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception:
            continue
    return []


async def _mx(domain: str) -> List[Tuple[int, str]]:
    for rs in _resolvers():
        try:
            ans = await rs.resolve(domain, "MX")
            return sorted((r.preference, str(r.exchange).rstrip(".").lower())
                          for r in ans)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception:
            continue
    return []


async def _a(name: str) -> bool:
    """True if the name resolves to any A/AAAA address (DNS only)."""
    for rs in _resolvers():
        try:
            await rs.resolve(name, "A")
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
        except Exception:
            continue
    return False


# Mail-flavored subdomain names worth resolving for any target domain.
MAIL_SUBDOMAINS = [
    "mail", "webmail", "smtp", "imap", "pop", "pop3", "autodiscover",
    "owa", "exchange", "mx", "mail2", "sogo",
]

# Subset that commonly serves a web login when it resolves.
WEBMAIL_HOSTS = {"webmail", "owa", "exchange", "mail", "sogo"}

# (marker, product) for webmail login surface identification. Markers are
# matched against the page title/body of a plain GET - an observation of
# what the surface IS, never a login attempt.
WEBMAIL_PRODUCTS = [
    ("roundcube", "Roundcube Webmail"),
    ("zimbra", "Zimbra Collaboration"),
    ("outlook web", "Outlook Web App (Exchange)"),
    ("oustorage", "Outlook Web App (Exchange)"),
    ("horde", "Horde Groupware Webmail"),
    ("squirrelmail", "SquirrelMail"),
    ("cpanel", "cPanel Webmail"),
    ("mailenable", "MailEnable WebMail"),
    ("smartermail", "SmarterMail"),
    ("kerio", "Kerio Connect WebMail"),
    ("icewarp", "IceWarp WebClient"),
    ("sogo", "SOGo Groupware"),
]


class EmailInfraPlugin(Plugin):
    id = "email_infra"
    label = "Email Security Posture"
    accepts = ["domain", "url", "email"]
    passive = True
    cost = Cost.FREE
    group = "identity"
    description = ("Audit email spoofing defenses: SPF, DKIM, DMARC, MX "
                   "provider. Scores spoofing risk.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        findings: List[Finding] = []
        state: Dict[str, Optional[str]] = {
            "spf": None, "dmarc_policy": None, "dkim": None, "mx": None,
        }

        # SPF/DMARC/DKIM/MX checks are independent DNS lookups: run them
        # concurrently instead of sequentially. Same checks, same
        # findings - just in parallel.
        await asyncio.gather(
            self._check_spf(domain, findings, state),
            self._check_dmarc(domain, findings, state),
            self._check_dkim(domain, findings, state),
            self._check_mx(domain, findings, state, ctx),
            self._check_mail_surfaces(domain, findings, ctx),
        )
        self._spoofing_risk(domain, findings, state)

        dur = int((time.monotonic() - t0) * 1000)
        res = self._ok(findings, f"email posture audit for {domain}")
        res.duration_ms = dur
        return res

    async def _check_spf(self, domain: str, findings: List[Finding],
                         state: Dict) -> None:
        records = [t for t in await _txt(domain)
                   if t.lower().startswith("v=spf1")]
        if not records:
            findings.append(self._f(
                "infra", "spf_missing",
                f"{domain}: NO SPF record. Anyone can send mail as this "
                f"domain and receivers cannot tell it is forged.",
                source="DNS TXT", confidence=95, passive=True,
                evidence=evidence_block("", "spf_missing", "credential",
                                        "high", {"fix": (
                                            "Publish a TXT record like "
                                            "'v=spf1 include:_spf.google.com "
                                            "-all' listing only your real "
                                            "senders.")})))
            state["spf"] = "missing"
            return
        if len(records) > 1:
            # RFC 7208: more than one SPF record = permerror everywhere;
            # receivers treat the domain as having NO usable SPF.
            findings.append(self._f(
                "infra", "spf_multiple_records",
                f"{domain}: {len(records)} SPF records published. "
                f"Multiple SPF records cause a permanent error - "
                f"receivers fall back to treating the domain as "
                f"unprotected.",
                source="DNS TXT", confidence=95, passive=True,
                evidence=evidence_block(
                    " | ".join(r[:60] for r in records),
                    "spf_multiple_records", "credential", "high",
                    {"fix": "Merge all senders into ONE v=spf1 record."})))
        spf = records[0]
        state["spf"] = spf
        sev = "low"
        notes = []
        low = spf.lower()
        if "+all" in low or " ?all" in spf or spf.strip().endswith("?all"):
            sev = "high"
            notes.append("uses +all/?all: authorizes the entire internet")
        elif "~all" in low:
            sev = "medium"
            notes.append("uses ~all (softfail): receivers usually still accept")
        elif "-all" in low:
            notes.append("hardfail (-all): correct")
        lookups = len(re.findall(r"(?i)include:|redirect=|exists:", spf))
        if lookups > 10:
            sev = max(sev, "medium",
                      key=lambda s: ("low", "medium", "high").index(s))
            notes.append(f"{lookups} DNS lookups: over the 10-lookup limit, "
                         "SPF can permerror")
        value = f"{domain} SPF: {spf[:160]}" + (f" [{'; '.join(notes)}]"
                                                if notes else " [looks sane]")
        findings.append(self._f(
            "infra", "spf_record", value, source="DNS TXT",
            confidence=95, passive=True,
            evidence=evidence_block(spf, "spf_record", "credential", sev,
                                    {"issues": notes})))

    async def _check_dmarc(self, domain: str, findings: List[Finding],
                           state: Dict) -> None:
        records = [t for t in await _txt(f"_dmarc.{domain}")
                   if "v=dmarc1" in t.lower()]
        if not records:
            findings.append(self._f(
                "infra", "dmarc_missing",
                f"{domain}: NO DMARC record. No policy tells receivers what "
                f"to do with forged mail from this domain.",
                source="DNS TXT", confidence=95, passive=True,
                evidence=evidence_block("", "dmarc_missing", "credential",
                                        "high", {"fix": (
                                            "Publish TXT at _dmarc.<domain>: "
                                            "'v=DMARC1; p=quarantine; "
                                            "rua=mailto:dmarc@<domain>' and "
                                            "tighten to p=reject once "
                                            "legit mail passes.")})))
            state["dmarc_policy"] = "missing"
            return
        dmarc = records[0]
        m = re.search(r"(?i)p\s*=\s*(none|quarantine|reject)", dmarc)
        policy = m.group(1).lower() if m else "unknown"
        state["dmarc_policy"] = policy
        sev = {"none": "medium", "quarantine": "low",
               "reject": "low"}.get(policy, "medium")
        note = {"none": "p=none only monitors, does not block forgeries",
                "quarantine": "quarantine: forgeries go to spam",
                "reject": "reject: forgeries are dropped (best)"}.get(
                    policy, "policy unclear")
        # Enforcement detail: pct= below 100 means a share of failing
        # mail is deliberately exempted; alignment modes decide how
        # strictly SPF/DKIM identities must match the From domain.
        extras: Dict = {"policy": policy}
        pm = re.search(r"(?i)pct\s*=\s*(\d+)", dmarc)
        pct = int(pm.group(1)) if pm else 100
        extras["pct"] = pct
        for tag, label in (("aspf", "spf_alignment"),
                           ("adkim", "dkim_alignment")):
            am = re.search(rf"(?i){tag}\s*=\s*([rs])", dmarc)
            extras[label] = ("strict" if am and am.group(1).lower() == "s"
                             else "relaxed")
        if "sp=" not in dmarc.lower() and policy != "none":
            extras["subdomain_policy"] = "inherits p= (no sp= set)"
        if "rua=" not in dmarc.lower():
            extras["reporting"] = "no rua= aggregate reports configured"
        findings.append(self._f(
            "infra", "dmarc_record",
            f"{domain} DMARC policy: p={policy} ({note})",
            source="DNS TXT", confidence=95, passive=True,
            evidence=evidence_block(dmarc, "dmarc_record", "credential",
                                    sev, extras)))
        if pct < 100:
            findings.append(self._f(
                "infra", "dmarc_partial_enforcement",
                f"{domain}: DMARC pct={pct} - only {pct}% of mail that "
                f"fails DMARC gets the p={policy} treatment; the rest "
                f"is delivered as if there were no policy.",
                source="DNS TXT", confidence=95, passive=True,
                evidence=evidence_block(
                    dmarc, "dmarc_partial_enforcement", "credential",
                    "medium",
                    {"fix": "Raise pct to 100 once monitoring shows "
                            "legit senders pass alignment."})))

    async def _check_dkim(self, domain: str, findings: List[Finding],
                          state: Dict) -> None:
        found = []
        for sel in DKIM_SELECTORS:
            name = f"{sel}._domainkey.{domain}"
            recs = await _txt(name)
            if any("v=dkim1" in r.lower() for r in recs):
                found.append(sel)
            if len(found) >= 3:
                break
        if found:
            state["dkim"] = ",".join(found)
            findings.append(self._f(
                "infra", "dkim_present",
                f"{domain}: DKIM signing selectors published: "
                f"{', '.join(found)}",
                source="DNS TXT", confidence=90, passive=True,
                evidence=evidence_block(",".join(found), "dkim_present",
                                        "credential", "low")))
        else:
            state["dkim"] = "missing"
            findings.append(self._f(
                "infra", "dkim_missing",
                f"{domain}: no common DKIM selector found. Outbound mail "
                f"is likely unsigned, which weakens DMARC enforcement.",
                source="DNS TXT", confidence=80, passive=True,
                evidence=evidence_block("", "dkim_missing", "credential",
                                        "medium", {"fix": (
                                            "Enable DKIM signing in your mail "
                                            "provider and publish the selector "
                                            "it gives you.")})))

    async def _check_mx(self, domain: str, findings: List[Finding],
                        state: Dict, ctx: Ctx = None) -> None:
        mxs = await _mx(domain)
        if not mxs:
            state["mx"] = "missing"
            findings.append(self._f(
                "infra", "mx_missing",
                f"{domain}: no MX records. Domain cannot receive mail; "
                f"verify this is intentional.",
                source="DNS MX", confidence=95, passive=True,
                evidence=evidence_block("", "mx_missing", "credential",
                                        "low")))
            return
        hosts = [h for _, h in mxs]
        state["mx"] = ",".join(hosts[:3])
        if ctx is not None:
            for h in hosts:
                if h.endswith("." + domain) or h == domain:
                    ctx.publish("subdomains", h)
        provider = "self-hosted / unknown"
        for needle, label in MX_PROVIDERS:
            if any(needle in h for h in hosts):
                provider = label
                break
        findings.append(self._f(
            "infra", "mx_records",
            f"{domain} MX: {', '.join(hosts[:5])} ({provider})",
            source="DNS MX", confidence=95, passive=True,
            evidence=evidence_block(",".join(hosts), "mx_records",
                                    "credential", "low",
                                    {"provider": provider})))

    async def _check_mail_surfaces(self, domain: str,
                                   findings: List[Finding],
                                   ctx: Ctx) -> None:
        """Mail subdomains + exposed mail login surfaces (observations).

        DNS-only discovery of mail-flavored subdomains; for the hosts
        that commonly serve a web login, one plain GET identifies the
        product from the page. No login attempt, no credential anything -
        the finding is that the surface exists and what it runs.
        """
        results = await asyncio.gather(
            *[_a(f"{sub}.{domain}") for sub in MAIL_SUBDOMAINS])
        alive = [f"{sub}.{domain}" for sub, ok
                 in zip(MAIL_SUBDOMAINS, results) if ok]
        if not alive:
            return
        for fqdn in alive:
            ctx.publish("subdomains", fqdn)
        findings.append(self._f(
            "infra", "mail_subdomains",
            f"{domain} mail subdomains resolve: {', '.join(alive)}",
            source="DNS A", confidence=90, passive=True,
            evidence=evidence_block(
                ",".join(alive), "mail_subdomains", "credential", "low",
                {"why": "Mail-named subdomains map the mail attack "
                        "surface: credential phishing, password spraying "
                        "targets, and autoconfig endpoints live here."})))
        for fqdn in alive:
            sub = fqdn.split(".")[0]
            if sub not in WEBMAIL_HOSTS:
                continue
            url = f"https://{fqdn}/"
            try:
                page = await ctx.fetch_page(url, timeout=12)
            except Exception:
                page = None
            status = (page or {}).get("status_code", (page or {}).get(
                "status"))
            if not page or status not in (200, 301, 302, 401):
                continue
            text = (page.get("text") or "")[:60000].lower()
            product = next((label for marker, label in WEBMAIL_PRODUCTS
                            if marker in text), None)
            findings.append(self._f(
                "infra", "mail_login_surface",
                f"Mail login surface exposed: {url} "
                f"({product or 'unidentified webmail'}) "
                f"[HTTP {status}]",
                source="webmail surface check", source_url=url,
                confidence=85, passive=True,
                evidence=evidence_block(
                    url, "mail_login_surface", "credential", "medium",
                    {"product": product or "unknown",
                     "why": "A public mail login is the top target for "
                            "credential phishing and password spraying "
                            "against the org's mailboxes. Observation "
                            "only: no login was attempted."})))

    def _spoofing_risk(self, domain: str, findings: List[Finding],
                       state: Dict) -> None:
        spf, dmarc = state["spf"], state["dmarc_policy"]
        if spf == "missing" and dmarc == "missing":
            risk, why = "high", ("no SPF and no DMARC: attackers can send "
                                 "mail as this domain with no receiver-side "
                                 "defense")
        elif dmarc in ("missing", "none") or (spf and "+all" in spf):
            risk, why = "medium", ("partial defenses: DMARC missing or "
                                   "monitor-only, or SPF authorizes too much")
        elif dmarc in ("quarantine", "reject"):
            risk, why = "low", (f"DMARC p={dmarc} with SPF present: "
                                 "forgeries are handled by receivers")
        else:
            risk, why = "medium", "email auth posture is incomplete"
        findings.append(self._f(
            "infra", "email_spoofing_risk",
            f"{domain} email spoofing risk: {risk.upper()} ({why})",
            source="email posture rollup", confidence=90, passive=True,
            evidence=evidence_block(why, "spoofing_risk", "credential", risk,
                                    {"spf": str(spf)[:80],
                                     "dmarc": str(dmarc),
                                     "dkim": str(state["dkim"]),
                                     "mx": str(state["mx"])[:80]})))
