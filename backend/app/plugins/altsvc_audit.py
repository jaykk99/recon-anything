"""Alt-Svc header audit plugin (altsvc_audit).

Until this plugin, the scanner knew a site's negotiated protocol (ALPN,
http2_check) but never read the Alt-Svc RESPONSE HEADER (RFC 7838) the
site itself sends - the header that tells browsers "you can also reach
me over HTTP/3 / QUIC, or over there instead". That header is a small
but real trust surface:

- A site advertising h3 is modern; a site advertising only DRAFT h3
  versions (h3-29, h3-Q050, ...) advertises protocols no current
  browser speaks, so the advertisement is dead weight.
- An Alt-Svc entry pointing at a DIFFERENT host routes this origin's
  traffic to another host entirely. If that host is not the site
  owner's, that is a traffic-hijack smell worth a human look.
- Alt-Svc served over plain http is ignored by every browser (the
  header is only valid over a secure transport), so a site sending it
  there is advertising something nobody will ever use.
- A malformed entry is silently ignored by clients, so a typo makes
  the whole advertisement ineffective with no visible error.
- "clear" and "ma=0" are the site explicitly withdrawing an
  advertisement - informational, but worth recording so a disappearing
  h3 advertisement is visible instead of silent.

What this plugin deliberately does NOT do: it never opens a UDP/QUIC
connection, never verifies the advertised alternative service is
reachable, and never follows an Alt-Svc entry to another host. It
reads one header off the target's own homepage response and parses
it. Detection only.

No Alt-Svc header at all is the common case and is NOT a finding:
most sites simply do not advertise alternative services.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..classifier import domain_from_target
from ..net import web_base
from ..ratelimit import fetch
from .base import Cost, Ctx, Finding, Plugin, PluginResult, PluginStatus, Target

# Draft / pre-RFC-9114 HTTP/3 protocol ids. Final HTTP/3 is exactly
# "h3"; anything matching these patterns is a draft no current browser
# negotiates.
_LEGACY_H3_RE = re.compile(r"^h3-(?:\d+|Q\d+)$|^hq-", re.IGNORECASE)

# An Alt-Svc entry: protocol-id="alt-authority" (; param=value)*
_ENTRY_RE = re.compile(
    r'^\s*([A-Za-z0-9._\-/]+)\s*=\s*"([^"]*)"\s*(?:;(.*))?$')

# Alt-authority: [host][:port]; an empty host means "this same host".
_AUTHORITY_RE = re.compile(r"^(?P<host>[^:]*)(?::(?P<port>\d+))?$")

_REMEDIATION = {
    "h3": ("No action - informational. Keep the server / CDN patched "
           "and the h3 advertisement current."),
    "legacy": ("Replace the draft version with the final \"h3\" "
               "advertisement; draft versions are not negotiated by "
               "current browsers."),
    "cross_origin": ("Confirm the alternate host is under the same "
                     "ownership as this origin. If it is not, remove "
                     "the entry: Alt-Svc lets that host serve traffic "
                     "for this origin."),
    "cleartext": ("Remove the cleartext (h2c) advertisement: it invites "
                  "clients to reach this origin without TLS."),
    "ignored_http": ("Alt-Svc is only honoured over HTTPS. Either serve "
                     "this origin over HTTPS or drop the header."),
    "malformed": ("Fix the Alt-Svc syntax so clients can parse it; "
                  "malformed entries are silently ignored."),
    "withdrawn": ("No action - informational. The site explicitly "
                  "withdrew an Alt-Svc advertisement (clear / ma=0)."),
}


class AltSvcEntry:
    """One parsed Alt-Svc entry (or one malformed fragment)."""

    def __init__(self, raw: str):
        self.raw = raw
        self.protocol: Optional[str] = None
        self.host: Optional[str] = None
        self.port: Optional[str] = None
        self.ma: Optional[int] = None
        self.persist: bool = False
        self.malformed: bool = False
        self._parse()

    def _parse(self) -> None:
        m = _ENTRY_RE.match(self.raw)
        if not m:
            self.malformed = True
            return
        self.protocol = m.group(1)
        authority = m.group(2)
        am = _AUTHORITY_RE.match(authority)
        if not am:
            self.malformed = True
            return
        self.host = am.group("host") or ""
        self.port = am.group("port") or ""
        params = m.group(3) or ""
        for param in params.split(";"):
            param = param.strip()
            if not param:
                continue
            if "=" in param:
                key, val = param.split("=", 1)
                key = key.strip().lower()
                val = val.strip().strip('"')
                if key == "ma":
                    try:
                        self.ma = int(val)
                    except ValueError:
                        self.malformed = True
                        return
                elif key == "persist":
                    # RFC 7838 writes persist as persist=1 (bare
                    # "persist" is also accepted defensively).
                    self.persist = val in ("1", "")
            elif param.lower() == "persist":
                self.persist = True
            # Unknown params are legal per RFC 7838 and ignored.

    @property
    def is_clear(self) -> bool:
        return self.raw.strip().lower() == "clear"

    @property
    def is_legacy_h3(self) -> bool:
        return bool(self.protocol) and bool(
            _LEGACY_H3_RE.match(self.protocol))

    @property
    def is_cleartext(self) -> bool:
        return (self.protocol or "").lower() == "h2c"


def _split_entries(value: str) -> List[str]:
    """Split an Alt-Svc value on commas outside quoted strings."""
    entries: List[str] = []
    depth = 0
    current: List[str] = []
    in_quote = False
    for ch in value:
        if ch == '"':
            in_quote = not in_quote
        if ch == "," and not in_quote:
            entries.append("".join(current))
            current = []
            continue
        current.append(ch)
    entries.append("".join(current))
    return [e.strip() for e in entries if e.strip()]


def parse_alt_svc(values: List[str]) -> Tuple[List[AltSvcEntry], bool]:
    """Parse every Alt-Svc header value.

    Returns (entries, saw_clear). A bare "clear" token is reported via
    saw_clear, not as an entry.
    """
    entries: List[AltSvcEntry] = []
    saw_clear = False
    for value in values:
        for fragment in _split_entries(value):
            if fragment.lower() == "clear":
                saw_clear = True
                continue
            entries.append(AltSvcEntry(fragment))
    return entries, saw_clear


def _dedup(entries: List[AltSvcEntry]) -> List[AltSvcEntry]:
    seen = set()
    out: List[AltSvcEntry] = []
    for e in entries:
        key = (e.protocol, e.host, e.port, e.ma, e.persist)
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


class AltSvcAuditPlugin(Plugin):
    id = "altsvc_audit"
    label = "Alt-Svc Header Audit"
    accepts = ["domain", "url"]
    passive = True
    cost = Cost.FREE
    group = "web"
    description = ("Parse the Alt-Svc response header (RFC 7838): HTTP/3 "
                   "advertisements, draft versions, cross-origin "
                   "alternative services, cleartext entries, and "
                   "malformed headers.")

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        domain = domain_from_target(target.type, target.normalized)
        if not domain:
            return self._skipped("no domain for this target type")
        url = await web_base(ctx, target, domain)
        try:
            r = await fetch(ctx.http, ctx.limiter, "GET", url, timeout=20)
        except Exception as e:
            return self._degraded(f"could not fetch {url}: {str(e)[:150]}")

        raw_values = r.headers.get_list("alt-svc", split_commas=False)
        if not raw_values:
            return PluginResult(
                plugin_id=self.id, status=PluginStatus.OK, findings=[],
                duration_ms=int((time.monotonic() - t0) * 1000),
                reason="no Alt-Svc header advertised")
        raw_joined = ", ".join(raw_values)
        entries, saw_clear = parse_alt_svc(raw_values)
        entries = _dedup(entries)
        host = (urlparse(url).hostname or domain).lower()
        scheme = (urlparse(url).scheme or "").lower()

        findings: List[Finding] = []
        evidence_base: Dict[str, str] = {
            "alt_svc": raw_joined[:300],
            "source": "Alt-Svc response header",
        }

        # Alt-Svc over plain http is ignored by browsers outright.
        if scheme == "http":
            findings.append(self._f(
                "web", "altsvc_ignored_http",
                f"{domain} sends an Alt-Svc header over plain HTTP, "
                "which browsers ignore (Alt-Svc is only honoured over "
                "a secure transport): " + raw_joined[:200],
                source="Alt-Svc response header", source_url=url,
                confidence=85, passive=True,
                evidence={**evidence_base, "severity": "low",
                          "remediation": _REMEDIATION["ignored_http"]}))
            return PluginResult(
                plugin_id=self.id, status=PluginStatus.OK,
                findings=findings,
                duration_ms=int((time.monotonic() - t0) * 1000),
                reason="Alt-Svc present but ignored over HTTP")

        if saw_clear:
            findings.append(self._f(
                "web", "altsvc_clear",
                f"{domain} sends Alt-Svc: clear, explicitly clearing "
                "any cached alternative-service advertisement",
                source="Alt-Svc response header", source_url=url,
                confidence=95, passive=True,
                evidence={**evidence_base, "severity": "low",
                          "remediation": _REMEDIATION["withdrawn"]}))

        for e in entries:
            if e.malformed:
                findings.append(self._f(
                    "web", "altsvc_malformed",
                    f"{domain} sends a malformed Alt-Svc entry that "
                    f"clients silently ignore: {e.raw[:200]}",
                    source="Alt-Svc response header", source_url=url,
                    confidence=80, passive=True,
                    evidence={**evidence_base, "severity": "low",
                              "remediation": _REMEDIATION["malformed"]}))
                continue
            if e.ma == 0:
                findings.append(self._f(
                    "web", "altsvc_ma_zero",
                    f"{domain} withdraws its {e.protocol} Alt-Svc "
                    "advertisement (ma=0)",
                    source="Alt-Svc response header", source_url=url,
                    confidence=90, passive=True,
                    evidence={**evidence_base, "severity": "low",
                              "remediation": _REMEDIATION["withdrawn"]}))
                continue
            if e.is_cleartext:
                findings.append(self._f(
                    "web", "altsvc_cleartext",
                    f"{domain} advertises a cleartext alternative "
                    f"service ({e.protocol}) for a secure origin",
                    source="Alt-Svc response header", source_url=url,
                    confidence=85, passive=True,
                    evidence={**evidence_base, "severity": "low",
                              "remediation": _REMEDIATION["cleartext"]}))
            if e.is_legacy_h3:
                findings.append(self._f(
                    "web", "altsvc_legacy_draft",
                    f"{domain} advertises draft HTTP/3 version "
                    f"{e.protocol}, which current browsers do not "
                    "negotiate; advertise final \"h3\" instead",
                    source="Alt-Svc response header", source_url=url,
                    confidence=85, passive=True,
                    evidence={**evidence_base, "severity": "low",
                              "remediation": _REMEDIATION["legacy"]}))
            if e.host and e.host.lower() != host:
                findings.append(self._f(
                    "web", "altsvc_cross_origin",
                    f"{domain} routes this origin's traffic to a "
                    f"different host via Alt-Svc: {e.protocol}="
                    f"\"{e.host}:{e.port or ''}\"",
                    source="Alt-Svc response header", source_url=url,
                    confidence=80, passive=True,
                    evidence={**evidence_base, "severity": "medium",
                              "remediation":
                                  _REMEDIATION["cross_origin"]}))
            if (e.protocol or "").lower() == "h3":
                persist_note = ("; persist=1" if e.persist else "")
                findings.append(self._f(
                    "web", "altsvc_h3_advertised",
                    f"{domain} advertises HTTP/3 via Alt-Svc "
                    f"(h3=\"{e.host}:{e.port or ''}\"; "
                    f"ma={e.ma if e.ma is not None else 86400}"
                    f"{persist_note})",
                    source="Alt-Svc response header", source_url=url,
                    confidence=90, passive=True,
                    evidence={**evidence_base, "severity": "low",
                              "remediation": _REMEDIATION["h3"]}))

        return PluginResult(
            plugin_id=self.id, status=PluginStatus.OK, findings=findings,
            duration_ms=int((time.monotonic() - t0) * 1000),
            reason=f"Alt-Svc parsed: {len(entries)} entries, "
                   f"{len(findings)} findings")
