"""DNS-over-HTTPS / SNI extractor: inventories resolver destinations
and TLS SNI values from operator-supplied captures, and checks the
target's own HTTPS/SVCB records for an exposed DoH endpoint.

Lane 1 (supplied captures): SNI values are pulled from TLS
ClientHello bytes inside a supplied pcap (minimal record parser)
or from text logs; DoH queries are pulled from dns-query URLs /
dns.google-style JSON in the same artifacts. Internal hostnames
leaking to an external resolver are the finding.
Lane 2 (live, read-only): one DoH query (dns.google, keyless) for
the target's HTTPS records; a dohpath / DoH endpoint advertised on
the target's own hosts is reported as exposure posture.

BOUNDARY: supplied captures only for traffic data; the live lane is
a single public-resolver query about the target itself.
"""
from __future__ import annotations

import json
import re
import struct
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import (collect, is_private_ip, packet_payloads,
                           parse_pcap, text_of)

_INTERNAL_SUFFIX = (".internal", ".corp", ".lan", ".local", ".intranet",
                    ".home.arpa")
_DOH_URL_RE = re.compile(
    r"(?i)(?:dns-query|/resolve)\?[^\s\"']*?(?:name=|qname=)([a-z0-9.\-]+)")
_SNI_LOG_RE = re.compile(r"(?i)\bSNI[:=\s]+([a-z0-9.\-]+\.[a-z]{2,})")


def _is_internal(host: str) -> bool:
    h = (host or "").lower()
    return h.endswith(_INTERNAL_SUFFIX) or "." not in h


def extract_sni_from_tcp(payload: bytes) -> List[str]:
    """Minimal TLS ClientHello SNI extraction. Never raises."""
    snis: List[str] = []
    try:
        pos = 0
        while pos + 5 <= len(payload):
            if payload[pos] != 0x16:  # handshake record
                break
            rlen = struct.unpack_from(">H", payload, pos + 3)[0]
            rec = payload[pos + 5:pos + 5 + rlen]
            if len(rec) < 4 or rec[0] != 0x01:  # ClientHello
                break
            # session id + cipher suites + compression walk to exts
            p = 4 + 2 + 32
            if p >= len(rec):
                break
            sid_len = rec[p]
            p += 1 + sid_len
            if p + 2 > len(rec):
                break
            cs_len = struct.unpack_from(">H", rec, p)[0]
            p += 2 + cs_len
            if p >= len(rec):
                break
            comp_len = rec[p]
            p += 1 + comp_len
            if p + 2 > len(rec):
                break
            ext_total = struct.unpack_from(">H", rec, p)[0]
            p += 2
            end = min(p + ext_total, len(rec))
            while p + 4 <= end:
                etype, elen = struct.unpack_from(">HH", rec, p)
                p += 4
                ext = rec[p:p + elen]
                if etype == 0 and len(ext) >= 5:  # server_name
                    q = 2
                    while q + 3 <= len(ext):
                        ntype = ext[q]
                        nlen = struct.unpack_from(
                            ">H", ext, q + 1)[0]
                        name = ext[q + 3:q + 3 + nlen].decode(
                            "utf-8", "ignore")
                        if ntype == 0 and name:
                            snis.append(name)
                        q += 3 + nlen
                p += elen
            pos += 5 + rlen
    except Exception:
        pass
    return snis


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    hosts = set()
    pcap = parse_pcap(data)
    if pcap.get("ok"):
        for p in packet_payloads(pcap):
            if p["proto"] == "tcp" and p["data"]:
                for s in extract_sni_from_tcp(p["data"]):
                    hosts.add(s.lower())
    text = text_of(data)
    for m in _SNI_LOG_RE.finditer(text):
        hosts.add(m.group(1).lower())
    doh_hosts = {m.group(1).lower() for m in _DOH_URL_RE.finditer(text)}
    internal_sni = sorted(h for h in hosts if _is_internal(h))
    internal_doh = sorted(h for h in doh_hosts if _is_internal(h))
    for h in internal_doh[:6]:
        hits.append({
            "key": "doh_internal_name_leak", "severity": "medium",
            "value": f"Internal hostname '{h}' queried over DNS-over-"
                     "HTTPS in supplied capture - internal naming "
                     "leaks to an external resolver",
            "evidence": {"hostname": h, "via": "doh",
                         "remediation": "Route internal zones to the "
                         "internal resolver only (split-horizon DNS); "
                         "DoH to public resolvers must not carry "
                         "internal names."}})
    for h in internal_sni[:6]:
        if h in internal_doh:
            continue
        hits.append({
            "key": "sni_internal_name_exposure", "severity": "low",
            "value": f"Internal hostname '{h}' exposed as cleartext "
                     "TLS SNI in supplied capture",
            "evidence": {"hostname": h, "via": "sni",
                         "remediation": "SNI is cleartext: avoid "
                         "descriptive internal hostnames on externally "
                         "reachable TLS services, or front them with "
                         "ECH / a generic external name."}})
    if "application/dns-message" in text and (
            "/dns-query" in text):
        hits.append({
            "key": "doh_endpoint_in_capture", "severity": "low",
            "value": "DoH endpoint traffic (application/dns-message "
                     "at /dns-query) present in supplied capture - "
                     "inventory the resolver destination before "
                     "trusting it",
            "evidence": {"content_type": "application/dns-message"}})
        # An inventory note alone is not a posture finding.
        hits.pop()
    return hits[:10]


def analyze_svcb(payload: Dict[str, Any], target_host: str
                 ) -> List[Dict[str, Any]]:
    """Hits from a DoH JSON answer for the target's HTTPS records."""
    hits: List[Dict[str, Any]] = []
    for ans in (payload or {}).get("Answer", []) or []:
        data = str(ans.get("data", ""))
        if "dohpath=" in data or "/dns-query" in data:
            hits.append({
                "key": "doh_endpoint_exposed", "severity": "medium",
                "value": f"{target_host} advertises a DNS-over-HTTPS "
                         f"endpoint in its HTTPS/SVCB record: "
                         f"{data[:160]}",
                "evidence": {"record": data[:300],
                             "remediation": "A public DoH endpoint is "
                             "an open resolver: require "
                             "authentication / rate limits or remove "
                             "the dohpath advertisement."}})
    return hits


class DnsOverHttpsSniExtractorPlugin(Plugin):
    id = "dns_over_https_sni_extractor"
    label = "DNS-over-HTTPS / SNI Extractor"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "network"
    phase = 2
    description = ("Extracts TLS SNI + DoH query hostnames from "
                   "supplied captures (internal-name leak focus) and "
                   "checks the target's HTTPS/SVCB records for an "
                   "exposed DoH endpoint.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "dns",
                          ("sni_captures", "doh_captures"))
            if got is not None:
                return got
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
        # Live lane: one keyless DoH query for the target's own
        # HTTPS records.
        host = (target.normalized or "").split("/")[0].split(":")[0]
        if not host or "." not in host:
            return self._ok([], "no supplied capture and no domain "
                            "for the SVCB live lane")
        try:
            from ..ratelimit import fetch as _fetch
            resp = await _fetch(
                ctx.http, ctx.limiter, "GET",
                "https://dns.google/resolve?name="
                f"{host}&type=HTTPS",
                timeout=8, follow_redirects=True)
            payload = resp.json() if resp is not None else {}
        except Exception:
            return self._degraded("DoH resolver query failed")
        findings = []
        for hit in analyze_svcb(payload if isinstance(payload, dict)
                                else {}, host):
            ev = {"severity": hit["severity"],
                  "remediation": (hit.get("evidence") or {}).get(
                      "remediation", "")}
            ev.update(hit.get("evidence") or {})
            findings.append(self._f("dns", hit["key"], hit["value"],
                                    source="DoH HTTPS-record query",
                                    confidence=80, evidence=ev))
        return self._ok(findings, "SVCB/HTTPS record check complete")
