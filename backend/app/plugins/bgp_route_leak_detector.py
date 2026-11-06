"""BGP route leak detector: RPKI validity, origin-AS mismatches and
AS-path anomalies for the target's prefixes, from keyless public
BGP data (RIPEstat-style) or operator-supplied route records.

Read-only public data - no BGP session is ever established. The
pure analyzer consumes route records of the shape:
  {"prefix": ..., "origin_as": ..., "announced_by": ...,
   "rpki_status": "valid|invalid|unknown|notfound",
   "as_path": [asn, ...], "received_from": "peer|provider|customer",
   "sent_to": "peer|provider|customer"}
Flags: RPKI-invalid origins, origin mismatches, RFC 7908-shaped
leak propagation (peer/provider-learned route re-announced to
another peer/provider), private/reserved ASNs in path, AS loops.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, text_of

_PRIVATE_AS = [(64512, 65534), (4200000000, 4294967294)]


def _records(data: bytes) -> List[Dict[str, Any]]:
    text = text_of(data)
    recs: List[Dict[str, Any]] = []
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            for key in ("routes", "records", "data", "results"):
                if isinstance(obj.get(key), list):
                    recs = [r for r in obj[key]
                            if isinstance(r, dict)]
                    break
            else:
                recs = [obj]
        elif isinstance(obj, list):
            recs = [r for r in obj if isinstance(r, dict)]
    except Exception:
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if isinstance(obj, dict):
                    recs.append(obj)
    return recs


def _is_private_as(asn: Any) -> bool:
    try:
        n = int(str(asn).upper().replace("AS", ""))
    except Exception:
        return False
    return any(lo <= n <= hi for lo, hi in _PRIVATE_AS) or n == 0 \
        or n == 65535 or n == 4294967295


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for rec in _records(data):
        prefix = str(rec.get("prefix") or "?")
        rpki = str(rec.get("rpki_status") or
                   rec.get("rpki") or "").lower()
        origin = rec.get("origin_as") or rec.get("origin")
        announced = rec.get("announced_by") or rec.get("origin_as")
        if rpki == "invalid":
            hits.append({
                "key": "bgp_rpki_invalid_origin", "severity": "high",
                "value": f"Prefix {prefix} is announced by AS"
                         f"{announced} but RPKI state is INVALID - "
                         "the announcement contradicts the ROA "
                         "(hijack or mis-origination posture)",
                "evidence": {"prefix": prefix,
                             "remediation": "Publish a correct ROA "
                             "for the prefix/origin pair or withdraw "
                             "the announcement; enable ROV on "
                             "upstreams."}})
        elif origin and announced and str(origin) != str(announced):
            hits.append({
                "key": "bgp_origin_as_mismatch", "severity": "medium",
                "value": f"Prefix {prefix}: ROA/records origin AS"
                         f"{origin} but announced by AS{announced}",
                "evidence": {"prefix": prefix,
                             "remediation": "Reconcile the ROA with "
                             "the announcing ASN or withdraw the "
                             "announcement."}})
        elif rpki in ("unknown", "notfound") and origin:
            hits.append({
                "key": "bgp_rpki_not_covered", "severity": "low",
                "value": f"Prefix {prefix} has no covering ROA "
                         "(RPKI not-found) - anyone can announce it "
                         "without cryptographic contradiction",
                "evidence": {"prefix": prefix,
                             "remediation": "Create ROAs for all "
                             "announced prefixes."}})
            hits.pop()  # coverage gap alone is posture hygiene, not
            # a leak finding for this detector
        path = rec.get("as_path") or rec.get("path") or []
        if isinstance(path, list) and path:
            if len([str(a) for a in path]) != \
                    len({str(a) for a in path}):
                hits.append({
                    "key": "bgp_as_path_loop", "severity": "medium",
                    "value": f"Prefix {prefix}: AS path {path} "
                             "contains a repeated ASN (path loop / "
                             "prepending anomaly)",
                    "evidence": {"prefix": prefix,
                                 "as_path": [str(a) for a in path]}})
            priv = [a for a in path if _is_private_as(a)]
            if priv:
                hits.append({
                    "key": "bgp_private_as_in_path",
                    "severity": "medium",
                    "value": f"Prefix {prefix}: private/reserved "
                             f"ASN(s) {priv} appear in a public AS "
                             "path - leaks internal topology",
                    "evidence": {"prefix": prefix,
                                 "remediation": "Strip private ASNs "
                                 "at the border (remove-private-as)."}})
        recv = str(rec.get("received_from") or "").lower()
        sent = str(rec.get("sent_to") or "").lower()
        if recv in ("peer", "provider") and sent in ("peer",
                                                     "provider"):
            hits.append({
                "key": "bgp_route_leak_pattern", "severity": "high",
                "value": f"Prefix {prefix}: route learned from a "
                         f"{recv} was re-announced to a {sent} - "
                         "RFC 7908 route-leak pattern (valley-free "
                         "violation)",
                "evidence": {"prefix": prefix,
                             "remediation": "Apply leak detection / "
                             "OTC (RFC 9234) marking and peer-locking; "
                             "a transit-free relationship must not "
                             "become transit."}})
    return hits[:12]


class BgpRouteLeakDetectorPlugin(Plugin):
    id = "bgp_route_leak_detector"
    label = "BGP Route Leak Detector"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "network"
    phase = 2
    description = ("RPKI validity, origin-AS mismatch and AS-path "
                   "leak anomalies for target prefixes from keyless "
                   "public BGP data / supplied route records. No BGP "
                   "session.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "infra",
                          ("bgp_records", "route_records"))
            if got is not None:
                return got
            return self._ok([], "no supplied BGP route records in "
                            "ctx.shared and no prefix on the bus to "
                            "query public BGP data for")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
