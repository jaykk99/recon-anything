"""NetFlow traffic volume profiler: aggregates operator-supplied
flow records (NetFlow/IPFIX exports rendered as CSV/JSON flow logs)
per host/destination and flags exfil-shaped patterns:

- large sustained outbound volume to a single rare external
  destination (one external dst taking the bulk of a host's egress)
- beacon-like regular intervals (many small flows to one external
  destination at near-constant spacing)
- off-hours bulk transfers

Pure local parsing of SUPPLIED records only - no live capture,
no tapping.
"""
from __future__ import annotations

import csv
import io
import json
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, is_external_ip, text_of

EXFIL_MIN_BYTES = 10 * 1024 * 1024
EXFIL_SHARE = 0.8
BEACON_MIN_FLOWS = 8


def _to_int(v: Any) -> int:
    try:
        return int(float(str(v)))
    except Exception:
        return 0


def _to_ts(v: Any) -> float:
    if v is None:
        return 0.0
    try:
        return float(v)
    except Exception:
        pass
    try:
        return datetime.fromisoformat(
            str(v).replace("Z", "+00:00")).timestamp()
    except Exception:
        return 0.0


def parse_flows(data: bytes) -> List[Dict[str, Any]]:
    text = text_of(data)
    flows: List[Dict[str, Any]] = []
    if not text:
        return flows
    stripped = text.strip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            rows = obj if isinstance(obj, list) else \
                obj.get("flows", obj.get("records", []))
            for r in rows if isinstance(rows, list) else []:
                if isinstance(r, dict):
                    flows.append(_norm(r))
            if flows:
                return flows
        except Exception:
            pass
    try:
        reader = csv.DictReader(io.StringIO(text))
        if reader.fieldnames and any(
                "src" in (f or "") or "dst" in (f or "")
                for f in reader.fieldnames):
            for r in reader:
                flows.append(_norm(r))
    except Exception:
        pass
    return flows


def _norm(r: Dict[str, Any]) -> Dict[str, Any]:
    low = {str(k).lower(): v for k, v in r.items()}
    return {
        "src": str(low.get("src") or low.get("src_ip")
                   or low.get("source") or ""),
        "dst": str(low.get("dst") or low.get("dst_ip")
                   or low.get("destination") or ""),
        "bytes": _to_int(low.get("bytes") or low.get("octets")
                         or low.get("size") or 0),
        "ts": _to_ts(low.get("ts") or low.get("time")
                     or low.get("timestamp") or low.get("start")),
        "dport": _to_int(low.get("dport") or low.get("dst_port")
                          or low.get("port") or 0),
    }


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    flows = [f for f in parse_flows(data)
             if f["src"] and f["dst"]]
    if not flows:
        return hits
    by_pair: Dict = defaultdict(list)
    total_by_src: Dict[str, int] = defaultdict(int)
    for f in flows:
        by_pair[(f["src"], f["dst"])].append(f)
        total_by_src[f["src"]] += f["bytes"]
    for (src, dst), fs in by_pair.items():
        vol = sum(f["bytes"] for f in fs)
        if is_external_ip(dst) and vol >= EXFIL_MIN_BYTES and \
                total_by_src[src] and \
                vol / total_by_src[src] >= EXFIL_SHARE:
            hits.append({
                "key": "netflow_bulk_exfil_pattern",
                "severity": "high",
                "value": f"Flow profile: {src} sent "
                         f"{vol / 1e6:.1f} MB to single external "
                         f"destination {dst} "
                         f"({vol / total_by_src[src]:.0%} of its "
                         "total egress in the supplied records) - "
                         "bulk-exfiltration shape",
                "evidence": {"src": src, "dst": dst, "bytes": vol,
                             "remediation": "Identify the process/"
                             "owner behind this flow, confirm the "
                             "destination is sanctioned, and alert "
                             "on single-destination egress dominance "
                             "in flow monitoring."}})
        stamps = sorted(f["ts"] for f in fs if f["ts"])
        if is_external_ip(dst) and len(stamps) >= BEACON_MIN_FLOWS:
            intervals = [b - a for a, b in zip(stamps, stamps[1:])]
            if intervals and min(intervals) > 0:
                mean = statistics.fmean(intervals)
                if mean > 0:
                    sd = statistics.pstdev(intervals) \
                        if len(intervals) > 1 else 0.0
                    if sd / mean < 0.1 and \
                            max(f["bytes"] for f in fs) < 100000:
                        hits.append({
                            "key": "netflow_beacon_pattern",
                            "severity": "medium",
                            "value": f"Flow profile: {src} contacts "
                                     f"{dst} at near-constant "
                                     f"{mean:.0f}s intervals "
                                     f"({len(stamps)} flows, jitter "
                                     f"{sd / mean:.1%}) - beacon "
                                     "shape",
                            "evidence": {"src": src, "dst": dst,
                                         "interval_s": round(mean),
                                         "flows": len(stamps),
                                         "remediation": "Hunt the "
                                         "host for C2-style periodic "
                                         "check-ins; constant "
                                         "intervals are a classic "
                                         "beacon signature."}})
        off_hours = [f for f in fs if f["ts"] and
                     datetime.fromtimestamp(
                         f["ts"], timezone.utc).hour < 5]
        off_vol = sum(f["bytes"] for f in off_hours)
        if is_external_ip(dst) and off_vol >= EXFIL_MIN_BYTES and \
                not any(h["key"] == "netflow_bulk_exfil_pattern"
                        and h["evidence"].get("dst") == dst
                        for h in hits):
            hits.append({
                "key": "netflow_off_hours_bulk_transfer",
                "severity": "medium",
                "value": f"Flow profile: {off_vol / 1e6:.1f} MB "
                         f"from {src} to external {dst} during "
                         "00:00-05:00 UTC in supplied records",
                "evidence": {"src": src, "dst": dst,
                             "bytes": off_vol,
                             "remediation": "Confirm the off-hours "
                             "bulk job is a sanctioned backup/replication; "
                             "otherwise investigate as staged exfil."}})
    return hits[:10]


class NetflowTrafficVolumeProfilerPlugin(Plugin):
    id = "netflow_traffic_volume_profiler"
    label = "NetFlow Traffic Volume Profiler"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = True
    cost = Cost.FREE
    group = "network"
    phase = 2
    description = ("Profiles supplied NetFlow/IPFIX/CSV flow "
                   "records: bulk single-destination egress, "
                   "beacon-regular intervals, off-hours bulk "
                   "transfers. Supplied records only.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "infra",
                          ("netflow_records", "flow_data"))
            if got is not None:
                return got
            return self._ok([], "no supplied flow records in "
                            "ctx.shared; no live traffic is tapped")
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
