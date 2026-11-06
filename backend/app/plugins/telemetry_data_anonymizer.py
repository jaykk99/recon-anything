"""Telemetry data anonymizer (variant of reporting.py _mask).

reporting._mask only truncates known secret values. This plugin's
delta: full PII/telemetry scrub analysis over supplied records. It
detects raw emails, IPs, hostnames and account ids sitting in
telemetry/flow records, and reports the exposure with MASKED evidence
only, plus the consistent hash-pseudonym each value would map to (so
correlations survive anonymization). It never emits a raw identifier.
Pure local analysis, keyless.
"""
from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Dict, List

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

_EMAIL_RX = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IPV4_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ACCT_RX = re.compile(r"\b(?:acct|account|user|uid)[_\-]?id\s*[:=]\s*([A-Za-z0-9\-]{4,})", re.I)
_HOST_RX = re.compile(r"\b(?:[a-z0-9\-]+\.)+(?:internal|local|corp|lan)\b", re.I)


def pseudonym(kind: str, value: str) -> str:
    return f"{kind}-" + hashlib.sha256(value.strip().lower().encode()).hexdigest()[:10]


def _mask_email(v: str) -> str:
    local, _, dom = v.partition("@")
    return (local[:1] + "***@" + dom[:1] + "***") if dom else "***"


def _mask_ip(v: str) -> str:
    parts = v.split(".")
    return ".".join(parts[:2] + ["*", "*"]) if len(parts) == 4 else "***"


def analyze_telemetry(records: Any) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    texts: List[str] = []
    if isinstance(records, list):
        for r in records:
            texts.append(r if isinstance(r, str) else _stringify(r))
    elif records is not None:
        texts.append(_stringify(records))
    counts: Dict[str, Dict[str, Any]] = {}

    def note(kind: str, raw: str, masked: str, sev: str) -> None:
        slot = counts.setdefault(kind, {"n": 0, "masked": masked,
                                        "pseudo": pseudonym(kind, raw),
                                        "severity": sev})
        slot["n"] += 1

    for t in texts:
        for m in _EMAIL_RX.finditer(t):
            note("email", m.group(0), _mask_email(m.group(0)), "high")
        for m in _IPV4_RX.finditer(t):
            if m.group(0) not in ("0.0.0.0", "127.0.0.1"):
                note("ip", m.group(0), _mask_ip(m.group(0)), "medium")
        for m in _ACCT_RX.finditer(t):
            note("account_id", m.group(1), m.group(1)[:2] + "***", "high")
        for m in _HOST_RX.finditer(t):
            note("internal_hostname", m.group(0), m.group(0)[:3] + "***", "medium")
    for kind, slot in counts.items():
        rows.append({"key": f"telemetry_raw_{kind}",
                     "value": f"Telemetry contains {slot['n']} raw {kind} "
                              f"value(s) (example masked: {slot['masked']}): "
                              f"anonymize to consistent pseudonym "
                              f"{slot['pseudo']} before export",
                     "severity": slot["severity"],
                     "evidence": {"kind": kind, "count": slot["n"],
                                  "masked_example": slot["masked"],
                                  "pseudonym_example": slot["pseudo"]}})
    return rows


def _stringify(obj: Any) -> str:
    import json
    try:
        return json.dumps(obj, default=str)
    except Exception:
        return str(obj)


class TelemetryDataAnonymizerPlugin(Plugin):
    id = "telemetry_data_anonymizer"
    label = "Telemetry Data Anonymizer"
    accepts = ["domain", "url", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Scrub analysis of supplied telemetry: raw emails, IPs, "
                   "hostnames, account ids reported masked, with consistent "
                   "hash pseudonyms.")
    phase = 2

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        try:
            records = ctx.consume("telemetry_records") or ctx.consume("artifacts")
            rows = analyze_telemetry(records)
        except Exception as exc:
            return self._degraded(f"anonymizer failed: {exc}")
        findings: List[Finding] = [
            self._f("infra", r["key"], r["value"], source="Telemetry anonymizer",
                    confidence=90,
                    evidence={"severity": r["severity"],
                              "remediation": "Replace raw identifiers with "
                                             "the consistent pseudonyms before "
                                             "the telemetry leaves the run.",
                              **r.get("evidence", {})})
            for r in rows]
        res = self._ok(findings, f"telemetry PII rows: {len(findings)}")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res
