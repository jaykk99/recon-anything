"""I2C bus traffic logger - offline capture decode adaptation: decode
an operator-supplied logic-analyzer capture (CSV-style export) into
I2C transactions (slave addresses, read/write, register offsets),
inventory bus devices, and flag EEPROM/flash reads and unexpected
writes during boot sequences. The plugin does not tap a live bus.
"""
from __future__ import annotations

import csv
import io
import re
from typing import Any, Dict, List

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat8_common import collect

_EEPROM = set(range(0x50, 0x58))
_LINE_RE = re.compile(
    r"([0-9.]+)\s*,\s*(write|read|w|r)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*"
    r"(?:,\s*((?:0x[0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0x[0-9a-fA-F]+|\d+))*))?",
    re.I)


def _num(tok: str) -> int:
    tok = tok.strip()
    return int(tok, 16) if tok.lower().startswith("0x") else int(tok)


def parse_transactions(text: str) -> List[Dict[str, Any]]:
    txns: List[Dict[str, Any]] = []
    for m in _LINE_RE.finditer(text):
        try:
            kind = "write" if m.group(2).lower().startswith("w") else "read"
            addr = _num(m.group(3))
            payload = []
            if m.group(4):
                payload = [_num(t) for t in m.group(4).split(",")]
            txns.append({"time": float(m.group(1)), "kind": kind,
                         "addr": addr, "data": payload})
        except Exception:
            continue
    if not txns:  # tolerate real CSV with headers via the csv module
        try:
            for row in csv.reader(io.StringIO(text)):
                if len(row) >= 3 and row[1].strip().lower() in (
                        "write", "read", "w", "r"):
                    txns.append({
                        "time": 0.0,
                        "kind": "write" if row[1].strip().lower()
                        in ("write", "w") else "read",
                        "addr": _num(row[2]),
                        "data": [_num(c) for c in row[3:] if c.strip()]})
        except Exception:
            pass
    return txns


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    if not data:
        return hits
    txns = parse_transactions(data.decode("utf-8", "ignore"))
    if not txns:
        return hits
    addrs = sorted({t["addr"] for t in txns})
    inventory = {
        "key": "i2c_bus_inventory", "severity": "low",
        "value": f"I2C capture decoded: {len(txns)} transactions, "
                 f"devices at {', '.join(hex(a) for a in addrs[:10])}",
        "evidence": {"transactions": len(txns),
                     "devices": [hex(a) for a in addrs[:10]]}}
    for t in txns:
        if t["addr"] in _EEPROM and t["kind"] == "read" \
                and len(t["data"]) >= 16:
            hits.append({
                "key": "i2c_eeprom_bulk_read", "severity": "medium",
                "value": f"Bulk read ({len(t['data'])} bytes) from "
                         f"EEPROM at {t['addr']:#x} in the capture - "
                         "device identity/config material leaving the "
                         "bus in plaintext",
                "evidence": {"address": hex(t["addr"]),
                             "bytes": len(t["data"])}})
            break
    for t in txns:
        if t["addr"] in _EEPROM and t["kind"] == "write":
            hits.append({
                "key": "i2c_eeprom_write", "severity": "medium",
                "value": f"Write to EEPROM at {t['addr']:#x} captured "
                         "- configuration/identity storage is writable "
                         "from the bus master",
                "evidence": {"address": hex(t["addr"])}})
            break
    if hits:
        hits.insert(0, inventory)
    return hits[:8]


class I2cBusTrafficLoggerPlugin(Plugin):
    id = "i2c_bus_traffic_logger"
    label = "I2C Bus Traffic Logger (offline)"
    accepts = ["binary", "artifact", "file", "url", "domain", "ip"]
    passive = True
    cost = Cost.FREE
    group = "infra"
    description = ("Offline decode of supplied I2C logic-analyzer "
                   "captures: device inventory, EEPROM bulk reads and "
                   "writes flagged. Does not tap a live bus.")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            return collect(self, target, ctx, analyze)
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
