"""RPCbind procedure dump (variant of port_audit): port_audit
labels port 111 open with a note. This delta speaks ONC RPC: ONE
RPCBIND/PMAP DUMP call (keyless stdlib, UDP) listing registered
programs, versions, protocols and ports, flagging sensitive
registrations (nfs, mountd, ypserv/nis, rquota, nlockmgr) exposed
on the portmapper. Supplied rpcinfo-style dumps are analysed with
the same pure classifier.
"""
from __future__ import annotations

import asyncio
import re
import socket
import struct
from typing import Any, Dict, List, Optional

from .base import Cost, Ctx, Plugin, PluginResult, Target
from ._cat9_common import collect, host_port_of, text_of

SENSITIVE = {100003: "nfs", 100005: "mountd", 100004: "ypserv/nis",
             100011: "rquotad", 100021: "nlockmgr",
             100024: "status/statd", 100002: "rusersd",
             100008: "walld", 100012: "sprayd"}
ALL_PROGRAMS = {100000: "rpcbind/portmapper", **SENSITIVE,
                100001: "rstatd", 100007: "rwall/rup"}
_DUMP_LINE = re.compile(
    r"(?m)^\s*(\d{6,})\s+(\d+)\s+(tcp|udp)\s+(\d+)\s+([a-z0-9_\-]+)")


def hits_for_programs(progs: List[Dict[str, Any]], src: str
                      ) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    bad = [p for p in progs if p.get("program") in SENSITIVE]
    if bad:
        names = sorted({f"{SENSITIVE[p['program']]}"
                        f"({p['program']}/v{p.get('version', '?')}"
                        f"@{p.get('port', '?')})" for p in bad})
        hits.append({
            "key": "rpcbind_sensitive_program_exposed",
            "severity": "medium",
            "value": f"RPCbind dump ({src}) exposes sensitive RPC "
                     f"registrations: {', '.join(names[:8])}",
            "evidence": {"programs": names,
                         "remediation": "Firewall port 111 and the "
                         "registered RPC service ports to trusted "
                         "hosts; NIS/ypserv and mountd should never "
                         "be reachable from untrusted networks."}})
    return hits


def parse_dump_text(text: str) -> List[Dict[str, Any]]:
    progs = []
    for m in _DUMP_LINE.finditer(text or ""):
        progs.append({"program": int(m.group(1)),
                      "version": int(m.group(2)),
                      "proto": m.group(3),
                      "port": int(m.group(4)),
                      "service": m.group(5)})
    return progs


def build_pmap_dump_call(xid: int = 0x1234ABCD) -> bytes:
    return struct.pack(">IIIIIIIII", xid, 0, 2, 100000, 2, 4,
                       0, 0, 0)


def parse_pmap_dump_reply(data: bytes) -> List[Dict[str, Any]]:
    """Parse a PMAP DUMP (v2) reply body into program entries."""
    progs: List[Dict[str, Any]] = []
    try:
        blob = data or b""
        if len(blob) < 24:
            return progs
        # xid, type=1(reply), reply_stat=0, verfier(8), accept_stat=0
        pos = 24
        while pos + 4 <= len(blob) and len(progs) < 512:
            follows = struct.unpack_from(">I", blob, pos)[0]
            pos += 4
            if follows == 0:
                break
            if pos + 16 > len(blob):
                break
            prog, vers, proto, port = struct.unpack_from(
                ">IIII", blob, pos)
            pos += 16
            progs.append({"program": prog, "version": vers,
                          "proto": "tcp" if proto == 6 else "udp",
                          "port": port,
                          "service": ALL_PROGRAMS.get(prog, "")})
    except Exception:
        pass
    return progs


def analyze(data: bytes, name: str = "") -> List[Dict[str, Any]]:
    if not data:
        return []
    # rpcinfo-style text dumps and binary PMAP replies are told
    # apart by shape: text first when dump lines match (a text
    # buffer can otherwise decode as a garbage binary reply).
    progs = parse_dump_text(text_of(data))
    if not progs:
        progs = parse_pmap_dump_reply(data)
    return hits_for_programs(progs, "supplied dump")


def _probe(host: str, port: int, timeout: float = 3.0
           ) -> Optional[bytes]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(build_pmap_dump_call(), (host, port))
            data, _ = s.recvfrom(65535)
            return data
    except Exception:
        return None


class RpcbindProcedureDumpPlugin(Plugin):
    id = "rpcbind_procedure_dump"
    label = "RPCbind Procedure Dump"
    accepts = ["domain", "url", "ip", "artifact", "file"]
    passive = False
    cost = Cost.FREE
    group = "network"
    description = ("One RPCBIND/PMAP DUMP exchange listing "
                   "registered RPC programs/versions/ports; flags "
                   "sensitive registrations (nfs, mountd, ypserv).")
    timeout_s = 30

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        try:
            got = collect(self, target, ctx, analyze, "infra",
                          ("rpcbind_dumps",))
            if got is not None:
                return got
        except Exception as exc:
            return self._ok([], f"analysis degraded: {exc}"[:200])
        host, port = host_port_of(target, 111)
        try:
            resp = await asyncio.to_thread(_probe, host, port)
        except Exception:
            resp = None
        if not resp:
            return self._degraded(f"no RPCbind reply from "
                                  f"{host}:{port}")
        progs = parse_pmap_dump_reply(resp)
        findings = []
        for hit in hits_for_programs(progs, f"{host}:{port}"):
            ev = {"severity": hit["severity"]}
            ev.update(hit.get("evidence") or {})
            findings.append(self._f(
                "infra", hit["key"], hit["value"],
                source="RPCBIND dump", confidence=90, evidence=ev,
                passive=False))
        return self._ok(findings,
                        f"{len(progs)} RPC program(s) registered")
