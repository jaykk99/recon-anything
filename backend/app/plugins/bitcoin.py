"""Bitcoin node / config exposure (defensive OSINT).

Connect-only checks against common Bitcoin service ports on the target
host: 8333 (mainnet P2P), 8332 (RPC), 50001/50002 (Electrum), plus HTTP
probes for unauthenticated block-explorer APIs (blockbook, esplora).
Detection only: opens a TCP connection, reads any banner the service
volunteers, then closes. Never sends RPC commands, never attempts
authentication, never touches wallets or funds.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Dict, List, Tuple

from ..classifier import domain_from_target
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

# (port, service label, finding key, severity, description)
TCP_PORTS = [
    (8333, "Bitcoin P2P", "btc_p2p_exposed", "low",
     "Bitcoin P2P node exposed (port 8333). Peer-to-peer port reachable "
     "from the internet."),
    (8332, "Bitcoin RPC", "btc_rpc_exposed", "high",
     "Bitcoin RPC exposed to the internet (port 8332). An unauthenticated "
     "RPC gives full node control: wallet access, fund movement, chain "
     "rewrites. Verify by hand whether it answers without auth."),
    (50001, "Electrum", "btc_electrum_exposed", "medium",
     "Electrum server exposed (port 50001). Leaks the node's indexed "
     "wallet history to anyone who connects."),
    (50002, "Electrum TLS", "btc_electrum_tls_exposed", "medium",
     "Electrum TLS server exposed (port 50002). Leaks the node's indexed "
     "wallet history to anyone who connects."),
]

# HTTP explorer APIs probed without auth (blockbook default 9130,
# esplora often 3002/50001 behind a reverse proxy).
EXPLORER_PORTS = [9130, 3002]

VERSION_RE = re.compile(r"Satoshi:([0-9.]+)|ElectrumX\s*([0-9.]+)|"
                        r"electrs\s*([0-9.]+)", re.I)


async def _tcp_banner(host: str, port: int,
                      timeout: float = 4.0) -> Tuple[bool, str]:
    """Connect-only banner grab. Returns (open, banner_text)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=3)
            return True, data.decode("utf-8", errors="ignore")[:300]
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return False, ""


class BitcoinPlugin(Plugin):
    id = "bitcoin"
    label = "Bitcoin Node Exposure"
    accepts = ["domain", "url", "ip"]
    passive = True  # connect-only; runs in both scan modes
    cost = Cost.FREE
    group = "network"
    description = ("Bitcoin service exposure: P2P (8333), RPC (8332), "
                   "Electrum (50001/50002), and unauthenticated block "
                   "explorer APIs. Connect-only, never authenticates.")
    timeout_s = 60

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        mode = self.module_mode(ctx)
        passive = (mode == "passive")

        if target.type == "ip":
            host = (target.normalized or "").strip()
        else:
            host = domain_from_target(target.type, target.normalized) or ""
        if not host:
            res = self._skipped("no host for this target type")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
            return res

        findings: List[Finding] = []
        results = await asyncio.gather(
            *[_tcp_banner(host, port) for port, *_ in TCP_PORTS],
            *[_tcp_banner(host, port) for port in EXPLORER_PORTS])

        port_results: Dict[int, Tuple[bool, str]] = {}
        for (port, *_), (is_open, banner) in zip(
                TCP_PORTS, results[:len(TCP_PORTS)]):
            port_results[port] = (is_open, banner)
        for port, (is_open, banner) in zip(EXPLORER_PORTS,
                                           results[len(TCP_PORTS):]):
            port_results[port] = (is_open, banner)

        for port, svc, key, sev, desc in TCP_PORTS:
            is_open, banner = port_results[port]
            if not is_open:
                continue
            detail = f"{sev.upper()}: {desc}"
            vm = VERSION_RE.search(banner)
            if vm:
                ver = next(g for g in vm.groups() if g)
                detail += (f" Version disclosed in banner: {ver} - fingerprint "
                           "for targeted exploits.")
            findings.append(self._f(
                "network", key, detail,
                source="Bitcoin exposure scan", confidence=85,
                passive=passive,
                evidence={
                    "severity": sev, "host": host, "port": port,
                    "service": svc,
                    "banner": banner.strip()[:200],
                    "exploitability": ("weaponized" if port == 8332
                                       else "theoretical"),
                    "remediation": (
                        "Bind the service to localhost / a private network, "
                        "firewall the port, and require strong authentication. "
                        "RPC must NEVER be internet-facing."
                        if port == 8332 else
                        "Restrict the port to trusted peers/clients. A public "
                        "P2P or Electrum port should be a deliberate choice, "
                        "not an accident."),
                    "scope_note": ("Connect-only check: opened a TCP "
                                   "connection and read the banner. No RPC "
                                   "commands sent, no auth attempted.")}))

        # HTTP explorer APIs without auth
        for port in EXPLORER_PORTS:
            is_open, _banner = port_results[port]
            if not is_open:
                continue
            try:
                page = await ctx.fetch_page(
                    f"http://{host}:{port}/", timeout=8)
            except Exception:
                page = None
            if not page:
                continue
            text = (page.get("text") or "")[:4000]
            if re.search(r"blockbook|Txid|/api/v2", text, re.I):
                findings.append(self._f(
                    "network", "btc_blockbook_exposed",
                    f"MEDIUM: Blockbook API exposed without auth on "
                    f"{host}:{port}. Address balances, xpubs and transaction "
                    "history queryable by anyone.",
                    source="Bitcoin exposure scan", confidence=80,
                    passive=passive,
                    evidence={
                        "severity": "medium", "host": host, "port": port,
                        "service": "blockbook",
                        "exploitability": "theoretical",
                        "remediation": ("Put the explorer API behind auth or "
                                        "a private network. Public xpub "
                                        "indexing deanonymizes every wallet "
                                        "that touches it."),
                        "scope_note": "Read-only HTTP GET of the API root; "
                                      "no queries issued."}))
            elif re.search(r"esplora|mempool", text, re.I):
                findings.append(self._f(
                    "network", "btc_esplora_exposed",
                    f"MEDIUM: Esplora/mempool API exposed without auth on "
                    f"{host}:{port}. Chain data and address lookups open to "
                    "the internet.",
                    source="Bitcoin exposure scan", confidence=80,
                    passive=passive,
                    evidence={
                        "severity": "medium", "host": host, "port": port,
                        "service": "esplora",
                        "exploitability": "theoretical",
                        "remediation": ("Restrict the explorer API to trusted "
                                        "clients or require authentication."),
                        "scope_note": "Read-only HTTP GET of the API root; "
                                      "no queries issued."}))

        dur = int((time.monotonic() - t0) * 1000)
        open_ports = sorted(p for p, (o, _) in port_results.items() if o)
        res = self._ok(findings,
                       f"probed {len(port_results)} bitcoin ports on {host}; "
                       f"open: {open_ports or 'none'}")
        res.duration_ms = dur
        return res
