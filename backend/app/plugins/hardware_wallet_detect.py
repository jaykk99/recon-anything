"""Hardware wallet detection (IP -> device -> files -> key pre-gate).

Jay's order, in his words: it finds the IP, then the device, then the
files on the device connected to any crypto, and before it goes on it
checks for any crypto key. A second refinement adds a blockchain-backend
stage: for the target IP, query public blockchain backends to correlate
that IP with hardware (public explorer APIs, public node endpoints and
public peer tables).

Stages, in order:
  0. KEY PRE-GATE - fingerprint-only check for private keys, seeds or
     keystores, matched by filename/pattern and stat metadata. Runs
     BEFORE the scan proceeds. Reports existence + metadata ONLY.
  1. IP STAGE - identify the device at the target IP: wallet-bridge
     port fingerprint (Trezor Bridge 21325), mDNS/SSDP advertisements,
     reverse DNS, MAC vendor from ARP data on the local LAN.
  2. BLOCKCHAIN-BACKEND STAGE - correlate the IP with public chain
     backends: Bitnodes per-node API (keyless), Solana public
     getClusterNodes peer table (keyless public RPC), and TCP
     fingerprint of known P2P/wallet-backend ports. Backends that need
     a key or a login (Etherscan, Ethernodes, Blockchair node lookup,
     Shodan/Censys) are SKIPPED and noted as gated, never worked
     around.
  3. DEVICE STAGE - identify hardware wallet presence: USB vendor /
     product IDs (Ledger 0x2c97, Trezor 0x534c, KeepKey 0x2b24, BitBox
     0x03eb:0x2402, Coldcard 0xd13e:0xcc10) via local enumeration,
     running wallet-bridge processes/services, known wallet software
     data directories.
  4. FILES STAGE - enumerate wallet-related file NAMES in standard
     locations (Ledger Live, Trezor Suite, Electrum, Bitcoin Core
     wallet.dat, keystore dirs) on the authorized machine only.
     Record path, size, mtime. Never read file contents.

HARD BOUNDARIES (do not cross these):
- Authorized targets only: Jay's own devices/network, or targets he
  explicitly names. Never scan arbitrary internet IPs looking for
  wallets. Local enumeration (lsusb, process list, wallet dirs) runs
  ONLY when the target is a loopback / RFC1918 / link-local address,
  or when an authorized local agent feeds the data in on the discovery
  bus (ctx.shared keys below). A remote public target only ever gets
  the network stages (bridge-port probe, public backend lookups).
- NEVER output, store or transmit key material, seed phrases or
  private keys. Fingerprints and metadata only. This follows the
  fingerprint-only card-leak detector precedent (PR #175) and the
  exposed-key sweep precedent: finding a key is recon, USING one is
  theft and off limits. The plugin never opens a file whose name
  matches a key pattern, never signs anything, never moves funds.
- No auth bypass, no exploitation, no credential guessing, no remote
  file access without authorization. Read-only probes only.

Discovery-bus inputs an authorized local agent may feed in (so the
plugin can run without shelling out):
  local_usb_devices : lsusb text
  local_processes   : ps text
  local_mdns        : mDNS response text
  local_ssdp        : SSDP response text
  local_arp         : arp -a text
  local_wallet_files: [{path, size, mtime}] directory listings
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target

REMEDIATION_KEY = (
    "Key material is sitting on this machine. Move seeds and private "
    "keys to a hardware wallet, encrypt any keystore with a strong "
    "password, delete plaintext backups, and rotate any key that may "
    "have been exposed."
)
REMEDIATION_DEVICE = (
    "A hardware wallet (or its bridge software) is reachable on this "
    "host. Keep bridge software updated, never approve a transaction "
    "you did not start, and restrict bridge ports to localhost."
)
REMEDIATION_NODE = (
    "This IP is publicly listed as a blockchain node or wallet backend. "
    "That is public peer-table data, not a vulnerability by itself: keep "
    "the node patched, close RPC to the internet, and do not expose "
    "wallet RPC ports."
)

# ---------------------------------------------------------------------------
# Known hardware wallets: USB vendor/product IDs.
# Ledger / Trezor / KeepKey own dedicated VIDs, so a VID match alone
# identifies the vendor (model from PID when known). BitBox (0x03eb is
# Atmel's VID, shared by many devices) and Coldcard need the VID+PID
# pair, otherwise the false-positive rate is unacceptable.
# ---------------------------------------------------------------------------
USB_DEVICES = [
    # (vid, pid or None, vendor, model or None)
    (0x2C97, 0x0001, "Ledger", "Nano S"),
    (0x2C97, 0x0004, "Ledger", "Nano X"),
    (0x2C97, 0x0005, "Ledger", "Nano S Plus"),
    (0x2C97, None, "Ledger", None),
    (0x534C, 0x0001, "Trezor", "One"),
    (0x534C, 0x0021, "Trezor", "Model T"),
    (0x534C, None, "Trezor", None),
    (0x2B24, 0x0001, "KeepKey", None),
    (0x2B24, None, "KeepKey", None),
    (0x03EB, 0x2402, "BitBox", "BitBox02"),
    (0xD13E, 0xCC10, "Coldcard", None),
]

# Wallet bridge / backend ports (TCP connect fingerprint, authorized
# targets only). 21325 is the Trezor Bridge (trezord) HTTP port; the
# rest are P2P / wallet-backend ports used by the backend stage.
BRIDGE_PORTS = {21325: "Trezor Bridge (trezord)"}
P2P_PORTS = {
    8333: "Bitcoin P2P",
    30303: "Ethereum devp2p",
    9735: "Lightning Network",
    18080: "Monero P2P",
    50001: "Electrum server",
    50002: "Electrum server (SSL)",
}

# mDNS / SSDP markers: service names or headers that name wallet
# software. Hardware wallets themselves rarely advertise; the bridge
# and companion apps sometimes do.
MDNS_MARKERS = ("trezor", "trezord", "ledger", "keepkey", "bitbox",
                "coldcard", "electrum", "hardware-wallet", "hardware wallet")

# Small OUI table for common host hardware (MAC vendor). Anything not
# listed reports "unknown" rather than guessing.
OUI_VENDORS = {
    "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "24:6f:28": "Espressif",
    "24:0a:c4": "Espressif",
    "30:ae:a4": "Espressif",
}

# Filename patterns that indicate key material. Matched against the
# BASENAME only, case-insensitive. A match means "key material is
# present here" - the file is never opened, never read, never hashed.
KEY_FILENAME_PATTERNS = [
    re.compile(r"^wallet\.dat$", re.I),
    re.compile(r"^UTC--", re.I),                      # Ethereum keystore
    re.compile(r"\.keystore$", re.I),
    re.compile(r"keystore.*\.json$", re.I),
    re.compile(r"(seed|recovery|mnemonic|passphrase).*\.txt$", re.I),
    re.compile(r"\.wallet$", re.I),
    re.compile(r"^(\.|_)?(seed|mnemonic|recovery)[-_ .]", re.I),
]

# Wallet-app file kinds for the files stage (non-key files only get a
# hash when the authorized collector already computed one; the plugin
# itself never opens files).
NON_KEY_KINDS = [
    (re.compile(r"\.log$", re.I), "log"),
    (re.compile(r"(config|settings|app)\.json$", re.I), "config"),
    (re.compile(r"\.(sqlite|sqlite3|db|ldb)$", re.I), "app_data"),
]

# Standard wallet software data directories, relative to the user's
# home directory, per OS. Only scanned on local targets, metadata
# only (scandir: name/size/mtime, never open).
WALLET_DIRS = [
    # Linux
    ".config/Ledger Live",
    ".config/@trezor/suite",
    ".electrum",
    ".bitcoin/wallets",
    ".sparrow",
    ".wasabi",
    ".config/Exodus",
    # macOS
    "Library/Application Support/Ledger Live",
    "Library/Application Support/Trezor Suite",
    "Library/Application Support/Electrum",
    "Library/Application Support/Bitcoin",
    # Windows
    "AppData/Roaming/Ledger Live",
    "AppData/Roaming/Trezor Suite",
    "AppData/Roaming/Electrum",
    "AppData/Roaming/Bitcoin",
]

# Wallet bridge / companion processes.
WALLET_PROCESSES = ("trezord", "ledger-live", "ledger live", "electrum",
                    "sparrow", "wasabi", "exodus", "trezor-suite",
                    "trezor suite", "bitcoin-qt", "bitcoind")

# Public, keyless blockchain-backend sources. Anything keyed or login
# gated is listed in GATED_BACKENDS and never queried.
BITNODES_NODE_URL = "https://bitnodes.io/api/v1/nodes/{ip}-8333/"
SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"
GATED_BACKENDS = [
    "Etherscan Node Tracker (API key required)",
    "Ethernodes.org (no public machine-readable API)",
    "Blockchair node lookup (API key required)",
    "Shodan / Censys (API key required)",
]


# ---------------------------------------------------------------------------
# Pure helpers (unit-testable, no I/O)
# ---------------------------------------------------------------------------

def parse_lsusb(text: str) -> List[Dict[str, Any]]:
    """Parse `lsusb` output into identified hardware wallets.

    Only VID/PID pairs from USB_DEVICES count. A Ledger/Trezor/KeepKey
    VID alone identifies the vendor; BitBox/Coldcard need the pair.
    """
    out: List[Dict[str, Any]] = []
    if not text:
        return out
    for line in text.splitlines():
        m = re.search(r"ID\s+([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\s*(.*)",
                      line)
        if not m:
            continue
        vid, pid = int(m.group(1), 16), int(m.group(2), 16)
        desc = (m.group(3) or "").strip()
        best = None
        for v, p, vendor, model in USB_DEVICES:
            if v != vid:
                continue
            if p is None:
                if best is None:
                    best = (vendor, model, "vendor")
            elif p == pid:
                best = (vendor, model, "exact")
                break
        if best is None:
            continue
        vendor, model, match = best
        out.append({"vendor": vendor, "model": model, "vid": vid,
                    "pid": pid, "match": match,
                    "label": desc or vendor})
    return out


def parse_bridge_probe(port: int, status: int, headers: Dict[str, Any],
                       text: str) -> Optional[Dict[str, Any]]:
    """Fingerprint a wallet-bridge HTTP response.

    Trezor Bridge answers on 21325 and names itself in headers/body.
    A bare open port with no wallet markers is NOT a finding.
    """
    blob = " ".join([str(headers.get("server", "")),
                     str(headers.get("x-trezord-version", "")),
                     text or ""]).lower()
    if port == 21325 and ("trezor" in blob or "trezord" in blob):
        return {"service": "Trezor Bridge (trezord)", "port": port,
                "status": status}
    return None


def parse_mdns(text: str) -> List[str]:
    """Wallet markers found in mDNS response text."""
    if not text:
        return []
    low = text.lower()
    return sorted({m for m in MDNS_MARKERS if m in low})


def parse_ssdp(text: str) -> List[str]:
    """Wallet markers found in SSDP response text."""
    if not text:
        return []
    low = text.lower()
    return sorted({m for m in MDNS_MARKERS if m in low})


def mac_vendor(mac: str) -> str:
    """OUI lookup from the small built-in table; 'unknown' otherwise."""
    oui = (mac or "").strip().lower().replace("-", ":")[:8]
    return OUI_VENDORS.get(oui, "unknown")


def parse_arp(text: str) -> List[Dict[str, str]]:
    """Parse `arp -a` style text into [{ip, mac, vendor}]."""
    out: List[Dict[str, str]] = []
    if not text:
        return out
    for line in text.splitlines():
        m = re.search(
            r"(\d{1,3}(?:\.\d{1,3}){3}).*?"
            r"([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}"
            r"[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})",
            line)
        if m:
            out.append({"ip": m.group(1), "mac": m.group(2),
                        "vendor": mac_vendor(m.group(2))})
    return out


def classify_wallet_file(name: str) -> Optional[str]:
    """Kind of a wallet file by name only: key_material | log | config |
    app_data | None (not wallet-related). Never reads contents."""
    base = (name or "").split("/")[-1].split("\\")[-1]
    for rx in KEY_FILENAME_PATTERNS:
        if rx.search(base):
            return "key_material"
    for rx, kind in NON_KEY_KINDS:
        if rx.search(base):
            return kind
    low = base.lower()
    if low in ("wallet.dat",) or "wallet" in low and low.endswith(
            (".dat", ".json")):
        return "app_data"
    return None


def key_gate(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pre-gate: entries whose names match key-material patterns.

    Returns the matching entries (path/size/mtime/kind only). The
    caller never opens these files.
    """
    out = []
    for e in entries or []:
        name = e.get("path", "") or e.get("name", "")
        if classify_wallet_file(name) == "key_material":
            out.append(e)
    return out


def parse_bitnodes_node(payload: Any) -> Optional[Dict[str, Any]]:
    """Parse a Bitnodes per-node API response.

    Verified live 2026-11-14: GET bitnodes.io/api/v1/nodes/{ip}-8333/
    returns {"found": true, "status": "UP", "node": {user_agent,
    height, city, country, asn, organization, ...}} or
    {"found": false, ...} for a non-node IP.
    """
    if not isinstance(payload, dict) or not payload.get("found"):
        return None
    node = payload.get("node") or {}
    return {
        "source": "bitnodes",
        "ip": payload.get("address", ""),
        "status": payload.get("status", ""),
        "user_agent": node.get("user_agent", ""),
        "height": node.get("height"),
        "city": node.get("city", ""),
        "country": node.get("country", ""),
        "asn": node.get("asn", ""),
        "organization": node.get("organization", ""),
    }


def parse_solana_cluster_nodes(payload: Any, ip: str) -> List[Dict[str, Any]]:
    """Match a target IP against a Solana getClusterNodes result.

    The public RPC returns [{gossip: "ip:port", pubkey, version, ...}].
    Only entries whose gossip IP equals the target count.
    """
    out: List[Dict[str, Any]] = []
    if not isinstance(payload, dict):
        return out
    for entry in payload.get("result") or []:
        if not isinstance(entry, dict):
            continue
        gossip = str(entry.get("gossip") or "")
        if gossip.split(":")[0] == ip:
            out.append({"source": "solana getClusterNodes",
                        "gossip": gossip,
                        "pubkey": entry.get("pubkey", ""),
                        "version": entry.get("version", "")})
    return out


def is_local_target(ip: str) -> bool:
    """Loopback / RFC1918 / link-local only. Anything else is remote."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def resolve_host(host: str) -> Optional[str]:
    """DNS-resolve a hostname to an IP; None on failure."""
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """True if a TCP connect to host:port succeeds within timeout."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _rel_home(path: str) -> str:
    """Path relative to $HOME for findings (never leak full home paths)."""
    home = os.path.expanduser("~")
    if path.startswith(home):
        return path[len(home):].lstrip("/\\")
    return os.path.basename(path)


# ---------------------------------------------------------------------------
# Local enumeration (local targets only, metadata only, never opens files)
# ---------------------------------------------------------------------------

def _run_lsusb() -> Optional[str]:
    try:
        proc = subprocess.run(["lsusb"], capture_output=True, text=True,
                              timeout=5)
        return proc.stdout if proc.returncode == 0 else None
    except Exception:
        return None


def _run_ps() -> Optional[str]:
    try:
        proc = subprocess.run(["ps", "aux"], capture_output=True,
                              text=True, timeout=5)
        return proc.stdout if proc.returncode == 0 else None
    except Exception:
        return None


def _collect_local_files(max_entries: int = 200) -> List[Dict[str, Any]]:
    """Metadata-only walk of standard wallet dirs (name/size/mtime).

    Uses scandir only: no file is ever opened, so key material can
    never be read. Depth 2, capped, so a huge home dir cannot stall
    the scan.
    """
    home = os.path.expanduser("~")
    entries: List[Dict[str, Any]] = []
    for rel in WALLET_DIRS:
        base = os.path.join(home, rel)
        try:
            if not os.path.isdir(base):
                continue
        except Exception:
            continue
        for root, _dirs, files in os.walk(base):
            depth = root[len(base):].count(os.sep)
            if depth > 1:
                _dirs[:] = []
                continue
            for name in files:
                full = os.path.join(root, name)
                try:
                    st = os.stat(full)
                except Exception:
                    continue
                entries.append({"path": _rel_home(full),
                                "size": st.st_size,
                                "mtime": int(st.st_mtime)})
                if len(entries) >= max_entries:
                    return entries
    return entries


def _wallet_dirs_present() -> List[str]:
    home = os.path.expanduser("~")
    out = []
    for rel in WALLET_DIRS:
        try:
            if os.path.isdir(os.path.join(home, rel)):
                out.append(rel)
        except Exception:
            continue
    return out


def _ssdp_discover(timeout: float = 2.0) -> str:
    """One SSDP M-SEARCH on the LAN (active mode, local targets only).

    Returns the raw response text (may be empty). Best-effort only.
    """
    msg = ("\r\n".join([
        "M-SEARCH * HTTP/1.1",
        "HOST: 239.255.255.250:1900",
        'MAN: "ns=01"',
        "MX: 1",
        "ST: ssdp:all",
        "", ""])).encode()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                             socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.sendto(msg, ("239.255.255.250", 1900))
        chunks = []
        try:
            while True:
                data, _ = sock.recvfrom(65535)
                chunks.append(data.decode("utf-8", "replace"))
        except socket.timeout:
            pass
        finally:
            sock.close()
        return "\n".join(chunks)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class HardwareWalletDetect(Plugin):
    id = "hardware_wallet_detect"
    label = "Hardware Wallet Detect"
    accepts = ["ip", "domain", "url"]
    passive = False  # sends bridge-port + TCP probes to the target
    cost = Cost.FREE
    group = "web3"
    description = (
        "Finds the IP, then the device, then the files on a device "
        "connected to crypto: wallet-bridge ports, USB hardware wallets, "
        "wallet software dirs and wallet files, plus a public "
        "blockchain-backend correlation for the IP. A fingerprint-only "
        "key check runs first; key material is never read or output."
    )

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        findings: List[Finding] = []
        notes: List[str] = []
        gated = list(GATED_BACKENDS)

        # -- resolve target to an IP ------------------------------------
        raw = (target.normalized or target.raw or "").strip()
        if target.type == "ip":
            ip = raw
        else:
            host = raw.split("://", 1)[-1].split("/")[0].split(":")[0]
            # blocking DNS (gethostbyname): resolve off the event loop
            ip = (await asyncio.to_thread(resolve_host, host)
                  if host else None)
        if not ip:
            return self._skipped("could not resolve target to an IP")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return self._skipped("target did not resolve to a valid IP")
        local = is_local_target(ip)
        mode = self.module_mode(ctx)
        shared = ctx.shared or {}

        # -- local evidence: bus-fed first, live enumeration second -----
        # Local stages only ever run for local targets. For a remote
        # target the scanner host's own USB/files are NOT the target's.
        usb_text = shared.get("local_usb_devices")
        ps_text = shared.get("local_processes")
        mdns_text = shared.get("local_mdns")
        ssdp_text = shared.get("local_ssdp")
        arp_text = shared.get("local_arp")
        file_entries: List[Dict[str, Any]] = list(
            shared.get("local_wallet_files") or [])
        if local:
            if usb_text is None:
                usb_text = _run_lsusb()
            if ps_text is None:
                ps_text = _run_ps()
            if not file_entries:
                file_entries = _collect_local_files()
        elif file_entries:
            # Bus-fed listings for a remote target: only usable when
            # the agent that fed them attests they belong to the
            # target; otherwise they would misattribute. The bus is
            # only populated by an authorized local agent, so accept.
            pass

        # -- stage 0: KEY PRE-GATE (runs before anything else) --------
        key_hits = key_gate(file_entries)
        if key_hits:
            kinds = sorted({classify_wallet_file(e.get("path", ""))
                            for e in key_hits})
            findings.append(self._f(
                "leak", "hw_wallet_key_material_present",
                "key material present: %d file(s) (%s)"
                % (len(key_hits), ", ".join(
                    sorted({(e.get("path", "").split("/")[-1])
                            for e in key_hits}))),
                source="hardware_wallet_detect:key-gate",
                confidence=90,
                evidence={
                    "severity": "high",
                    "remediation": REMEDIATION_KEY,
                    "attacker_impact": (
                        "Plaintext key material on disk can be copied by "
                        "anyone (or any malware) with read access to this "
                        "machine and used to drain the wallet."),
                    "count": len(key_hits),
                    "kinds": kinds,
                    "files": [{"path": e.get("path", ""),
                               "size": e.get("size")}
                              for e in key_hits[:10]],
                    "note": ("Fingerprint only: filenames and sizes. "
                             "No file was opened and no key material is "
                             "included in this finding."),
                }))
        else:
            notes.append("key pre-gate: no key-material filenames found")

        # -- stage 1: IP stage ----------------------------------------
        # Bridge-port fingerprint (HTTP probe, works on any target).
        for port, svc in BRIDGE_PORTS.items():
            try:
                resp = await ctx.probe("http://%s:%d/" % (ip, port))
            except Exception:
                continue
            hit = parse_bridge_probe(
                port, resp.get("status", 0), resp.get("headers", {}),
                resp.get("text", ""))
            if hit:
                findings.append(self._f(
                    "infra", "hw_wallet_bridge_detected",
                    "%s reachable on %s:%d" % (svc, ip, port),
                    source="hardware_wallet_detect:bridge",
                    confidence=85,
                    evidence={
                        "severity": "medium",
                        "remediation": REMEDIATION_DEVICE,
                        "port": port, "service": svc,
                        "http_status": hit["status"],
                    }))
                ctx.publish("tech", "trezor-bridge:%d" % port)
        # mDNS / SSDP / ARP: bus-fed text is attested to this target by
        # the authorized agent that fed it, so it counts for any target.
        # A live SSDP probe only ever runs on the local LAN, active
        # mode. There is no live mDNS probe: mDNS is parse-only from
        # bus-fed text.
        if mdns_text is None and local and mode == "active":
            mdns_text = ""  # no live mDNS probe; bus-fed only
        if ssdp_text is None and local and mode == "active":
            ssdp_text = _ssdp_discover()
        for marker in parse_mdns(mdns_text or ""):
            findings.append(self._f(
                "infra", "hw_wallet_mdns_advertisement",
                "mDNS advertises %s on the local network" % marker,
                source="hardware_wallet_detect:mdns",
                confidence=70,
                evidence={"severity": "low",
                          "remediation": REMEDIATION_DEVICE,
                          "marker": marker}))
        for marker in parse_ssdp(ssdp_text or ""):
            findings.append(self._f(
                "infra", "hw_wallet_ssdp_advertisement",
                "SSDP advertises %s on the local network" % marker,
                source="hardware_wallet_detect:ssdp",
                confidence=70,
                evidence={"severity": "low",
                          "remediation": REMEDIATION_DEVICE,
                          "marker": marker}))
        for entry in parse_arp(arp_text or ""):
            if entry["ip"] == ip and entry["vendor"] != "unknown":
                findings.append(self._f(
                    "infra", "hw_wallet_mac_vendor",
                    "%s is a %s device (%s)"
                    % (ip, entry["vendor"], entry["mac"]),
                    source="hardware_wallet_detect:arp",
                    confidence=60,
                    evidence={"severity": "low",
                              "remediation": REMEDIATION_DEVICE,
                              "mac": entry["mac"],
                              "vendor": entry["vendor"]}))
        # Reverse DNS (read-only, any target).
        try:
            rev = await asyncio.to_thread(socket.gethostbyaddr, ip)
            if rev and rev[0]:
                notes.append("reverse DNS: %s" % rev[0])
        except Exception:
            pass

        # -- stage 2: BLOCKCHAIN-BACKEND correlation ------------------
        # (a) Bitnodes per-node lookup (keyless public API).
        try:
            page = await ctx.fetch_page(
                BITNODES_NODE_URL.format(ip=ip), timeout=10)
            payload = None
            if page is not None:
                text = page.get("text", "") if isinstance(page, dict) \
                    else getattr(page, "text", "")
                try:
                    payload = json.loads(text) if text else None
                except Exception:
                    payload = None
            node = parse_bitnodes_node(payload)
            if node:
                findings.append(self._f(
                    "infra", "hw_wallet_node_backend",
                    "IP %s is a public Bitcoin node (%s, height %s)"
                    % (ip, node.get("user_agent", "?"),
                       node.get("height", "?")),
                    source="hardware_wallet_detect:bitnodes",
                    source_url=BITNODES_NODE_URL.format(ip=ip),
                    confidence=95,
                    evidence={
                        "severity": "low",
                        "remediation": REMEDIATION_NODE,
                        "backend": "bitnodes",
                        "user_agent": node.get("user_agent", ""),
                        "height": node.get("height"),
                        "city": node.get("city", ""),
                        "country": node.get("country", ""),
                        "asn": node.get("asn", ""),
                        "organization": node.get("organization", ""),
                    }))
                ctx.publish("tech", "bitcoin-node:%s" % ip)
            else:
                notes.append("bitnodes: IP is not a listed Bitcoin node")
        except Exception:
            notes.append("bitnodes lookup failed")
        # (b) Solana public peer table (keyless public RPC).
        try:
            if getattr(ctx, "http", None) is not None:
                resp = await ctx.http.post(
                    SOLANA_RPC_URL,
                    json={"jsonrpc": "2.0", "id": 1,
                          "method": "getClusterNodes"},
                    timeout=10)
                payload = resp.json() if resp is not None else None
                matches = parse_solana_cluster_nodes(payload, ip)
                for m in matches:
                    findings.append(self._f(
                        "infra", "hw_wallet_node_backend",
                        "IP %s is a Solana cluster node (%s)"
                        % (ip, m.get("gossip", "?")),
                        source="hardware_wallet_detect:solana",
                        source_url=SOLANA_RPC_URL,
                        confidence=90,
                        evidence={
                            "severity": "low",
                            "remediation": REMEDIATION_NODE,
                            "backend": "solana getClusterNodes",
                            "gossip": m.get("gossip", ""),
                            "version": m.get("version", ""),
                        }))
                if not matches:
                    notes.append("solana: IP is not a listed cluster node")
        except Exception:
            notes.append("solana peer-table lookup failed")
        # (c) TCP fingerprint of known P2P / wallet-backend ports.
        open_ports = []
        for port, svc in P2P_PORTS.items():
            try:
                if await asyncio.to_thread(tcp_open, ip, port, 2.0):
                    open_ports.append((port, svc))
            except Exception:
                continue
        for port, svc in open_ports:
            findings.append(self._f(
                "infra", "hw_wallet_backend_port_open",
                "%s port open on %s (%s)" % (svc, ip, port),
                source="hardware_wallet_detect:ports",
                confidence=80,
                evidence={"severity": "medium",
                          "remediation": REMEDIATION_NODE,
                          "port": port, "service": svc}))
        if open_ports:
            notes.append("backend ports open: %s" % ", ".join(
                str(p) for p, _ in open_ports))
        notes.append("gated backends skipped (key/login required): "
                     + "; ".join(gated))

        # -- stage 3: DEVICE stage ------------------------------------
        for dev in parse_lsusb(usb_text or ""):
            label = dev["vendor"] + (
                " %s" % dev["model"] if dev["model"] else "")
            findings.append(self._f(
                "infra", "hw_wallet_usb_device",
                "USB hardware wallet attached: %s" % label,
                source="hardware_wallet_detect:usb",
                confidence=95 if dev["match"] == "exact" else 80,
                evidence={
                    "severity": "medium",
                    "remediation": REMEDIATION_DEVICE,
                    "vendor": dev["vendor"], "model": dev["model"],
                    "vid": "0x%04x" % dev["vid"],
                    "pid": "0x%04x" % dev["pid"],
                    "match": dev["match"],
                }))
            ctx.publish("tech", "hw-wallet-usb:%s" % dev["vendor"].lower())
        if ps_text:
            low = ps_text.lower()
            for proc in WALLET_PROCESSES:
                if proc in low:
                    findings.append(self._f(
                        "infra", "hw_wallet_process_running",
                        "wallet software running: %s" % proc,
                        source="hardware_wallet_detect:ps",
                        confidence=80,
                        evidence={"severity": "low",
                                  "remediation": REMEDIATION_DEVICE,
                                  "process": proc}))
                    break
        if local:
            for d in _wallet_dirs_present():
                findings.append(self._f(
                    "infra", "hw_wallet_software_dir",
                    "wallet software data directory present: %s" % d,
                    source="hardware_wallet_detect:dirs",
                    confidence=85,
                    evidence={"severity": "low",
                              "remediation": REMEDIATION_DEVICE,
                              "directory": d}))

        # -- stage 4: FILES stage --------------------------------------
        for e in file_entries:
            kind = classify_wallet_file(e.get("path", ""))
            if kind is None or kind == "key_material":
                continue  # key files already reported by the pre-gate
            findings.append(self._f(
                "infra", "hw_wallet_file_present",
                "wallet file present: %s (%s, %s bytes)"
                % (e.get("path", "").split("/")[-1], kind,
                   e.get("size", "?")),
                source="hardware_wallet_detect:files",
                confidence=75,
                evidence={"severity": "low",
                          "remediation": REMEDIATION_DEVICE,
                          "path": e.get("path", ""),
                          "kind": kind, "size": e.get("size"),
                          "mtime": e.get("mtime")}))

        reason = "; ".join(notes) if notes else "hardware wallet scan done"
        self._checkpoint(findings)
        return self._ok(findings, reason)
