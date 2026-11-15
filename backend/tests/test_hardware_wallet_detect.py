"""Behavior tests for hardware_wallet_detect (2026-11-14).

Every stage is exercised with canned data - network-free except one
real localhost TCP check. Covers: expected findings on positive input,
clean controls staying silent, the fingerprint-only key pre-gate (no
key material ever leaves the plugin), and the gated-backend rule.
"""
import asyncio
import json
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.plugins import hardware_wallet_detect as hwd  # noqa: E402
from app.plugins.base import Target  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures (fake evidence - never real key material)
# ---------------------------------------------------------------------------

LSUSB_WITH_WALLETS = """\
Bus 001 Device 002: ID 2c97:0001 Ledger Nano S
Bus 001 Device 003: ID 534c:0001 SatoshiLabs Trezor One
Bus 001 Device 004: ID 046d:c52b Logitech, Inc. Unifying Receiver
Bus 002 Device 002: ID 03eb:2402 Atmel Corp. BitBox02
"""

LSUSB_CLEAN = """\
Bus 001 Device 004: ID 046d:c52b Logitech, Inc. Unifying Receiver
Bus 001 Device 005: ID 05ac:024f Apple, Inc. Aluminium Keyboard
"""

LSUSB_ATMEL_GENERIC = """\
Bus 001 Device 006: ID 03eb:1234 Atmel Corp. Generic Eval Board
"""

BITNODES_FOUND = {
    "found": True,
    "hostname": "s-66-183-183-17.bc.hsia.telus.net",
    "address": "66.183.183.17",
    "status": "UP",
    "node": {
        "user_agent": "/Satoshi:29.1.0/",
        "height": 975854,
        "city": "Courtenay",
        "country": "CA",
        "asn": "AS852",
        "organization": "TELUS Communications",
    },
}

BITNODES_NOT_FOUND = {"found": False, "address": "8.8.8.8"}

SOLANA_NODES = {
    "jsonrpc": "2.0",
    "result": [
        {"gossip": "66.183.183.17:8001", "pubkey": "7Np41oeYq",
         "version": "2.0.1"},
        {"gossip": "1.2.3.4:8001", "pubkey": "9Xq2mPkd",
         "version": "2.0.1"},
    ],
    "id": 1,
}

WALLET_FILES = [
    {"path": ".config/Ledger Live/wallet.dat", "size": 98304,
     "mtime": 1700000000},
    {"path": ".config/Ledger Live/app.json", "size": 2048,
     "mtime": 1700000000},
    {"path": ".electrum/UTC--2024-01-01T00-00-00.000Z--"
             "0123456789abcdef0123456789abcdef01234567",
     "size": 512, "mtime": 1700000000},
    {"path": ".config/Ledger Live/debug.log", "size": 4096,
     "mtime": 1700000000},
    {"path": ".config/Ledger Live/notes.txt", "size": 128,
     "mtime": 1700000000},
]

# A planted fake mnemonic. It must NEVER appear in any finding value
# or evidence: the plugin only ever reports filenames and sizes.
FAKE_MNEMONIC = ("abandon ability able about above absent absorb abstract "
                 "absurd abuse access accident")

MDNS_WITH_TREZOR = "_trezor-bridge._tcp.local. port 21325 txt=trezord"
SSDP_WITH_LEDGER = ("HTTP/1.1 200 OK\r\nSERVER: Linux/3.10, "
                    "UPnP/1.0, ledger-live/2.0\r\n"
                    "ST: urn:schemas-upnp-org:device:ledger:1")
ARP_TEXT = "? (192.168.1.10) at dc:a6:32:11:22:33 [ether] on wlan0"


# ---------------------------------------------------------------------------
# Harness (mirrors backend/tests/test_new_plugins.py CtxStub)
# ---------------------------------------------------------------------------

class _FakeCache:
    def get(self, *a, **k):
        return None

    def set(self, *a, **k):
        return None

    async def cached(self, source, target, fn, ttl=None):
        return await fn(), False


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class _FakeHttp:
    def __init__(self, payload=None):
        self.payload = payload
        self.posts = []

    async def post(self, url, json=None, timeout=None):
        self.posts.append((url, json))
        return _FakeResp(self.payload)


class CtxStub:
    def __init__(self, pages=None, probes=None, http=None, shared=None,
                 mode="passive"):
        self.run_id = "test"
        self.mode = mode
        self.http = http
        self.cache = _FakeCache()
        self.keys = {}
        self.limiter = None
        self.emit = None
        self.module_overrides = {}
        self.evidence_dir = "/tmp"
        self.source_type = "website"
        self.shared = dict(shared or {})
        self.pages = pages or {}
        self.probes = probes or {}

    def publish(self, kind, item):
        b = self.shared.setdefault(kind, [])
        if isinstance(item, str):
            if item not in b:
                b.append(item)
        else:
            b.append(item)

    def consume(self, kind):
        return list(self.shared.get(kind, []))

    async def fetch_page(self, url, timeout=10):
        return self.pages.get(url) or self.pages.get(url.rstrip("/"))

    async def probe(self, url, timeout=8):
        return self.probes.get(url) or {"status": 0, "headers": {},
                                        "text": "", "url": url}


def _run(target, ctx):
    """Run the plugin with all live host/network I/O stubbed out."""
    import unittest.mock as _mock
    with _mock.patch.object(hwd, "tcp_open",
                            lambda *a, **k: False), \
         _mock.patch.object(hwd, "_collect_local_files",
                            lambda: []), \
         _mock.patch.object(hwd, "_wallet_dirs_present",
                            lambda: []), \
         _mock.patch.object(hwd, "_run_lsusb", lambda: None), \
         _mock.patch.object(hwd, "_run_ps", lambda: None):
        return asyncio.run(hwd.HardwareWalletDetect().run(target, ctx))


def _bitnodes_page(ip, payload):
    url = hwd.BITNODES_NODE_URL.format(ip=ip)
    return {url: {"status_code": 200, "headers": {},
                  "text": json.dumps(payload), "url": url}}


def _keys(result):
    return sorted({f.key for f in result.findings})


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def test_parse_lsusb_identifies_wallets():
    devs = hwd.parse_lsusb(LSUSB_WITH_WALLETS)
    by_vendor = {d["vendor"]: d for d in devs}
    assert by_vendor["Ledger"]["model"] == "Nano S"
    assert by_vendor["Ledger"]["match"] == "exact"
    assert by_vendor["Trezor"]["model"] == "One"
    assert by_vendor["BitBox"]["model"] == "BitBox02"
    assert "Logitech" not in str(devs)


def test_parse_lsusb_clean_stays_silent():
    assert hwd.parse_lsusb(LSUSB_CLEAN) == []
    assert hwd.parse_lsusb("") == []


def test_parse_lsusb_bitbox_needs_vid_pid_pair():
    # 0x03eb is Atmel's VID, shared by many devices: VID alone must
    # NOT flag a BitBox.
    assert hwd.parse_lsusb(LSUSB_ATMEL_GENERIC) == []


def test_classify_wallet_file():
    assert hwd.classify_wallet_file("wallet.dat") == "key_material"
    assert hwd.classify_wallet_file(
        "UTC--2024-01-01T00-00-00.000Z--0123456789abcdef0123456789"
        "abcdef01234567") == "key_material"
    assert hwd.classify_wallet_file("seed backup.txt") == "key_material"
    assert hwd.classify_wallet_file("recovery-phrase.txt") == "key_material"
    assert hwd.classify_wallet_file("app.json") == "config"
    assert hwd.classify_wallet_file("debug.log") == "log"
    assert hwd.classify_wallet_file("notes.txt") is None
    assert hwd.classify_wallet_file("ledger-live.sqlite") == "app_data"


def test_key_gate_fingerprint_only():
    hits = hwd.key_gate(WALLET_FILES)
    names = [h["path"].split("/")[-1] for h in hits]
    assert names == ["wallet.dat",
                     "UTC--2024-01-01T00-00-00.000Z--"
                     "0123456789abcdef0123456789abcdef01234567"]
    # Gate output carries names and sizes only - no contents, ever.
    assert FAKE_MNEMONIC not in json.dumps(hits)


def test_parse_bitnodes_node():
    node = hwd.parse_bitnodes_node(BITNODES_FOUND)
    assert node["user_agent"] == "/Satoshi:29.1.0/"
    assert node["height"] == 975854
    assert node["country"] == "CA"
    assert node["asn"] == "AS852"
    assert hwd.parse_bitnodes_node(BITNODES_NOT_FOUND) is None
    assert hwd.parse_bitnodes_node({}) is None
    assert hwd.parse_bitnodes_node(None) is None


def test_parse_solana_cluster_nodes():
    matches = hwd.parse_solana_cluster_nodes(SOLANA_NODES,
                                             "66.183.183.17")
    assert len(matches) == 1
    assert matches[0]["gossip"] == "66.183.183.17:8001"
    assert hwd.parse_solana_cluster_nodes(SOLANA_NODES, "8.8.8.8") == []
    assert hwd.parse_solana_cluster_nodes({}, "66.183.183.17") == []


def test_parse_mdns_ssdp():
    assert hwd.parse_mdns(MDNS_WITH_TREZOR) == ["trezor", "trezord"]
    assert hwd.parse_mdns("nothing here") == []
    assert hwd.parse_ssdp(SSDP_WITH_LEDGER) == ["ledger"]
    assert hwd.parse_ssdp("") == []


def test_parse_arp_and_mac_vendor():
    assert hwd.mac_vendor("dc:a6:32:11:22:33") == "Raspberry Pi"
    assert hwd.mac_vendor("00:11:22:33:44:55") == "unknown"
    entries = hwd.parse_arp(ARP_TEXT)
    assert entries == [{"ip": "192.168.1.10",
                        "mac": "dc:a6:32:11:22:33",
                        "vendor": "Raspberry Pi"}]


def test_parse_bridge_probe():
    hit = hwd.parse_bridge_probe(21325, 404, {"server": "trezord/2.0.0"},
                                 "not found")
    assert hit and hit["service"] == "Trezor Bridge (trezord)"
    assert hwd.parse_bridge_probe(21325, 200, {"server": "nginx"},
                                  "hello") is None
    assert hwd.parse_bridge_probe(8080, 200, {"server": "trezord"},
                                  "") is None


def test_tcp_open_local_listener():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _serve():
        try:
            conn, _ = srv.accept()
            conn.close()
        except Exception:
            pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    try:
        assert hwd.tcp_open("127.0.0.1", port) is True
    finally:
        srv.close()
    # A port with nothing listening on it: bind to pick a free port,
    # close it, then it must refuse.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()
    assert hwd.tcp_open("127.0.0.1", closed_port) is False


def test_is_local_target():
    assert hwd.is_local_target("127.0.0.1") is True
    assert hwd.is_local_target("192.168.1.10") is True
    assert hwd.is_local_target("10.0.0.5") is True
    assert hwd.is_local_target("8.8.8.8") is False
    assert hwd.is_local_target("not-an-ip") is False


# ---------------------------------------------------------------------------
# Plugin runs
# ---------------------------------------------------------------------------

def test_plugin_clean_local_target_silent():
    ctx = CtxStub(pages=_bitnodes_page("127.0.0.1", BITNODES_NOT_FOUND),
                  http=_FakeHttp({"result": []}),
                  shared={"local_usb_devices": "",
                          "local_processes": "",
                          "local_wallet_files": []})
    result = _run(Target("127.0.0.1", "ip"), ctx)
    assert result.findings == []
    assert "key pre-gate" in result.reason


def test_plugin_usb_and_files_findings():
    ctx = CtxStub(pages=_bitnodes_page("127.0.0.1", BITNODES_NOT_FOUND),
                  http=_FakeHttp({"result": []}),
                  shared={"local_usb_devices": LSUSB_WITH_WALLETS,
                          "local_processes": "user 123 trezord -p 21325",
                          "local_wallet_files": WALLET_FILES})
    result = _run(Target("127.0.0.1", "ip"), ctx)
    keys = _keys(result)
    assert "hw_wallet_key_material_present" in keys
    assert "hw_wallet_usb_device" in keys
    assert "hw_wallet_file_present" in keys
    assert "hw_wallet_process_running" in keys
    # The key-gate finding names files and sizes only: the planted
    # mnemonic (which the plugin never saw as content) is nowhere.
    blob = json.dumps([(f.key, f.value, f.evidence)
                       for f in result.findings])
    assert FAKE_MNEMONIC not in blob
    assert "abandon ability" not in blob
    # No finding value ever carries key material shapes either.
    assert "xprv" not in blob
    usb = [f for f in result.findings
           if f.key == "hw_wallet_usb_device"]
    assert {f.evidence["vendor"] for f in usb} == {
        "Ledger", "Trezor", "BitBox"}


def test_plugin_bitnodes_node_finding():
    ctx = CtxStub(pages=_bitnodes_page("66.183.183.17", BITNODES_FOUND),
                  http=_FakeHttp({"result": []}),
                  shared={"local_usb_devices": "",
                          "local_processes": "",
                          "local_wallet_files": []})
    result = _run(Target("66.183.183.17", "ip"), ctx)
    nodes = [f for f in result.findings
             if f.key == "hw_wallet_node_backend"]
    assert len(nodes) == 1
    assert nodes[0].evidence["backend"] == "bitnodes"
    assert nodes[0].evidence["user_agent"] == "/Satoshi:29.1.0/"
    assert nodes[0].evidence["asn"] == "AS852"


def test_plugin_solana_node_finding():
    ctx = CtxStub(pages=_bitnodes_page("66.183.183.17",
                                       BITNODES_NOT_FOUND),
                  http=_FakeHttp(SOLANA_NODES),
                  shared={"local_usb_devices": "",
                          "local_processes": "",
                          "local_wallet_files": []})
    result = _run(Target("66.183.183.17", "ip"), ctx)
    nodes = [f for f in result.findings
             if f.key == "hw_wallet_node_backend"]
    assert len(nodes) == 1
    assert nodes[0].evidence["backend"] == "solana getClusterNodes"


def test_plugin_bridge_detected():
    probes = {"http://127.0.0.1:21325/": {
        "status": 404, "headers": {"server": "trezord/2.0.0"},
        "text": "not found", "url": "http://127.0.0.1:21325/"}}
    ctx = CtxStub(pages=_bitnodes_page("127.0.0.1", BITNODES_NOT_FOUND),
                  probes=probes, http=_FakeHttp({"result": []}),
                  shared={"local_usb_devices": "",
                          "local_processes": "",
                          "local_wallet_files": []})
    result = _run(Target("127.0.0.1", "ip"), ctx)
    assert "hw_wallet_bridge_detected" in _keys(result)


def test_plugin_mdns_ssdp_arp_findings():
    ctx = CtxStub(pages=_bitnodes_page("192.168.1.10",
                                       BITNODES_NOT_FOUND),
                  http=_FakeHttp({"result": []}),
                  shared={"local_usb_devices": "",
                          "local_processes": "",
                          "local_wallet_files": [],
                          "local_mdns": MDNS_WITH_TREZOR,
                          "local_ssdp": SSDP_WITH_LEDGER,
                          "local_arp": ARP_TEXT})
    result = _run(Target("192.168.1.10", "ip"), ctx)
    keys = _keys(result)
    assert "hw_wallet_mdns_advertisement" in keys
    assert "hw_wallet_ssdp_advertisement" in keys
    assert "hw_wallet_mac_vendor" in keys


def test_plugin_remote_target_gets_network_stages_only():
    # No bus-fed local data and a public IP: nothing local can fire.
    ctx = CtxStub(pages=_bitnodes_page("8.8.8.8", BITNODES_NOT_FOUND),
                  http=_FakeHttp({"result": []}), shared={})
    result = _run(Target("8.8.8.8", "ip"), ctx)
    assert result.findings == []


def test_plugin_bus_fed_usb_honored_for_remote_target():
    # Bus-fed evidence is attested to the target by the agent that fed
    # it, so it counts even for a non-local target.
    ctx = CtxStub(pages=_bitnodes_page("8.8.8.8", BITNODES_NOT_FOUND),
                  http=_FakeHttp({"result": []}),
                  shared={"local_usb_devices": LSUSB_WITH_WALLETS,
                          "local_processes": "",
                          "local_wallet_files": []})
    result = _run(Target("8.8.8.8", "ip"), ctx)
    assert "hw_wallet_usb_device" in _keys(result)


def test_plugin_gated_backends_noted_never_queried():
    ctx = CtxStub(pages=_bitnodes_page("8.8.8.8", BITNODES_NOT_FOUND),
                  http=_FakeHttp({"result": []}), shared={})
    result = _run(Target("8.8.8.8", "ip"), ctx)
    assert "gated backends skipped" in result.reason
    assert "Etherscan" in result.reason
    # No HTTP client was given a keyed URL: nothing was fetched beyond
    # the keyless bitnodes lookup and the (stubbed) solana RPC.
    assert ctx.http.posts == [(hwd.SOLANA_RPC_URL,
                               {"jsonrpc": "2.0", "id": 1,
                                "method": "getClusterNodes"})]


def test_plugin_unresolvable_target_skips():
    ctx = CtxStub(http=_FakeHttp({"result": []}), shared={})
    result = _run(Target("nonexistent.invalid", "domain"), ctx)
    assert result.findings == []
