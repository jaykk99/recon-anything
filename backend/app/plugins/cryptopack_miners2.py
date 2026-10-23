"""Crypto pack wave 2: more mining - named pool stratum endpoints,
XMRig proxy/config-with-wallet detection, miner dashboards, and
the webminer kits wave 1 missed.

Wave 1 covered the classic browser miners and generic stratum://
URLs. Wave 2 attributes pool infrastructure per operator (the
pool hostname is the durable IOC), and catches the xmrig config
variant that carries the payout wallet in its pools array.
"""
from __future__ import annotations

from .cryptopack_util import PackPlugin, xmr_verify


def _pool(id_, brand, hosts, key):
    host_re = "|".join(h.replace(".", r"\.") for h in hosts)
    return type(id_, (PackPlugin,), {
        "id": id_,
        "label": f"Mining pool endpoints: {brand}",
        "description": f"{brand} stratum pool hostnames referenced "
                       "by the target - its mining (or its "
                       "compromise's mining) phones home here.",
        "__module__": __name__,
        "PATTERNS": [
            (rf"\b(?:[a-z0-9\-]+\.)?(?:{host_re})(?::\d{{2,5}})?\b",
             key, f"{brand} pool endpoint", 85, None)],
    })


CpPool2miners = _pool(
    "cp_pool_2miners", "2Miners",
    ("2miners.com",), "pool_2miners")

CpPoolNanopool = _pool(
    "cp_pool_nanopool", "Nanopool",
    ("nanopool.org",), "pool_nanopool")

CpPoolHiveon = _pool(
    "cp_pool_hiveon", "Hiveon",
    ("hiveon.net", "hiveon.com"), "pool_hiveon")

CpPoolViabtc = _pool(
    "cp_pool_viabtc", "ViaBTC",
    ("viabtc.com", "viabtc.net"), "pool_viabtc")

CpPoolLuxor = _pool(
    "cp_pool_luxor", "Luxor",
    ("mining.luxor.tech", "luxor.tech"), "pool_luxor")


class CpMinerXmrigProxy(PackPlugin):
    id = "cp_miner_xmrig_proxy"
    label = "Mining: XMRig proxy"
    description = ("XMRig stratum proxy signatures - the aggregation "
                   "layer mining botnets put between compromised "
                   "miners and the pool.")
    PATTERNS = [
        (r"(?:xmrig[-_ ]?proxy|xmrig-proxy|stratum[-_ ]?proxy.{0,30}"
         r"(?:xmr|monero|mining))",
         "miner_xmrig_proxy", "XMRig proxy reference", 85, None),
    ]


class CpMinerConfigWallet(PackPlugin):
    id = "cp_miner_config_wallet"
    label = "Exposed miner config with payout wallet"
    description = ("xmrig-style config bodies whose pools array "
                   "carries a stratum URL and a wallet 'user' - a "
                   "complete mining operation, payout address "
                   "included. The wallet is checksum-verified where "
                   "the chain has one.")
    VALUE_GROUP = 2
    PATTERNS = [
        (r"\"pools\"\s*:\s*\[\s*\{[^}]{0,300}?\"url\"\s*:\s*\"([^\"]+)\""
         r"[^}]{0,200}?\"user\"\s*:\s*\"([^\"]+)\"",
         "miner_config_wallet", "Miner config with payout wallet",
         92, None),
        (r"(\"user\"\s*:\s*)\"(4[1-9A-HJ-NP-Za-km-z]{94})\"",
         "miner_config_xmr_wallet", "Miner config Monero wallet", 95,
         lambda s: xmr_verify(s, (0x12, 0x35, 0x2A, 0x45))),
    ]


class CpMinerDashboardRefs(PackPlugin):
    id = "cp_miner_dashboard_refs"
    label = "Miner dashboard / fleet management references"
    description = ("Mining fleet dashboards (Hive OS, minerstat) "
                   "and XMRig HTTP API references in the target's "
                   "content - signs of an operated mining setup, "
                   "legit or otherwise.")
    PATTERNS = [
        (r"(?:hiveos\.farm|the\.hiveos\.farm|app\.hiveon\.com)",
         "miner_dashboard_hiveos", "Hive OS dashboard reference", 75,
         None),
        (r"(?:minerstat\.com|msr\.minerstat\.com)",
         "miner_dashboard_minerstat", "minerstat dashboard reference",
         75, None),
        (r"(?:api\.xmrig\.com|xmrig[^\"']{0,30}/json_rpc)",
         "miner_xmrig_api", "XMRig API reference", 78, None),
    ]


def _kit2(id_, label, desc, patterns):
    return type(id_, (PackPlugin,), {
        "id": id_, "label": label, "description": desc,
        "__module__": __name__,
        "PATTERNS": patterns,
    })


CpMinerDeepminer = _kit2(
    "cp_miner_deepminer", "Cryptojacking: DeepMiner",
    "DeepMiner web miner (deepminer / deepminer.net loader).",
    [(r"(?:deepminer(?:\.net)?/(?:lib|js)|DeepMiner\.Anonymous|"
      r"deepminer\.min\.js)",
      "miner_deepminer", "DeepMiner miner script", 88, None)])

CpMinerWebminerpool = _kit2(
    "cp_miner_webminerpool", "Cryptojacking: WebMinerPool",
    "WebMinerPool open-source web miner (webminerpool.com loader / "
    "WMP-style globals distinct from WebMinePool).",
    [(r"(?:webminerpool\.com|WebMinerPool|webminerpool)",
      "miner_webminerpool", "WebMinerPool miner script", 85, None)])

CpMinerMinero = _kit2(
    "cp_miner_minero", "Cryptojacking: Minero",
    "Minero web miner network (minero.cc loader, Minero.User API).",
    [(r"(?:minero\.cc/(?:lib|miner)|Minero\.(?:User|Anonymous))",
      "miner_minero", "Minero miner script", 88, None)])
