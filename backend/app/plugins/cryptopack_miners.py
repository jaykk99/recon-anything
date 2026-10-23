"""Crypto pack: cryptojacking / in-browser miner detection.

No pre-existing plugin looks for browser miners (the `jsminer` plugin
mines JS for data; it does not detect mining). Each plugin here keys
on one miner kit's distinctive loader domains, script paths and JS
API globals - the signatures incident responders actually match on.
A hit means the target's pages conscript visitors' CPUs into mining
(willingly or via compromise); payout addresses/sites are extracted
into the finding value where the kit exposes them.
"""
from __future__ import annotations

from .cryptopack_util import PackPlugin


def _kit(id_, label, desc, patterns):
    return type(id_, (PackPlugin,), {
        "id": id_, "label": label, "description": desc,
        "__module__": __name__,
        "PATTERNS": patterns,
    })


CpMinerCoinhive = _kit(
    "cp_miner_coinhive", "Cryptojacking: CoinHive",
    "CoinHive in-browser Monero miner (coinhive.com loader, "
    "CoinHive.Anonymous API, site-key start call).",
    [(r"(?:coinhive\.com/lib/coinhive\.min\.js|CoinHive\.Anonymous|"
      r"coinhive\.com/captcha)", "miner_coinhive",
      "CoinHive miner script", 95, None),
     (r"new\s+CoinHive\.Anonymous\(\s*['\"][A-Za-z0-9]{32}['\"]",
      "miner_coinhive_sitekey", "CoinHive site key (payout account)", 95,
      None)])

CpMinerAuthedmine = _kit(
    "cp_miner_authedmine", "Cryptojacking: AuthedMine",
    "AuthedMine opt-in CoinHive variant (authedmine.com loader/API).",
    [(r"(?:authedmine\.com/lib/authedmine\.min\.js|AuthedMine\.Anonymous)",
      "miner_authedmine", "AuthedMine miner script", 95, None)])

CpMinerCoinimp = _kit(
    "cp_miner_coinimp", "Cryptojacking: CoinImp",
    "CoinImp miner (coinimp.com loader, Client.Anonymous API).",
    [(r"(?:coinimp\.com/scripts/min\.js|Client\.Anonymous\s*\()",
      "miner_coinimp", "CoinImp miner script", 95, None)])

CpMinerCryptoloot = _kit(
    "cp_miner_cryptoloot", "Cryptojacking: CryptoLoot",
    "CryptoLoot miner (crypto-loot.org loader, CryptoLoot.Anonymous).",
    [(r"(?:crypto-loot\.org/m\.js|CryptoLoot\.Anonymous)",
      "miner_cryptoloot", "CryptoLoot miner script", 95, None)])

CpMinerMineralt = _kit(
    "cp_miner_mineralt", "Cryptojacking: Mineralt",
    "Mineralt miner network (mineralt.io loader, Minero API).",
    [(r"(?:mineralt\.io/lib/|Minero\.(?:User|Anonymous))",
      "miner_mineralt", "Mineralt miner script", 90, None)])

CpMinerJsecoin = _kit(
    "cp_miner_jsecoin", "Cryptojacking: JSEcoin",
    "JSEcoin platform miner (jsecoin.com loader / JSEmining API).",
    [(r"(?:jsecoin\.com/(?:server|platform)|JSEmining|"
      r"load\.jsecoin\.com)",
      "miner_jsecoin", "JSEcoin miner script", 90, None)])

CpMinerCoinnebula = _kit(
    "cp_miner_coinnebula", "Cryptojacking: CoinNebula",
    "CoinNebula miner (coinnebula.com loader, CoinNebula API).",
    [(r"(?:coinnebula\.com/lib/|CoinNebula\s*\()",
      "miner_coinnebula", "CoinNebula miner script", 90, None)])

CpMinerWebminepool = _kit(
    "cp_miner_webminepool", "Cryptojacking: WebMinePool",
    "WebMinePool miner (webminepool.com loader, WMP.Anonymous API).",
    [(r"(?:webminepool\.com/lib/base\.js|WMP\.Anonymous)",
      "miner_webminepool", "WebMinePool miner script", 90, None)])

CpMinerMoneroocean = _kit(
    "cp_miner_moneroocean", "Cryptojacking: MoneroOcean web miner",
    "MoneroOcean pool web miner (moneroocean.stream miner script).",
    [(r"moneroocean\.stream/(?:miner|main)\.js",
      "miner_moneroocean", "MoneroOcean web miner script", 90, None)])


class CpMinerXmrigWeb(PackPlugin):
    id = "cp_miner_xmrig_web"
    label = "Cryptojacking: XMRig web port"
    description = ("XMRig compiled/ported for the browser (xmrig wasm "
                   "workers, startXmrig-style bootstraps in JS).")
    PATTERNS = [
        (r"(?:xmrig\.min\.js|xmrig\.wasm|startXmrig|XmrigMiner)",
         "miner_xmrig_web", "XMRig web miner artifact", 85, None),
    ]


class CpMinerWasmCryptonight(PackPlugin):
    id = "cp_miner_wasm_cryptonight"
    label = "Cryptojacking: CryptoNight WASM miner (generic)"
    description = ("Generic WASM CryptoNight miner artifacts: "
                   "cryptonight wasm modules plus worker bootstrap "
                   "strings no legitimate library ships.")
    PATTERNS = [
        (r"(?:cryptonight\.wasm|cn\.wasm|cryptonight-worker|"
          r"wasm_miner|webminer\.js|miner\.wasm)",
         "miner_wasm_cryptonight", "CryptoNight WASM miner artifact", 85,
         None),
    ]


class CpMinerStratumEndpoints(PackPlugin):
    id = "cp_miner_stratum_endpoints"
    label = "Mining Pool Stratum Endpoints"
    description = ("Stratum mining endpoints referenced by the target "
                   "(stratum+tcp/ssl/ws URLs): pool infrastructure "
                   "the target's mining - or its compromises - talk to.")
    VALUE_GROUP = 1
    PATTERNS = [
        (r"\b(stratum\+(?:tcp|ssl|ws|wss)://[^\s\"'<>]+)", "stratum_endpoint",
         "Stratum endpoint", 90, None),
        (r"\b(stratum://[^\s\"'<>]+)", "stratum_endpoint",
         "Stratum endpoint", 85, None),
    ]
