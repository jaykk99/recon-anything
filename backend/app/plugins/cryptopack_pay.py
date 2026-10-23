"""Crypto pack: payment rails, mining pools, miner artifacts.

Hosted payment processors the target takes money through (spoofing
and account-takeover targets), mining pool infrastructure it
references, and miner configs/binaries it exposes. The xmrig config
detector is the sleeper here: a served config.json with pool URL +
wallet user is a complete mining operation on a plate.
"""
from __future__ import annotations

from .cryptopack_util import PackPlugin


def _pay(id_, label, desc, patterns):
    return type(id_, (PackPlugin,), {
        "id": id_, "label": label, "description": desc,
        "__module__": __name__,
        "PATTERNS": patterns,
    })


CpPayBtcpay = _pay(
    "cp_pay_btcpay", "Payment rail: BTCPay Server",
    "BTCPay Server checkout/invoice endpoints the target uses.",
    [(r"(?:btcpay|/api/v1/invoices|/i/[A-Za-z0-9]{20,}|BTCPayServer)",
      "pay_btcpay", "BTCPay Server reference", 80, None)])

CpPayCoinbaseCommerce = _pay(
    "cp_pay_coinbase_commerce", "Payment rail: Coinbase Commerce",
    "Coinbase Commerce hosted charge links.",
    [(r"commerce\.coinbase\.com/(?:checkout|charges)/[A-Za-z0-9\-]+",
      "pay_coinbase_commerce", "Coinbase Commerce charge link", 85, None)])

CpPayNowpayments = _pay(
    "cp_pay_nowpayments", "Payment rail: NOWPayments",
    "NOWPayments payment links/widgets.",
    [(r"(?:nowpayments\.io/(?:payment|donation)|NOWPayments)",
      "pay_nowpayments", "NOWPayments reference", 80, None)])

CpPayCoingate = _pay(
    "cp_pay_coingate", "Payment rail: CoinGate",
    "CoinGate payment buttons/order endpoints.",
    [(r"(?:coingate\.com/pay/|CoinGate)", "pay_coingate",
      "CoinGate reference", 80, None)])

CpPayCoinpayments = _pay(
    "cp_pay_coinpayments", "Payment rail: CoinPayments",
    "CoinPayments checkout buttons/links.",
    [(r"(?:coinpayments\.net/index\.php\?cmd=_pay|coinpayments\.net)"
      , "pay_coinpayments", "CoinPayments reference", 75, None)])

CpPayOpennode = _pay(
    "cp_pay_opennode", "Payment rail: OpenNode",
    "OpenNode Lightning/BTC checkout links.",
    [(r"(?:app\.opennode\.com|checkout\.opennode\.com)", "pay_opennode",
      "OpenNode checkout reference", 80, None)])

CpPayBitpay = _pay(
    "cp_pay_bitpay", "Payment rail: BitPay",
    "BitPay invoice/checkout links.",
    [(r"(?:bitpay\.com/(?:checkout|invoices)|bitpay\.com/checkout)",
      "pay_bitpay", "BitPay checkout reference", 80, None)])

CpPayBlockonomics = _pay(
    "cp_pay_blockonomics", "Payment rail: Blockonomics",
    "Blockonomics payment links/widgets.",
    [(r"(?:blockonomics\.co|www\.blockonomics\.co/api)",
      "pay_blockonomics", "Blockonomics reference", 75, None)])

CpPayCryptocom = _pay(
    "cp_pay_cryptocom_pay", "Payment rail: Crypto.com Pay",
    "Crypto.com Pay checkout references.",
    [(r"(?:pay\.crypto\.com|Crypto\.com Pay)", "pay_cryptocom",
      "Crypto.com Pay reference", 75, None)])


class CpPoolDomainRefs(PackPlugin):
    id = "cp_pool_domain_refs"
    label = "Mining pool references"
    description = ("Known mining pool domains referenced by the "
                   "target (F2Pool, ViaBTC, AntPool, Hiveon, 2Miners, "
                   "Nanopool, WoolyPooly, HeroMiners, SupportXMR, "
                   "MoneroOcean) - its mining footprint, legitimate "
                   "or planted.")
    PATTERNS = [
        (r"(?:f2pool\.com|viabtc\.com|antpool\.com|poolin\.com|"
         r"hiveon\.net|2miners\.com|nanopool\.org|woolypooly\.com|"
         r"herominers\.com|supportxmr\.com|moneroocean\.stream|"
         r"minexmr\.com|xmrpool\.eu|ragerx\.lol|unmineable\.com)",
         "mining_pool_ref", "Mining pool reference", 75, None),
    ]


class CpMinerConfigExposure(PackPlugin):
    id = "cp_miner_config_exposure"
    label = "Exposed miner configuration (xmrig-style)"
    description = ("xmrig-format miner config in served content: "
                   "algorithm + pool URL + wallet user together are a "
                   "working mining operation, whoever planted it.")
    PATTERNS = [
        (r"(?:\"algo\"\s*:\s*\"rx/0\"|\"algo\"\s*:\s*\"rx/wow\"|"
         r"\"coin\"\s*:\s*\"monero\")",
         "miner_config_algo", "Miner config (algorithm)", 80, None),
        (r"\"pools\"\s*:\s*\[\s*\{\s*\"url\"\s*:", "miner_config_pools",
         "Miner config (pool list)", 85, None),
        (r"\"donate-level\"\s*:\s*\d", "miner_config_donate",
         "Miner config (donate level)", 80, None),
    ]


class CpMinerBinaryLinks(PackPlugin):
    id = "cp_miner_binary_links"
    label = "Miner binary / release links"
    description = ("Download links for miner software releases "
                   "(xmrig, gminer, lolMiner, T-Rex, NBMiner, "
                   "SRBMiner, TeamRedMiner) hosted or referenced by "
                   "the target.")
    VALUE_GROUP = 1
    PATTERNS = [
        (r"((?:https?://)?[^\s\"'<>]*(?:xmrig|gminer|lolminer|"
         r"t-rex|nbminer|srbminer|teamredminer|phoenixminer)"
         r"[^\s\"'<>]*\.(?:zip|tar\.gz|exe|msi))",
         "miner_binary_link", "Miner binary download link", 75, None),
        (r"(github\.com/[^\s\"'<>]*/(?:xmrig|gminer|lolMiner|t-rex|"
         r"NBMiner|SRBMiner-Multi)/releases)",
         "miner_release_link", "Miner release page link", 70, None),
    ]
