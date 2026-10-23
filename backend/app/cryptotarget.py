"""Crypto-class target priority (Jay's order, 2026-10-23).

"Make sure if doing a crypto.com url like Crypto.com it should
find private keys not just whatever it's finding."

When a scan target is a crypto/web3 property (exchange, wallet
service, DeFi, token/project site - crypto.com is the archetype),
the scan exists to find EXPOSED private keys, seed phrases and
wallet files the target itself serves publicly. Generic recon
noise must never crowd those hunters out. This module provides:

- classify_crypto_targets(): is this run crypto-class, and why
  (domain keyword tokens, wallet-address seed targets, or an
  explicit Crypto Pack selection at run creation).
- key_hunter_ids(): the exposed-key detector set - every
  cp_secret_*/cp_wallet_* pack plugin plus the core wallets /
  secrets / keyleak / keyharvest / js_secrets plugins. On
  crypto-class runs the runner claims these FIRST and exempts
  them from the scan time-budget skips (same treatment as
  SELECTED MEANS RUN), and their jobs are enqueued at HIGH
  priority.
- is_exposed_key_finding(): ranking matcher used by
  reporting.findings_dump - on crypto-class runs, exposed
  key/seed/keystore findings sort to the TOP of the run's
  findings and are flagged critical.

Detection only, of material the target serves publicly. Findings
keep the established masked format (masked value + fingerprint);
full private keys and seed phrases are never stored or
displayed.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set

from .classifier import domain_from_target

# Whole-token domain signals. Domains are split into labels, then
# each label into hyphen/underscore segments; a segment must match
# exactly, so "methodist" does not trip "eth" and "coinbase" is a
# token of its own. Kept deliberately specific to avoid flagging
# generic sites.
CRYPTO_TOKENS: Set[str] = {
    "crypto", "cryptocurrency", "bitcoin", "btc", "ethereum", "eth",
    "wallet", "wallets", "defi", "web3", "nft", "token", "tokens",
    "coin", "coins", "coinbase", "binance", "kraken", "kucoin",
    "bybit", "okx", "bitfinex", "bitstamp", "gemini", "huobi",
    "swap", "uniswap", "pancakeswap", "dex", "blockchain",
    "solana", "sol", "xrp", "ripple", "doge", "dogecoin",
    "litecoin", "ltc", "usdt", "tether", "ledger", "trezor",
    "metamask", "tron", "cardano", "polkadot", "avalanche", "avax",
    "polygon", "matic", "arbitrum", "aave", "opensea", "staking",
    "miner", "mining", "satoshi", "web3wallet", "trustwallet",
}

# TLDs that are themselves crypto signals (.crypto / .nft are real
# naming systems; .eth appears in pasted ENS names).
CRYPTO_TLDS: Set[str] = {"crypto", "nft", "bitcoin", "wallet", "eth", "zil"}

_SPLIT = re.compile(r"[.\-_]+")


def domain_tokens(domain: str) -> List[str]:
    return [t for t in _SPLIT.split((domain or "").lower()) if t]


def crypto_domain_reason(domain: Optional[str]) -> Optional[str]:
    """Why this domain is crypto-class, or None."""
    if not domain:
        return None
    domain = domain.lower().strip(".")
    labels = domain.split(".")
    if labels and labels[-1] in CRYPTO_TLDS:
        return f"crypto TLD .{labels[-1]}"
    for tok in domain_tokens(domain):
        if tok in CRYPTO_TOKENS:
            return f"domain keyword '{tok}'"
    return None


def classify_crypto_targets(classified: Iterable[Dict],
                            plugin_ids: Optional[Iterable[str]] = None
                            ) -> Dict:
    """Classify a run's seed targets as crypto-class or not.

    Returns {"crypto": bool, "reasons": [str, ...]}. Signals:
    wallet-address seed targets (inherently crypto), domain
    keyword/TLD matches on any seed target, and an explicit
    Crypto Pack (cp_*) selection at run creation - the user
    declaring crypto focus for the run.
    """
    reasons: List[str] = []
    for c in classified or []:
        ttype = c.get("type", "")
        if ttype == "crypto_wallet":
            reasons.append("wallet address target")
            continue
        domain = domain_from_target(ttype, c.get("normalized", ""))
        r = crypto_domain_reason(domain)
        if r:
            reasons.append(f"{domain}: {r}")
    if plugin_ids:
        pack = sorted({p for p in plugin_ids
                       if isinstance(p, str) and p.startswith("cp_")})
        if pack:
            reasons.append(f"crypto pack selected ({len(pack)} plugins)")
    # dedupe, keep order
    seen: Set[str] = set()
    uniq = [r for r in reasons if not (r in seen or seen.add(r))]
    return {"crypto": bool(uniq), "reasons": uniq}


# Core (non-pack) exposed-key hunters.
KEY_HUNTER_CORE: Set[str] = {
    "wallets", "secrets", "keyleak", "keyharvest", "js_secrets",
}

# Pack hunter prefixes: leaked-secret detectors and wallet-file
# hunters. Address-format plugins (cp_btc_*, cp_eth_*, ...) are
# deliberately NOT in the set - they find public addresses, not
# exposed keys, and must not jump the key queue.
KEY_HUNTER_PREFIXES = ("cp_secret_", "cp_wallet_")


def is_key_hunter(plugin_id: str) -> bool:
    return (plugin_id in KEY_HUNTER_CORE
            or plugin_id.startswith(KEY_HUNTER_PREFIXES))


def key_hunter_ids(plugin_ids: Iterable[str]) -> List[str]:
    """The key-hunter subset of a run's plugin id list, sorted."""
    return sorted({p for p in plugin_ids if p and is_key_hunter(p)})


# Finding-key vocabulary of exposed private keys / seeds /
# keystores / wallet files (from the hunter plugins' key names:
# env_private_key, wif_private_key, keystore_file_exposed,
# metamask_vault_object, mnemonic_keyword, xprv_extended_key...).
_EXPOSED_KEY_RE = re.compile(
    r"private[_-]?key|privkey|mnemonic|seed[_-]?(phrase|file|backup)?|"
    r"keystore|wallet[_-]?dat|electrum[_-]?wallet|wallet[_-]?(backup|"
    r"archive|file|files)|xprv|nsec|wif|vault|hardhat|signer|keypair|"
    r"bip39|node[_-]?conf[_-]?creds|recovery[_-]?phrase", re.I)


def is_exposed_key_finding(row: Dict) -> bool:
    """True when a finding row is an exposed private key, seed
    phrase, keystore or wallet-file finding.

    Every finding from a cp_secret_*/cp_wallet_* plugin is one by
    construction (those plugins only emit leaked-secret / wallet
    artifact findings). Other plugins must match the exposed-key
    key vocabulary, and generic plugins additionally need the
    leak category so e.g. a drainer kit's seed-form lure (a
    phishing artifact, not the target's own exposed key) does not
    masquerade as a key finding.
    """
    try:
        plugin = str(row.get("plugin") or row.get("plugin_id") or "")
        key = str(row.get("key") or "")
        if plugin.startswith(KEY_HUNTER_PREFIXES):
            return True
        if not _EXPOSED_KEY_RE.search(key):
            return False
        if plugin in KEY_HUNTER_CORE:
            return True
        return str(row.get("category") or "") == "leak"
    except Exception:
        return False
