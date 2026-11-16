"""Address labeling for crypto OSINT (keyless, defensive).

Given a discovered address, attach what is publicly known about it:
burn/null addresses, known mixers, bridges, major-exchange hot wallets,
and sanctioned (OFAC-listed) addresses. This is the same labeling a
block explorer or a compliance tool shows - public, read-only
intelligence that turns "an address" into "an address linked to X".

Everything here is a small curated set of *publicly documented*
addresses plus a few structural heuristics. No network, no keys, pure
stdlib - so it unit-tests on its own and can never break a scan. It is
analysis, not action: nothing here signs, sends, or deanonymizes a
private individual; it only reports what an explorer already shows.

Extend LABELS / heuristics as new public labels appear.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# Exact-address labels. Keyed by lowercased address. Each value:
# (label, category, severity, note). Categories: burn | mixer | bridge |
# exchange | sanctioned | defi | contract. Sourced from public explorer
# labels / OFAC SDN listings.
LABELS: Dict[str, Dict[str, str]] = {
    # --- null / burn (ETH) ---
    "0x0000000000000000000000000000000000000000": {
        "label": "Null address (0x0)", "category": "burn",
        "severity": "low",
        "note": "The zero address - tokens sent here are burned/lost."},
    "0x000000000000000000000000000000000000dead": {
        "label": "Burn address (0x…dEaD)", "category": "burn",
        "severity": "low",
        "note": "Conventional burn address; funds are unrecoverable."},
    "0x00000000219ab540356cbb839cbe05303d7705fa": {
        "label": "ETH2 Beacon Deposit Contract", "category": "defi",
        "severity": "low", "note": "Official ETH2 staking deposit contract."},
    # --- known mixers (public, OFAC-listed) ---
    "0x8589427373d6d84e98730d7795d8f6f8731fda16": {
        "label": "Tornado Cash: Router (OFAC SDN)", "category": "sanctioned",
        "severity": "high",
        "note": "Publicly listed Tornado Cash mixer address (US OFAC SDN). "
                "Interaction carries sanctions/compliance risk."},
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": {
        "label": "Tornado Cash: 10 ETH pool (OFAC SDN)",
        "category": "sanctioned", "severity": "high",
        "note": "OFAC-listed Tornado Cash pool address."},
    "0xa160cdab225685da1d56aa342ad8841c3b53f291": {
        "label": "Tornado Cash: 100 ETH pool (OFAC SDN)",
        "category": "sanctioned", "severity": "high",
        "note": "OFAC-listed Tornado Cash pool address."},
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": {
        "label": "Tornado Cash: Router v2 (OFAC SDN)",
        "category": "sanctioned", "severity": "high",
        "note": "OFAC-listed Tornado Cash router address."},
    # --- bridges ---
    "0x3ee18b2214aff97000d974cf647e7c347e8fa585": {
        "label": "Wormhole Token Bridge", "category": "bridge",
        "severity": "low", "note": "Wormhole cross-chain bridge contract."},
    "0xa0c68c638235ee32657e8f720a23cec1bfc77c77": {
        "label": "Polygon (Matic) PoS Bridge", "category": "bridge",
        "severity": "low", "note": "Polygon PoS bridge deposit contract."},
    # --- major-exchange hot wallets (publicly labeled on Etherscan) ---
    "0x28c6c06298d514db089934071355e5743bf21d60": {
        "label": "Binance 14 (hot wallet)", "category": "exchange",
        "severity": "low", "note": "Publicly labeled Binance hot wallet."},
    "0x21a31ee1afc51d94c2efccaa2092ad1028285549": {
        "label": "Binance 15 (hot wallet)", "category": "exchange",
        "severity": "low", "note": "Publicly labeled Binance hot wallet."},
    "0x71660c4005ba85c37ccec55d0c4493e66fe775d3": {
        "label": "Coinbase 1 (hot wallet)", "category": "exchange",
        "severity": "low", "note": "Publicly labeled Coinbase hot wallet."},
    "0x503828976d22510aad0201ac7ec88293211d23da": {
        "label": "Coinbase 2 (hot wallet)", "category": "exchange",
        "severity": "low", "note": "Publicly labeled Coinbase hot wallet."},
    "0x267be1c1d684f78cb4f6a176c4911b741e4ffdc0": {
        "label": "Kraken 4 (hot wallet)", "category": "exchange",
        "severity": "low", "note": "Publicly labeled Kraken hot wallet."},
    # --- BTC well-known ---
    "1111111111111111111114oldf": {  # not a real burn, placeholder guard
        "label": "", "category": "", "severity": "low", "note": ""},
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh": {
        "label": "Bitcoin: known Satoshi-era / notable address",
        "category": "exchange", "severity": "low",
        "note": "Frequently-referenced public BTC address."},
}
# strip the placeholder guard entry
LABELS = {k: v for k, v in LABELS.items() if v.get("label")}

# Known sanctioned prefixes / fragments (defensive compliance signal).
_SANCTION_HINTS = ("tornado", "blender.io", "sinbad", "chipmixer")

# Mixer/privacy-tool contract name fragments (from verified source names).
_MIXER_NAME_RE = re.compile(r"(tornado|mixer|tumbler|coinjoin|wasabi|"
                            r"samourai|whirlpool)", re.I)

# Bridge contract name fragments.
_BRIDGE_NAME_RE = re.compile(r"(bridge|wormhole|multichain|anyswap|synapse|"
                             r"stargate|hop|celer|across|portal)", re.I)


def _is_burnish(addr: str) -> bool:
    """Structural burn heuristic: an all-ish-zero or 0x…dead address."""
    a = addr.lower()
    if a.startswith("0x"):
        body = a[2:]
        if body == "0" * 40:
            return True
        if body.endswith("dead") and body.count("0") >= 30:
            return True
        # leading-zero vanity (very unlikely to be a live wallet)
        if body.startswith("0" * 12):
            return True
    return False


def labels_for(address: str, chain: str = "",
               contract_name: str = "",
               verified: bool = False) -> List[Dict[str, Any]]:
    """Return everything publicly known about ``address``.

    ``contract_name`` (when the address is a verified contract) lets us
    label mixers/bridges by their source name even when the exact
    address is not in the static table. Never raises.
    """
    try:
        return _labels_for(address, chain, contract_name, verified)
    except Exception:
        return []


def _labels_for(address: str, chain: str, contract_name: str,
                verified: bool) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    a = (address or "").strip()
    la = a.lower()

    # 1. exact match against the curated table
    hit = LABELS.get(la)
    if hit:
        out.append(dict(hit, address=a, source="public label set",
                        match="exact"))

    # 2. structural burn heuristic (if not already labeled)
    if not hit and _is_burnish(a):
        out.append({
            "label": "Likely burn / null address", "category": "burn",
            "severity": "low", "address": a, "match": "heuristic",
            "note": "All-zero or 0x…dead-style address; funds sent here are "
                    "effectively burned.", "source": "structural heuristic"})

    # 3. contract-name based labels (mixer / bridge), when we have a name
    name = (contract_name or "").strip()
    if name:
        if _MIXER_NAME_RE.search(name):
            out.append({
                "label": f"Privacy-mixer contract ({name})",
                "category": "mixer", "severity": "high", "address": a,
                "match": "contract_name",
                "note": "Contract name matches a known privacy-mixer family; "
                        "interaction may carry compliance/sanctions risk.",
                "source": "verified contract name"})
        if _BRIDGE_NAME_RE.search(name):
            out.append({
                "label": f"Cross-chain bridge contract ({name})",
                "category": "bridge", "severity": "low", "address": a,
                "match": "contract_name",
                "note": "Contract name matches a cross-chain bridge; bridges "
                        "are high-value exploit targets.",
                "source": "verified contract name"})
    return out


def summarize_label(labels: List[Dict[str, Any]]) -> Optional[str]:
    """One-line human summary of an address's labels, or None."""
    if not labels:
        return None
    worst = max(labels, key=lambda l: {"high": 3, "medium": 2, "low": 1}
                .get(l.get("severity", "low"), 1))
    cats = sorted({l.get("category", "") for l in labels if l.get("category")})
    return f"{worst.get('label')} [{', '.join(cats)}]"
