"""AML typology exposure detection (read-only, detection only).

Jay's order, 2026-11-01: ReconAnything flags when a scanned target
(a crypto contract, a project site, wallet/infrastructure pages)
shows EXPOSURE TO or INDICATORS OF the eight classic crypto
money-laundering typologies, the way chain-analysis tools score
risk:

1. aml_mixer            - crypto mixers / tumblers (Tornado Cash)
2. aml_xmr_conversion   - Monero conversion points
3. aml_chain_hop        - rapid chain-hopping via bridge routers
4. aml_non_kyc_exchange - no-account / conditional-KYC instant swaps
5. aml_p2p_cash         - peer-to-peer cash-for-crypto trades
6. aml_giftcard_swap    - prepaid gift card <-> crypto swaps
7. aml_mule_network     - money-mule recruitment language
8. aml_shell_account    - verified / corporate exchange accounts
                          offered for sale, nominee bundles

Boundary (hard): DETECTION ONLY. These plugins read the target's
own served text and the target contract's verified source - the
same passive surface as the rest of Recon. They never interact
with a mixer, exchange, swap or P2P service, never transact,
never route funds, never open an account anywhere. A finding is a
risk indicator for a human to review, not proof of laundering.

Severity follows directness: a hardcoded on-chain route (a mixer
or exchange address/domain baked into contract source) scores
HIGH, a service integration in served code scores MEDIUM, and a
bare content mention scores LOW/MEDIUM.

Registry discipline: every address and domain below was verified
from a fetched public source at build time (2026-11-01); the
source is cited next to each registry. Anything that could not be
verified from a fetched source was dropped, never guessed.

- Tornado Cash Ethereum addresses: OFAC's designation notice,
  Federal Register document 2022-17272 (Aug 8, 2022), which lists
  38 ETH addresses for TORNADO CASH (the router and the ETH / DAI /
  cDAI / USDC / USDT / WBTC pools). Note: Tornado Cash was removed
  from the SDN list on 2025-03-21; the addresses are used here as
  MIXER contract identifiers (exposure scoring), not as a claim
  about current sanctions status.
- Tornado Cash side-chain pools (BSC / Polygon / Arbitrum /
  Optimism / Avalanche): the tornadocash-py "Supported
  Deployments" table (github.com/gokgokdak/tornadocash-py,
  fetched 2026-11-01). Its Ethereum rows match the OFAC notice
  address-for-address, which cross-validates the table.
- Bridge routers: the verified bridge set in
  recon-contract-watch/bridges.json - 54 deployments whose
  addresses were each verified from the bridge's own official
  docs / canonical deployment files (Wormhole docs, LayerZero
  Dedaub reference, Across canonical deployments, Synapse Dedaub
  reference, Chainlink CCIP directory, Celer docs, Halborn
  deBridge audit).
- Instant exchanges: each service's own site, cross-checked
  against the Flexe.io no-KYC comparison (checked 2026-10-20).
  Every one of them reserves risk-based KYC, so the registry
  wording is "no-account / conditional-KYC instant swap", never
  an absolute "no KYC" claim.
- P2P platforms: Bisq official docs (docs.bisq.network - P2P, no
  registration or identification, face-to-face cash trades),
  HodlHodl's own site (hodlhodl.com - global P2P, multisig
  escrow, no complex compliance procedures), Paxful's own site
  (paxful.com - wound down in 2025; a live reference to it today
  is itself an anomaly worth flagging).
- Gift cards: Bitrefill's own homepage (bitrefill.com, fetched
  2026-11-01 - 8,000+ gift cards and prepaid cards bought with
  BTC/ETH/USDT and other crypto).
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple

from . import contract_chain as cc
from .base import Cost, Ctx, Finding, Plugin, PluginResult, Target
from .cryptopack_util import collect_texts, xmr_verify

# ------------------------------------------------------------------
# Registry: Tornado Cash mixer contracts
# ------------------------------------------------------------------

_MIXER_SOURCE_OFAC = ("OFAC designation notice for TORNADO CASH, "
                      "Federal Register doc 2022-17272 (2022-08-08)")
_MIXER_SOURCE_SIDECHAIN = ("tornadocash-py Supported Deployments table "
                           "(github.com/gokgokdak/tornadocash-py), "
                           "Ethereum rows cross-match the OFAC notice")

# All 38 ETH addresses from the OFAC notice (router + pools).
_TORNADO_ETHEREUM = (
    "0x8589427373D6D84E98730D7795D8f6f8731FDA16",
    "0x722122dF12D4e14e13Ac3b6895a86e84145b6967",
    "0xDD4c48C0B24039969fC16D1cdF626eaB821d3384",
    "0xd90e2f925DA726b50C4Ed8D0Fb90Ad053324F31b",  # TornadoRouter
    "0xd96f2B1c14Db8458374d9Aca76E26c3D18364307",
    "0x4736dCf1b7A3d580672CcE6E7c65cd5cc9cFBa9D",
    "0xD4B88Df4D29F5CedD6857912842cff3b20C8Cfa3",
    "0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF",  # 10 ETH pool
    "0xA160cdAB225685dA1d56aa342Ad8841c3b53f291",  # 100 ETH pool
    "0xFD8610d20aA15b7B2E3Be39B396a1bC3516c7144",
    "0xF60dD140cFf0706bAE9Cd734Ac3ae76AD9eBC32A",
    "0x22aaA7720ddd5388A3c0A3333430953C68f1849b",
    "0xBA214C1c1928a32Bffe790263E38B4Af9bFCD659",
    "0xb1C8094B234DcE6e03f10a5b673c1d8C69739A00",
    "0x527653eA119F3E6a1F5BD18fbF4714081D7B31ce",
    "0x58E8dCC13BE9780fC42E8723D8EaD4CF46943dF2",
    "0xD691F27f38B395864Ea86CfC7253969B409c362d",
    "0xaEaaC358560e11f52454D997AAFF2c5731B6f8a6",
    "0x1356c899D8C9467C7f71C195612F8A395aBf2f0a",
    "0xA60C772958a3eD56c1F15dD055bA37AC8e523a0D",
    "0x169AD27A470D064DEDE56a2D3ff727986b15D52B",
    "0x0836222F2B2B24A3F36f98668Ed8F0B38D1a872f",
    "0xF67721A2D8F736E75a49FdD7FAd2e31D8676542a",
    "0x9AD122c22B14202B4490eDAf288FDb3C7cb3ff5E",
    "0x905b63Fff465B9fFBF41DeA908CEb12478ec7601",
    "0x07687e702b410Fa43f4cB4Af7FA097918ffD2730",
    "0x94A1B5CdB22c43faab4AbEb5c74999895464Ddaf",
    "0xb541fc07bC7619fD4062A54d96268525cBC6FfEF",
    "0x12D66f87A04A9E220743712cE6d9bB1B5616B8Fc",  # 0.1 ETH pool
    "0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936",  # 1 ETH pool
    "0x23773E65ed146A459791799d01336DB287f25334",
    "0xD21be7248e0197Ee08E0c20D4a96DEBdaC3D20Af",
    "0x610B717796ad172B316836AC95a2ffad065CeaB4",
    "0x178169B423a011fff22B9e3F3abeA13414dDD0F1",
    "0xbB93e510BbCD0B7beb5A853875f9eC60275CF498",
    "0x2717c5e28cf931547B621a5dddb772Ab6A35B701",
    "0x03893a7c7463AE47D46bc7f091665f1893656003",
    "0xCa0840578f57fE71599D29375e16783424023357",
)

# Side-chain pools (Tornado's CREATE2 deployments reuse the same
# addresses across several chains). address -> chains.
_TORNADO_SIDECHAIN = {
    "0x84443CFd09A48AF6eF360C6976C5392aC5023a1F":
        ("bsc", "polygon", "arbitrum", "optimism"),
    "0xd47438C816c9E7f2E2888E060936a499Af9582b3":
        ("bsc", "arbitrum", "optimism"),
    "0x330bdFADE01eE9bF63C209Ee33102DD334618e0a":
        ("bsc", "arbitrum", "optimism", "avalanche"),
    "0x1E34A77868E19A6647b1f2F47B51ed72dEDE95DD":
        ("bsc", "polygon", "arbitrum", "optimism", "avalanche"),
    "0xdf231d99Ff8b6c6CBF4E9B9a945CBAcEF9339178": ("polygon",),
    "0xaf4c0B70B2Ea9FB7487C7CbB37aDa259579fe040": ("polygon",),
    "0xa5C2254e4253490C54cef0a4347fddb8f75A4998": ("polygon",),
    "0xaf8d1839c3c67cf571aa74B5c12398d4901147B3": ("avalanche",),
}


def _build_mixer_registry() -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for addr in _TORNADO_ETHEREUM:
        out[addr.lower()] = {
            "service": "Tornado Cash",
            "chains": ("ethereum",),
            "registry_source": _MIXER_SOURCE_OFAC,
        }
    for addr, chains in _TORNADO_SIDECHAIN.items():
        out[addr.lower()] = {
            "service": "Tornado Cash",
            "chains": chains,
            "registry_source": _MIXER_SOURCE_SIDECHAIN,
        }
    return out


MIXER_CONTRACTS: Dict[str, Dict[str, Any]] = _build_mixer_registry()

# Mixer service domains. tornado.cash is the website named in the
# OFAC notice itself.
MIXER_DOMAINS: Dict[str, Tuple[str, str]] = {
    "tornado.cash": ("Tornado Cash", _MIXER_SOURCE_OFAC),
}

# ------------------------------------------------------------------
# Registry: no-account / conditional-KYC instant swap exchanges
# (domain -> service name). Source: each service's own site,
# cross-checked via the Flexe.io comparison, 2026-10-20. All of
# them reserve risk-based KYC; the finding wording keeps that
# qualifier.
# ------------------------------------------------------------------
INSTANT_EXCHANGES: Dict[str, str] = {
    "sideshift.ai": "SideShift.ai",
    "godex.io": "Godex",
    "stealthex.io": "StealthEX",
    "fixedfloat.com": "FixedFloat",
    "simpleswap.io": "SimpleSwap",
    "exolix.com": "Exolix",
    "changenow.io": "ChangeNOW",
}
_INSTANT_EXCHANGE_SOURCE = ("service's own website, cross-checked "
                            "against the Flexe.io instant-exchange "
                            "comparison (checked 2026-10-20)")

# ------------------------------------------------------------------
# Registry: P2P cash-trade platforms (domain -> (name, source))
# ------------------------------------------------------------------
P2P_PLATFORMS: Dict[str, Tuple[str, str]] = {
    "bisq.network": ("Bisq", "Bisq official docs, docs.bisq.network "
                             "(P2P, no registration/identification, "
                             "face-to-face cash trades)"),
    "hodlhodl.com": ("HodlHodl", "HodlHodl official site, hodlhodl.com "
                                 "(global P2P, multisig escrow, 100+ "
                                 "payment methods)"),
    "paxful.com": ("Paxful", "Paxful official site, paxful.com "
                             "(P2P marketplace; wound down 2025, so a "
                             "live reference is itself anomalous)"),
}

# ------------------------------------------------------------------
# Registry: gift-card <-> crypto swap services (domain -> (name,
# source)). Bitrefill sells gift cards / prepaid cards FOR crypto:
# the off-ramp leg of the gift-card typology.
# ------------------------------------------------------------------
GIFTCARD_SERVICES: Dict[str, Tuple[str, str]] = {
    "bitrefill.com": ("Bitrefill", "Bitrefill official homepage, "
                                   "bitrefill.com (fetched 2026-11-01: "
                                   "8,000+ gift cards and prepaid "
                                   "cards payable in BTC/ETH/USDT)"),
}

# ------------------------------------------------------------------
# Registry: verified bridge routers (address -> (service, chains)).
# From recon-contract-watch/bridges.json: 54 deployments, each
# address verified from the bridge's own official docs or
# canonical deployment files (see module docstring).
# ------------------------------------------------------------------
BRIDGE_ROUTERS: Dict[str, Tuple[str, str]] = {
    "0x98f3c9e6e3face36baad05fe09d375ef1464288b": ("Wormhole Core Bridge", "bsc, ethereum"),
    "0xa5f208e072434bc67592e4c49c1b991ba79bca46": ("Wormhole Core Bridge", "arbitrum"),
    "0x7a4b5a56256163f07b2c80a7ca55abe66c4ec4d7": ("Wormhole Core Bridge", "polygon"),
    "0x3ee18b2214aff97000d974cf647e7c347e8fa585": ("Wormhole Token Bridge", "ethereum"),
    "0xb6f6d86a8f9879a9c87f643768d9efc38c1da6e7": ("Wormhole Token Bridge", "bsc"),
    "0x0b2402144bb366a632d14b83f244d2e0e21bd39c": ("Wormhole Token Bridge", "arbitrum"),
    "0x5a58505a96d1dbf8df91cb21b54419fc36e93fde": ("Wormhole Token Bridge", "polygon"),
    "0x1a44076050125825900e736c501f859c50fe728c": ("LayerZero EndpointV2", "arbitrum, base, bsc, ethereum, optimism, polygon"),
    "0x66a71dcef29a0ffbdbe3c6a460a3b5bc225cd675": ("LayerZero V1 Endpoint", "ethereum"),
    "0x5c7bcd6e7de5423a257d81b442095a1a6ced35c5": ("Across SpokePool", "ethereum"),
    "0xc186fa914353c44b2e33ebe05f21846f1048beda": ("Across HubPool", "ethereum"),
    "0xe35e9842fceaca96570b734083f4a58e8f7c5f2a": ("Across SpokePool", "arbitrum"),
    "0x9295ee1d8c5b022be115a2ad3c30c72e34e7f096": ("Across SpokePool", "polygon"),
    "0x4e8e101924ede233c13e2d8622dc8aed2872d505": ("Across SpokePool", "bsc"),
    "0x2796317b0ff8538f253012862c06787adfb8ceb6": ("Synapse Bridge", "ethereum"),
    "0x6f4e8eba4d337f874ab57478acc2cb5bacdc19c9": ("Synapse Bridge", "arbitrum"),
    "0x8f5bbb2bb8c2ee94639e55d5f41de9b4839c1280": ("Synapse Bridge", "polygon"),
    "0xd123f70ae324d34a9e76b67a27bf77593ba8749f": ("Synapse Bridge", "bsc"),
    "0x7e7a0e201fd38d3adaa9523da6c109a07118c96a": ("Synapse Router", "base, ethereum, optimism"),
    "0x5523d3c98809dddb82c686e152f5c58b1b0fb59e": ("Synapse FastBridge (RFQ)", "ethereum"),
    "0x8731d54e9d02c286767d56ac03e8037c07e01e98": ("Stargate Router", "ethereum"),
    "0x53bf833a5d6c4dda888f69c22c88c9f356a41614": ("Stargate Router", "arbitrum"),
    "0x80226fc0ee2b096224eeac085bb9a8cba1146f7d": ("Chainlink CCIP Router", "ethereum"),
    "0x34b03cb9086d7d758ac55af71584f81a598759fe": ("Chainlink CCIP Router", "bsc"),
    "0x849c5ed5a80f5b408dd4969b78c2c8fdf0565bfe": ("Chainlink CCIP Router", "polygon"),
    "0x141fa059441e0ca23ce184b6a78bafd2a517dde8": ("Chainlink CCIP Router", "arbitrum"),
    "0x5427fefa711eff984124bfbb1ab6fbf5e3da1820": ("Celer cBridge", "ethereum"),
    "0xdd90e5e87a2081dcf0391920868ebc2ffb81a1af": ("Celer cBridge", "bsc"),
    "0x88dcdc47d2f83a99cf0000fdf667a468bb958a78": ("Celer cBridge", "polygon"),
    "0x1619de6b6b20ed217a58d00f37b9d47c7663feca": ("Celer cBridge", "arbitrum"),
    "0xef4fb24ad0916217251f553c0596f8edc630eb66": ("deBridge DLN Source", "arbitrum, base, optimism"),
    "0x51bfd427d06b2a5fc3588f9d023994a9f70e0ce0": ("deBridge Gate", "arbitrum"),
    "0xbebdb6c8ddc678ffa9f8748f85c815c556dd8ac6": ("Wormhole Core Bridge", "base"),
    "0xee91c335eab126df5fdb3797ea9d6ad93aec9722": ("Wormhole Core Bridge", "optimism"),
    "0x8d2de8d2f73f1f4cab472ac9a881c9b123c79627": ("Wormhole Token Bridge", "base"),
    "0x1d68124e65fafc907325e3edbf8c4d84499daa8b": ("Wormhole Token Bridge", "optimism"),
    "0x09aea4b2242abc8bb4bb78d537a67a245a7bec64": ("Across SpokePool", "base"),
    "0x6f26bf09b1c792e3228e5467807a900a503c0281": ("Across SpokePool", "optimism"),
    "0xf07d1c752fab503e47fef309bf14fbdd3e867089": ("Synapse Bridge", "base"),
    "0xaf41a65f786339e7911f4acdad6bd49426f2dc6b": ("Synapse Bridge", "optimism"),
    "0x881e3a65b4d4a04dd529061dd0071cf975f58bcd": ("Chainlink CCIP Router", "base"),
    "0x3206695cae29952f4b0c22a169725a865bc8ce0f": ("Chainlink CCIP Router", "optimism"),
    "0x7d43aabc515c356145049227cee54b608342c0ad": ("Celer cBridge", "base"),
    "0x9d39fc627a6d9d9f8c831c16995b209548cc3401": ("Celer cBridge", "optimism"),
}
_BRIDGE_SOURCE = ("recon-contract-watch/bridges.json - each address "
                  "verified from the bridge's official docs / "
                  "canonical deployment files")

# ------------------------------------------------------------------
# Pure helpers (unit-tested without any network)
# ------------------------------------------------------------------

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_XMR_STD_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
_XMR_INT_RE = re.compile(r"\b8[1-9A-HJ-NP-Za-km-z]{105}\b")
_CRYPTO_CONTEXT_RE = re.compile(
    r"\b(bitcoin|btc|ethereum|eth|crypto|usdt|usdc|xmr|monero|"
    r"solana|sol|bnb|litecoin|ltc)\b", re.I)
MAX_CONTRACTS = 3


def _snippet(text: str, start: int, end: int, radius: int = 110) -> str:
    """Whitespace-collapsed excerpt of text around [start, end)."""
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    out = re.sub(r"\s+", " ", text[lo:hi]).strip()
    if lo > 0:
        out = "..." + out
    if hi < len(text):
        out += "..."
    return out[:340]


def _domain_hits(text: str, domain: str) -> List[Tuple[int, int]]:
    """Spans where `domain` appears as a host (subdomains allowed)."""
    pat = re.compile(r"(?<![\w.-])(?:[a-z0-9-]+\.)*" +
                     re.escape(domain) + r"(?![\w.-])", re.I)
    return [(m.start(), m.end()) for m in pat.finditer(text)]


def _evm_addresses(text: str) -> List[str]:
    return [m.group(0) for m in _ADDRESS_RE.finditer(text)]


def find_xmr_addresses(text: str) -> List[str]:
    """Checksum-valid Monero addresses in text.

    Shape alone produces false positives, so every candidate is
    verified with the real Monero base58 checksum (Keccak) before
    it counts: standard addresses (prefix 0x12) and integrated
    addresses with an embedded payment id (prefix 0x13).
    """
    out: List[str] = []
    seen = set()
    for m in _XMR_STD_RE.finditer(text):
        s = m.group(0)
        if s not in seen and xmr_verify(s, (0x12,)):
            seen.add(s)
            out.append(s)
    for m in _XMR_INT_RE.finditer(text):
        s = m.group(0)
        if s not in seen and xmr_verify(s, (0x13,)):
            seen.add(s)
            out.append(s)
    return out


# ------------------------------------------------------------------
# Document gathering (shared by all 8 plugins via the run bus, so
# the pages and contract sources are fetched once per scan)
# ------------------------------------------------------------------

def _collect_addresses(target: Target,
                       ctx: Ctx) -> List[Tuple[Optional[str], str]]:
    """Contract addresses to pull source for (target + bus)."""
    out: List[Tuple[Optional[str], str]] = []
    seen = set()

    def add(chain_hint: Optional[str], addr: str) -> None:
        addr = (addr or "").strip()
        if not cc.ADDRESS_RE.match(addr):
            return
        if addr.lower() == cc.ZERO_ADDRESS:
            return
        k = addr.lower()
        if k in seen:
            return
        seen.add(k)
        out.append((chain_hint, addr))

    for raw in (target.normalized, target.raw):
        chain_hint, addr = cc.parse_target_address(raw or "")
        if addr:
            add(chain_hint, addr)
            break
    for kind in ("contract_addresses", "crypto_addresses"):
        for item in ctx.consume(kind):
            a = item if isinstance(item, str) else \
                str(item.get("address", ""))
            add(None, a)
    for item in ctx.consume("chain_contracts"):
        if isinstance(item, dict):
            hint = item.get("chain")
            add(hint if isinstance(hint, str) and hint in cc.CHAINS
                else None, str(item.get("address", "")))
    return out


async def _contract_docs(ctx: Ctx, target: Target) -> List[Dict[str, Any]]:
    """Verified-source documents for the target's contracts.

    Read-only explorer lookups (the same routes contract_recon
    uses). Any failure degrades to no document, never an error.
    """
    docs: List[Dict[str, Any]] = []
    for chain_hint, addr in _collect_addresses(target, ctx)[:MAX_CONTRACTS]:
        chain_ids = [chain_hint] if chain_hint else \
            list(cc.DEFAULT_CHAIN_ORDER)
        for cid in chain_ids:
            chain = cc.CHAINS[cid]
            try:
                code = await cc.rpc_get_code(ctx, chain, addr)
            except Exception:
                code = None
            if not code:
                continue
            try:
                info = await cc.fetch_verified_source(ctx, chain, addr)
            except Exception:
                info = None
            if info and info.get("source"):
                docs.append({
                    "kind": "contract",
                    "where": f"verified source of contract {addr} "
                             f"on {cid}",
                    "text": str(info["source"]),
                    "url": None,
                    "address": addr,
                    "chain": cid,
                })
            break  # contract lives on this chain; stop probing
    return docs


async def _gather_docs(ctx: Ctx, target: Target) -> List[Dict[str, Any]]:
    """All documents the AML detectors read, gathered once per run.

    Two surfaces: the target's served text (homepage + same-domain
    JS, via the shared fetch_page cache) and the verified source
    of the target's contracts. Cached on the run bus so the eight
    AML plugins together pay for the fetches once.
    """
    cached = ctx.shared.get("_aml_docs")
    if cached is not None:
        return cached
    docs: List[Dict[str, Any]] = []
    try:
        for where, text, url in await collect_texts(ctx, target):
            docs.append({"kind": "web", "where": where, "text": text,
                         "url": url})
    except Exception:
        pass
    try:
        docs.extend(await _contract_docs(ctx, target))
    except Exception:
        pass
    ctx.shared["_aml_docs"] = docs
    return docs


# ------------------------------------------------------------------
# Shared plugin base
# ------------------------------------------------------------------

class _AmlPlugin(Plugin):
    """Base for the AML typology detectors (not itself registered)."""

    id = ""
    accepts = ["crypto_wallet", "domain", "url"]
    passive = True
    cost = Cost.FREEMIUM
    group = "web3"
    phase = 2  # consumes addresses discovered by phase-1 miners
    timeout_s = 120
    tag = ""

    async def run(self, target: Target, ctx: Ctx) -> PluginResult:
        t0 = time.monotonic()
        docs = await _gather_docs(ctx, target)
        findings = self.detect(docs, target)
        res = self._ok(findings, f"{len(findings)} {self.tag} "
                                 f"indicator(s) across {len(docs)} "
                                 f"document(s)")
        res.duration_ms = int((time.monotonic() - t0) * 1000)
        return res

    def detect(self, docs: List[Dict[str, Any]],
               target: Target) -> List[Finding]:
        return []

    def _mk(self, doc: Dict[str, Any], severity: str, value: str,
            evidence: Dict[str, Any],
            confidence: int = 80) -> Finding:
        ev: Dict[str, Any] = {
            "severity": severity,
            "typology": self.tag,
            "where": doc.get("where", ""),
        }
        ev.update(evidence)
        return self._f("web3", self.tag, value,
                       source=f"aml typologies ({doc.get('where', '')})",
                       source_url=doc.get("url"),
                       confidence=confidence, evidence=ev)

_MIXER_NAME_RE = re.compile(r"tornado\s*cash", re.I)
_MIXER_VERB_RE = re.compile(
    r"\b(deposit|withdraw|mix|route|send)\b", re.I)
_SWAP_LANG_RE = re.compile(r"\b(swap|exchange|convert|trade)\b", re.I)
_MONERO_WORD_RE = re.compile(r"\b(monero|xmr)\b", re.I)


class AmlMixerPlugin(_AmlPlugin):
    id = "aml_mixer"
    label = "AML: Mixer / Tumbler Exposure"
    tag = "aml_mixer"
    description = ("Flags exposure to known crypto mixers: the scan "
                   "target IS a Tornado Cash mixer contract, its "
                   "verified source hardcodes a mixer pool/router "
                   "address, or its pages reference the mixer "
                   "service. Detection only - the mixer is never "
                   "contacted.")

    def detect(self, docs: List[Dict[str, Any]],
               target: Target) -> List[Finding]:
        findings: List[Finding] = []
        seen = set()

        def add(doc, severity, addr, entry, span):
            key = (addr.lower(), doc.get("where"), severity)
            if key in seen:
                return
            seen.add(key)
            text = doc.get("text", "")
            findings.append(self._mk(doc, severity, (
                f"{severity.upper()}: {entry['service']} mixer "
                f"contract {addr} "
                f"({'/'.join(entry['chains'])}) - "
                + ("the scan target itself is this mixer contract."
                   if doc.get("self") else
                   "a hardcoded mixer route in the scanned "
                   "material is a direct laundering-path exposure.")),
                {"matched_address": addr,
                 "service": entry["service"],
                 "chains": list(entry["chains"]),
                 "registry_source": entry["registry_source"],
                 "snippet": _snippet(text, span[0], span[1])
                 if span else addr,
                 "remediation": "Remove the mixer route/reference. "
                                "If it is intentional, document the "
                                "compliance rationale - mixer "
                                "exposure is a top-tier AML risk "
                                "signal for exchanges and partners."},
                confidence=95))

        # The target itself is a known mixer contract.
        _hint, taddr = cc.parse_target_address(target.normalized or "")
        if taddr and taddr.lower() in MIXER_CONTRACTS:
            add({"kind": "contract", "where": "scan target itself",
                 "text": "", "url": None, "self": True},
                "high", taddr, MIXER_CONTRACTS[taddr.lower()], None)

        for doc in docs:
            text = doc.get("text", "")
            if not text:
                continue
            in_contract = doc.get("kind") == "contract"
            for m in _ADDRESS_RE.finditer(text):
                addr = m.group(0)
                entry = MIXER_CONTRACTS.get(addr.lower())
                if entry:
                    add(doc, "high" if in_contract else "medium",
                        addr, entry, (m.start(), m.end()))
            if in_contract:
                continue
            for domain, (service, src) in MIXER_DOMAINS.items():
                for start, end in _domain_hits(text, domain):
                    key = (domain, doc.get("where"))
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(self._mk(doc, "medium", (
                        f"MEDIUM: page references mixer service "
                        f"{service} ({domain}) - a mixer integration "
                        f"or referral on the target's own surface."),
                        {"matched_domain": domain, "service": service,
                         "registry_source": src,
                         "snippet": _snippet(text, start, end),
                         "remediation": "Remove the mixer reference "
                                        "unless there is a documented "
                                        "compliance rationale."},
                        confidence=85))
            for m in _MIXER_NAME_RE.finditer(text):
                window = text[max(0, m.start() - 90):m.end() + 90]
                if not _MIXER_VERB_RE.search(window):
                    continue
                key = ("tornado-name", doc.get("where"))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._mk(doc, "medium", (
                    "MEDIUM: page text directs users to the Tornado "
                    "Cash mixer (name + deposit/withdraw/mix "
                    "language) - a mixer-service reference."),
                    {"matched_text": _snippet(text, m.start(), m.end()),
                     "service": "Tornado Cash",
                     "registry_source": _MIXER_SOURCE_OFAC,
                     "remediation": "Remove the mixer direction "
                                    "unless there is a documented "
                                    "compliance rationale."},
                    confidence=75))
        return findings


class AmlXmrConversionPlugin(_AmlPlugin):
    id = "aml_xmr_conversion"
    label = "AML: Monero Conversion Points"
    tag = "aml_xmr_conversion"
    description = ("Flags Monero conversion points on the target: "
                   "checksum-valid XMR addresses in code or content, "
                   "and instant-swap integrations advertising Monero. "
                   "This flags the conversion POINT only - Monero "
                   "transfers themselves are opaque by design, so "
                   "nothing past the point can be scored from public "
                   "data.")

    _LIMIT = ("Limit: this flags the conversion point only. Monero "
              "is opaque by design (ring signatures, stealth "
              "addresses), so where funds go after conversion cannot "
              "be scored from public data.")

    def detect(self, docs: List[Dict[str, Any]],
               target: Target) -> List[Finding]:
        findings: List[Finding] = []
        seen = set()
        for doc in docs:
            text = doc.get("text", "")
            if not text:
                continue
            in_contract = doc.get("kind") == "contract"
            swap_ctx = bool(_SWAP_LANG_RE.search(text))
            for addr in find_xmr_addresses(text):
                key = (addr, doc.get("where"))
                if key in seen:
                    continue
                seen.add(key)
                idx = text.find(addr)
                severity = "high" if in_contract else "medium"
                findings.append(self._mk(doc, severity, (
                    f"{severity.upper()}: Monero (XMR) address "
                    f"{addr} in "
                    f"{'contract source - a hardcoded conversion '
                     'point baked into the contract'
                     if in_contract else 'target content'}"
                    + (" alongside swap/exchange language."
                       if swap_ctx else ".")
                    + " " + self._LIMIT),
                    {"matched_address": addr, "asset": "XMR",
                     "swap_language_present": swap_ctx,
                     "snippet": _snippet(text, idx, idx + len(addr)),
                     "remediation": "Identify why a Monero "
                                    "conversion point is present. "
                                    "XMR legs cannot be traced "
                                    "on-chain, so counterparties "
                                    "treat them as a break in the "
                                    "audit trail."},
                    confidence=95))
            if _MONERO_WORD_RE.search(text):
                for domain, name in INSTANT_EXCHANGES.items():
                    hits = _domain_hits(text, domain)
                    if not hits:
                        continue
                    key = (domain, doc.get("where"))
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(self._mk(doc, "medium", (
                        f"MEDIUM: instant-swap service {name} "
                        f"({domain}) referenced together with "
                        f"Monero - an XMR conversion route via a "
                        f"no-account swap. " + self._LIMIT),
                        {"matched_domain": domain, "service": name,
                         "registry_source": _INSTANT_EXCHANGE_SOURCE,
                         "snippet": _snippet(text, hits[0][0],
                                             hits[0][1]),
                         "remediation": "Review the swap "
                                        "integration: a Monero leg "
                                        "breaks the on-chain audit "
                                        "trail."},
                        confidence=80))
        return findings


_FLOW_RE = re.compile(
    r"\b(bridge|deposit|withdraw|swap|cross[\s-]?chain)", re.I)
_NOACCT_SWAP_RE = re.compile(
    r"(instant|immediate|lightning|fast)[^.\n]{0,90}"
    r"(cross[\s-]?chain|bridge|swap)[^.\n]{0,90}"
    r"(no[\s-]?(account|kyc|registration|sign[\s-]?up)|"
    r"without\s+(an?\s+)?(account|registration|kyc))",
    re.I)
_NOACCT_SWAP_RE2 = re.compile(
    r"(no[\s-]?(account|kyc|registration|sign[\s-]?up)|"
    r"without\s+(an?\s+)?(account|registration|kyc))"
    r"[^.\n]{0,90}(cross[\s-]?chain|bridge|swap)", re.I)


class AmlChainHopPlugin(_AmlPlugin):
    id = "aml_chain_hop"
    label = "AML: Chain-Hopping Indicators"
    tag = "aml_chain_hop"
    description = ("Flags rapid cross-chain movement setups: one "
                   "document embedding two or more verified bridge "
                   "router addresses inside a deposit/withdrawal "
                   "flow (multi-bridge routing is the chain-hopping "
                   "pattern), and content advertising instant "
                   "cross-chain swaps with no account.")

    def detect(self, docs: List[Dict[str, Any]],
               target: Target) -> List[Finding]:
        findings: List[Finding] = []
        for doc in docs:
            text = doc.get("text", "")
            if not text:
                continue
            hits: Dict[str, Tuple[str, str]] = {}
            first_span: Optional[Tuple[int, int]] = None
            for m in _ADDRESS_RE.finditer(text):
                entry = BRIDGE_ROUTERS.get(m.group(0).lower())
                if entry:
                    hits[m.group(0).lower()] = entry
                    if first_span is None:
                        first_span = (m.start(), m.end())
            if len(hits) >= 2 and _FLOW_RE.search(text):
                detail = "; ".join(
                    f"{addr} ({svc}, {chains})"
                    for addr, (svc, chains) in sorted(hits.items()))
                doc_kind = "contract" if doc.get("kind") == \
                    "contract" else "page"
                findings.append(self._mk(doc, "medium", (
                    f"MEDIUM: {len(hits)} verified bridge routers "
                    f"embedded in one {doc_kind} with "
                    f"deposit/withdrawal flow language - the "
                    f"multi-bridge routing shape used for "
                    f"chain-hopping (moving value across chains "
                    f"to break the trail): {detail}"),
                    {"matched_addresses": sorted(hits),
                     "services": sorted({s for s, _ in
                                         hits.values()}),
                     "registry_source": _BRIDGE_SOURCE,
                     "snippet": _snippet(text, first_span[0],
                                         first_span[1])
                     if first_span else "",
                     "remediation": "Confirm the multi-bridge flow "
                                    "has a legitimate purpose and "
                                    "that counterparties across the "
                                    "hops are identified; unhosted "
                                    "multi-hop routing is a scored "
                                    "laundering typology."},
                    confidence=80))
            for pat in (_NOACCT_SWAP_RE, _NOACCT_SWAP_RE2):
                m = pat.search(text)
                if m:
                    findings.append(self._mk(doc, "medium", (
                        "MEDIUM: content advertises instant "
                        "cross-chain swaps with no account / no "
                        "registration - a chain-hopping route "
                        "pitched on anonymity."),
                        {"matched_text": _snippet(text, m.start(),
                                                  m.end()),
                         "remediation": "Review the advertised "
                                        "route: no-account "
                                        "cross-chain swaps are a "
                                        "scored laundering "
                                        "typology."},
                        confidence=75))
                    break
        return findings


class AmlNonKycExchangePlugin(_AmlPlugin):
    id = "aml_non_kyc_exchange"
    label = "AML: No-Account Instant Exchange Exposure"
    tag = "aml_non_kyc_exchange"
    description = ("Flags integrations with known no-account / "
                   "conditional-KYC instant swap exchanges "
                   "(SideShift, Godex, StealthEX, FixedFloat, "
                   "SimpleSwap, Exolix, ChangeNOW): referral links, "
                   "API endpoints or widgets in served content "
                   "(MEDIUM), or the service baked into contract "
                   "source (HIGH).")

    def detect(self, docs: List[Dict[str, Any]],
               target: Target) -> List[Finding]:
        findings: List[Finding] = []
        seen = set()
        for doc in docs:
            text = doc.get("text", "")
            if not text:
                continue
            in_contract = doc.get("kind") == "contract"
            for domain, name in INSTANT_EXCHANGES.items():
                hits = _domain_hits(text, domain)
                if not hits:
                    continue
                key = (domain, doc.get("where"))
                if key in seen:
                    continue
                seen.add(key)
                severity = "high" if in_contract else "medium"
                findings.append(self._mk(doc, severity, (
                    f"{severity.upper()}: no-account instant swap "
                    f"exchange {name} ({domain}) "
                    f"{'hardcoded in contract source - deposits '
                     'routed to a conditional-KYC swapper by the '
                     'contract itself'
                     if in_contract else
                     'referenced in target content (referral link, '
                     'API endpoint or widget)'}"
                    f". These services swap without an account and "
                    f"apply KYC only on risk triggers."),
                    {"matched_domain": domain, "service": name,
                     "registry_source": _INSTANT_EXCHANGE_SOURCE,
                     "snippet": _snippet(text, hits[0][0],
                                         hits[0][1]),
                     "remediation": "Review the integration: swaps "
                                    "through no-account exchanges "
                                    "weaken the audit trail and are "
                                    "scored as an AML typology "
                                    "exposure."},
                    confidence=90 if in_contract else 85))
        return findings

_CASH_TRADE_PATTERNS = (
    ("cash in person", re.compile(r"cash\s+in\s+person", re.I)),
    ("cash by mail", re.compile(r"cash\s+by\s+mail", re.I)),
    ("meet in person", re.compile(
        r"meet\s+(in\s+person|face[\s-]?to[\s-]?face)", re.I)),
    ("face-to-face cash trade", re.compile(
        r"face[\s-]?to[\s-]?face\s+(cash\s+)?(trade|deal|exchange)",
        re.I)),
    ("cash deposit", re.compile(
        r"cash\s+deposit(s|ing)?\s+(at|to)\s+(a\s+)?(bank|atm)",
        re.I)),
)
_CASH_WORD_RE = re.compile(r"\bcash\b", re.I)


class AmlP2pCashPlugin(_AmlPlugin):
    id = "aml_p2p_cash"
    label = "AML: P2P Cash Trade Indicators"
    tag = "aml_p2p_cash"
    description = ("Flags peer-to-peer cash-for-crypto routes: "
                   "references to P2P platforms built around "
                   "no-identification cash trades (Bisq, HodlHodl, "
                   "Paxful) and cash-meetup language ('cash in "
                   "person', 'cash by mail') alongside crypto "
                   "context.")

    def detect(self, docs: List[Dict[str, Any]],
               target: Target) -> List[Finding]:
        findings: List[Finding] = []
        seen = set()
        for doc in docs:
            if doc.get("kind") == "contract":
                continue
            text = doc.get("text", "")
            if not text:
                continue
            has_cash = bool(_CASH_WORD_RE.search(text))
            for domain, (name, src) in P2P_PLATFORMS.items():
                hits = _domain_hits(text, domain)
                if not hits:
                    continue
                key = (domain, doc.get("where"))
                if key in seen:
                    continue
                seen.add(key)
                severity = "medium" if has_cash else "low"
                findings.append(self._mk(doc, severity, (
                    f"{severity.upper()}: P2P cash-trade platform "
                    f"{name} ({domain}) referenced in target "
                    f"content - a peer-to-peer route where crypto "
                    f"changes hands for physical cash outside "
                    f"regulated exchanges."),
                    {"matched_domain": domain, "service": name,
                     "registry_source": src,
                     "cash_language_present": has_cash,
                     "snippet": _snippet(text, hits[0][0],
                                         hits[0][1]),
                     "remediation": "Review why a P2P cash route "
                                    "is promoted: cash trades leave "
                                    "no regulated audit trail."},
                    confidence=80))
            if not _CRYPTO_CONTEXT_RE.search(text):
                continue
            for label, pat in _CASH_TRADE_PATTERNS:
                m = pat.search(text)
                if not m:
                    continue
                key = (label, doc.get("where"))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._mk(doc, "medium", (
                    f"MEDIUM: '{label}' cash-trade language on a "
                    f"crypto page - advertising in-person / mailed "
                    f"cash-for-crypto trades, the P2P cash "
                    f"typology."),
                    {"matched_text": _snippet(text, m.start(),
                                              m.end()),
                     "pattern": label,
                     "remediation": "Review the offer: cash-for-"
                                    "crypto trades bypass regulated "
                                    "on/off-ramps and their record "
                                    "keeping."},
                    confidence=75))
        return findings


_GIFTCARD_PATTERNS = (
    ("sell gift cards for crypto", re.compile(
        r"sell\s+(your\s+)?gift\s+cards?\s+for\s+"
        r"(btc|bitcoin|crypto|usdt|ethereum)", re.I)),
    ("buy crypto with gift cards", re.compile(
        r"(buy|purchase|get)\s+(btc|bitcoin|crypto|usdt)\s+with\s+"
        r"(a\s+)?gift\s+cards?", re.I)),
    ("gift cards for crypto", re.compile(
        r"gift\s+cards?\s+for\s+(btc|bitcoin|crypto)\b", re.I)),
    ("trade gift cards for crypto", re.compile(
        r"trade\s+(your\s+)?gift\s+cards?\s+for\s+crypto", re.I)),
    ("gift cards accepted as payment", re.compile(
        r"accept(s|ing)?\s+gift\s+cards?\s+as\s+payment", re.I)),
)


class AmlGiftcardSwapPlugin(_AmlPlugin):
    id = "aml_giftcard_swap"
    label = "AML: Gift Card Swap Indicators"
    tag = "aml_giftcard_swap"
    description = ("Flags the prepaid gift card typology: content "
                   "offering to swap gift cards for crypto (the "
                   "classic route for turning stolen or fraud-bought "
                   "gift cards into clean funds) and references to "
                   "gift-card-for-crypto services such as Bitrefill.")

    def detect(self, docs: List[Dict[str, Any]],
               target: Target) -> List[Finding]:
        findings: List[Finding] = []
        seen = set()
        for doc in docs:
            if doc.get("kind") == "contract":
                continue
            text = doc.get("text", "")
            if not text:
                continue
            for domain, (name, src) in GIFTCARD_SERVICES.items():
                hits = _domain_hits(text, domain)
                if not hits:
                    continue
                key = (domain, doc.get("where"))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._mk(doc, "low", (
                    f"LOW: gift-card-for-crypto service {name} "
                    f"({domain}) referenced in target content - "
                    f"crypto converted into prepaid instruments is "
                    f"one leg of the gift-card laundering "
                    f"typology (a bare reference is weak evidence "
                    f"on its own)."),
                    {"matched_domain": domain, "service": name,
                     "registry_source": src,
                     "snippet": _snippet(text, hits[0][0],
                                         hits[0][1]),
                     "remediation": "Note the reference; escalate "
                                    "only with corroborating "
                                    "indicators (bulk card resale, "
                                    "discounted card offers)."},
                    confidence=65))
            accepted_spans: List[Tuple[int, int]] = []
            for label, pat in _GIFTCARD_PATTERNS:
                m = pat.search(text)
                if not m:
                    continue
                if label == "gift cards accepted as payment" and \
                        not _CRYPTO_CONTEXT_RE.search(text):
                    continue
                if any(m.start() < e and s < m.end()
                       for s, e in accepted_spans):
                    continue  # same offer already reported
                key = (label, doc.get("where"))
                if key in seen:
                    continue
                seen.add(key)
                accepted_spans.append((m.start(), m.end()))
                findings.append(self._mk(doc, "medium", (
                    f"MEDIUM: '{label}' offer in target content - "
                    f"swapping prepaid gift cards into crypto is a "
                    f"documented laundering route for stolen and "
                    f"fraud-obtained cards."),
                    {"matched_text": _snippet(text, m.start(),
                                              m.end()),
                     "pattern": label,
                     "remediation": "Review the offer: gift-card-"
                                    "to-crypto swaps need card "
                                    "provenance checks to avoid "
                                    "handling stolen value."},
                    confidence=75))
        return findings


_MULE_MOVE = (
    re.compile(r"receive\s+(transfers?|payments?|funds|money)\s+"
               r"and\s+(forward|send|transfer|pass)", re.I),
    re.compile(r"forward\s+(the\s+)?(funds|money|payments?|"
               r"transfers?)\s+to", re.I),
    re.compile(r"process(ing)?\s+payments?\s+(from\s+home|online|"
               r"remotely)", re.I),
    re.compile(r"(transfer|send|move)\s+(the\s+)?(funds|money)\s+"
               r"to\s+(our\s+)?(partners|clients|suppliers|"
               r"accounts)", re.I),
)
_MULE_COMMISSION = (
    re.compile(r"keep\s+(\d{1,2}\s?%|a\s+(percentage|commission|"
               r"cut|share))", re.I),
    re.compile(r"(earn|get|receive)\s+(a\s+)?\d{1,2}\s?%\s*"
               r"(commission|cut)?", re.I),
    re.compile(r"commission\s+of\s+\d{1,2}\s?%", re.I),
    re.compile(r"your\s+(commission|share|cut)\s+is\s+\d", re.I),
)
_MULE_RECRUIT = (
    re.compile(r"work\s+from\s+home", re.I),
    re.compile(r"payment\s+processing\s+agent", re.I),
    re.compile(r"financial\s+(processing\s+)?agent", re.I),
    re.compile(r"no\s+experience\s+(needed|required|necessary)",
               re.I),
    re.compile(r"we\s+are\s+hiring", re.I),
    re.compile(r"hiring\s+(payment\s+)?agents?", re.I),
)


def _first_match(patterns, text):
    for pat in patterns:
        m = pat.search(text)
        if m:
            return m
    return None


class AmlMuleNetworkPlugin(_AmlPlugin):
    id = "aml_mule_network"
    label = "AML: Money Mule Recruitment Indicators"
    tag = "aml_mule_network"
    description = ("Candidate-style detector for money-mule "
                   "recruitment: a page only flags when THREE "
                   "signal families co-occur - money movement "
                   "(receive and forward funds), a commission for "
                   "the middleman, and recruitment framing (work "
                   "from home, payment processing agent, no "
                   "experience needed). Ordinary job postings, "
                   "which never combine all three, stay silent. "
                   "Human review required.")

    def detect(self, docs: List[Dict[str, Any]],
               target: Target) -> List[Finding]:
        findings: List[Finding] = []
        for doc in docs:
            if doc.get("kind") == "contract":
                continue
            text = doc.get("text", "")
            if not text:
                continue
            move = _first_match(_MULE_MOVE, text)
            comm = _first_match(_MULE_COMMISSION, text)
            recr = _first_match(_MULE_RECRUIT, text)
            if not (move and comm and recr):
                continue
            findings.append(self._mk(doc, "medium", (
                "MEDIUM (candidate, human review): page combines "
                "money-movement instructions, a middleman "
                "commission, and recruitment framing - the "
                "money-mule recruitment pattern. Matched: "
                f"movement '{move.group(0)}', commission "
                f"'{comm.group(0)}', recruitment "
                f"'{recr.group(0)}'."),
                {"matched_text": _snippet(text, move.start(),
                                          move.end()),
                 "signals": {
                     "money_movement": move.group(0),
                     "commission": comm.group(0),
                     "recruitment": recr.group(0)},
                 "candidate": True,
                 "remediation": "Review manually: legitimate "
                                "employers do not pay staff to "
                                "receive and forward third-party "
                                "funds through personal accounts "
                                "for a percentage."},
                confidence=70))
        return findings


_SHELL_SALE = (
    ("verified accounts for sale", re.compile(
        r"verified\s+(exchange\s+|crypto\s+)?accounts?\s+for\s+"
        r"sale", re.I)),
    ("verified exchange account sale", re.compile(
        r"(buy|sell|selling)\s+verified\s+(binance|coinbase|"
        r"kraken|bybit|okx|kucoin|bitstamp|exchange|crypto)\s+"
        r"accounts?", re.I)),
    ("aged corporate accounts for sale", re.compile(
        r"aged\s+(corporate\s+)?accounts?\s+for\s+sale", re.I)),
    ("named exchange accounts for sale", re.compile(
        r"(binance|coinbase|kraken|bybit|okx|kucoin)\s+accounts?"
        r"\s+for\s+sale", re.I)),
)
_SHELL_NOMINEE_RE = re.compile(r"\bnominee\b", re.I)
_SHELL_ACCOUNT_RE = re.compile(
    r"(exchange|crypto|bank)\s+accounts?", re.I)
_SHELL_FORMATION_RE = re.compile(
    r"(company\s+formation|incorporation|offshore\s+company|"
    r"shell\s+company|aged\s+corporations?)", re.I)


class AmlShellAccountPlugin(_AmlPlugin):
    id = "aml_shell_account"
    label = "AML: Shell / Verified Account Resale Indicators"
    tag = "aml_shell_account"
    description = ("Flags the shell-company exchange-account "
                   "typology: offers to sell verified or aged "
                   "corporate exchange accounts (HIGH - a KYC "
                   "identity for hire), and company-formation "
                   "packages bundled with nominee directors and "
                   "exchange/crypto accounts (MEDIUM).")

    def detect(self, docs: List[Dict[str, Any]],
               target: Target) -> List[Finding]:
        findings: List[Finding] = []
        seen = set()
        for doc in docs:
            if doc.get("kind") == "contract":
                continue
            text = doc.get("text", "")
            if not text:
                continue
            accepted_spans: List[Tuple[int, int]] = []
            for label, pat in _SHELL_SALE:
                m = pat.search(text)
                if not m:
                    continue
                if any(m.start() < e and s < m.end()
                       for s, e in accepted_spans):
                    continue  # same offer already reported
                key = (label, doc.get("where"))
                if key in seen:
                    continue
                seen.add(key)
                accepted_spans.append((m.start(), m.end()))
                findings.append(self._mk(doc, "high", (
                    f"HIGH: '{label}' offer in target content - "
                    f"reselling verified exchange accounts hands a "
                    f"clean KYC identity to whoever pays, the "
                    f"shell-account laundering typology."),
                    {"matched_text": _snippet(text, m.start(),
                                              m.end()),
                     "pattern": label,
                     "remediation": "Treat as a high-risk service: "
                                    "verified-account resale exists "
                                    "to defeat exchange KYC. Do not "
                                    "integrate or refer users."},
                    confidence=85))
            nom = _SHELL_NOMINEE_RE.search(text)
            acct = _SHELL_ACCOUNT_RE.search(text)
            form = _SHELL_FORMATION_RE.search(text)
            if nom and acct:
                key = ("nominee-bundle", doc.get("where"))
                if key not in seen:
                    seen.add(key)
                    findings.append(self._mk(doc, "medium", (
                        "MEDIUM: page pairs nominee arrangements "
                        "with exchange/crypto accounts - the "
                        "nominee-company + account bundle used to "
                        "open accounts under a front identity."),
                        {"matched_text": _snippet(
                            text, nom.start(), nom.end()),
                         "matched_account_text": _snippet(
                             text, acct.start(), acct.end()),
                         "pattern": "nominee + exchange account",
                         "remediation": "Review the bundle: "
                                        "nominee-held exchange "
                                        "accounts hide the real "
                                        "operator from KYC."},
                        confidence=75))
            elif form and acct and _CRYPTO_CONTEXT_RE.search(text):
                key = ("formation-bundle", doc.get("where"))
                if key not in seen:
                    seen.add(key)
                    findings.append(self._mk(doc, "medium", (
                        "MEDIUM: page bundles company formation "
                        "with crypto/exchange account opening - "
                        "the corporate-vehicle leg of the "
                        "shell-account typology."),
                        {"matched_text": _snippet(
                            text, form.start(), form.end()),
                         "matched_account_text": _snippet(
                             text, acct.start(), acct.end()),
                         "pattern": "formation + crypto account",
                         "remediation": "Review the package: "
                                        "formation-plus-account "
                                        "bundles are sold to defeat "
                                        "exchange KYC."},
                        confidence=70))
        return findings
